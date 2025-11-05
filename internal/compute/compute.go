package compute

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"text/tabwriter"

	"golang.org/x/oauth2"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// GetAllInstances retrieves all VM instances from a GCP project
func GetAllInstances(service *compute.Service, project string) ([]*compute.Instance, error) {
	var allInstances []*compute.Instance

	// Use aggregated list to get instances from all zones
	req := service.Instances.AggregatedList(project)
	if err := req.Pages(context.Background(), func(page *compute.InstanceAggregatedList) error {
		for _, instancesScopedList := range page.Items {
			allInstances = append(allInstances, instancesScopedList.Instances...)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return allInstances, nil
}

// GetAllProjects retrieves all active GCP projects
func GetAllProjects(service *cloudresourcemanager.Service) ([]*cloudresourcemanager.Project, error) {
	var allProjects []*cloudresourcemanager.Project

	req := service.Projects.List()
	if err := req.Pages(context.Background(), func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range page.Projects {
			// Only include active projects
			if project.LifecycleState == "ACTIVE" {
				allProjects = append(allProjects, project)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return allProjects, nil
}

// DisplayInstances prints instances in a formatted table
func DisplayInstances(instances []*compute.Instance, projectID string) {
	if len(instances) == 0 {
		fmt.Println("No instances found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tZONE\tMACHINE TYPE\tSTATUS\tINTERNAL IP\tEXTERNAL IP")

	for _, instance := range instances {
		zone := GetZoneFromURL(instance.Zone)
		machineType := GetMachineTypeFromURL(instance.MachineType)
		internalIP := ""
		externalIP := ""

		if len(instance.NetworkInterfaces) > 0 {
			internalIP = instance.NetworkInterfaces[0].NetworkIP
			if len(instance.NetworkInterfaces[0].AccessConfigs) > 0 {
				externalIP = instance.NetworkInterfaces[0].AccessConfigs[0].NatIP
			}
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			instance.Name,
			zone,
			machineType,
			instance.Status,
			internalIP,
			externalIP,
		)
	}

	w.Flush()
	fmt.Printf("\nTotal instances: %d\n", len(instances))
}

// GetZoneFromURL extracts the zone name from a GCP URL
func GetZoneFromURL(url string) string {
	// Extract zone name from URL like: https://www.googleapis.com/compute/v1/projects/PROJECT/zones/ZONE
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			return url[i+1:]
		}
	}
	return url
}

// GetMachineTypeFromURL extracts the machine type from a GCP URL
func GetMachineTypeFromURL(url string) string {
	// Extract machine type from URL
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			return url[i+1:]
		}
	}
	return url
}

// FindInstanceInProjects searches for an instance across multiple projects
func FindInstanceInProjects(ctx context.Context, computeService *compute.Service, instanceName string, projectsToSearch []*cloudresourcemanager.Project) (*compute.Instance, string, string, error) {
	var foundInstance *compute.Instance
	var foundProjectName string
	var foundProjectID string

	for _, proj := range projectsToSearch {
		// Use aggregated list to search all zones at once
		req := computeService.Instances.AggregatedList(proj.ProjectId)
		err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
			for _, instancesScopedList := range page.Items {
				for _, instance := range instancesScopedList.Instances {
					if instance.Name == instanceName {
						foundInstance = instance
						foundProjectName = proj.Name
						foundProjectID = proj.ProjectId
						return fmt.Errorf("found") // Break out of pagination
					}
				}
			}
			return nil
		})

		if foundInstance != nil {
			break
		}

		// Ignore errors from individual projects (might not have compute API enabled)
		if err != nil && err.Error() != "found" {
			continue
		}
	}

	if foundInstance == nil {
		return nil, "", "", fmt.Errorf("instance %s not found in any accessible project", instanceName)
	}

	return foundInstance, foundProjectName, foundProjectID, nil
}

// GetExternalIP extracts the external IP from an instance
func GetExternalIP(instance *compute.Instance) string {
	if len(instance.NetworkInterfaces) > 0 {
		if len(instance.NetworkInterfaces[0].AccessConfigs) > 0 {
			return instance.NetworkInterfaces[0].AccessConfigs[0].NatIP
		}
	}
	return ""
}

// WaitForOperation waits for a GCP operation to complete
func WaitForOperation(service *compute.Service, project, zone, operation string) error {
	ctx := context.Background()
	for {
		op, err := service.ZoneOperations.Get(project, zone, operation).Context(ctx).Do()
		if err != nil {
			return err
		}

		if op.Status == "DONE" {
			if op.Error != nil {
				var errMsgs []string
				for _, e := range op.Error.Errors {
					errMsgs = append(errMsgs, e.Message)
				}
				return fmt.Errorf("operation errors: %s", joinStrings(errMsgs, ", "))
			}
			return nil
		}

		// Poll every 2 seconds
		fmt.Print(".")
	}
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// CreateServices creates compute and cloud resource manager services with token refresh
func CreateServices(ctx context.Context, config *oauth2.Config, token *oauth2.Token, onTokenRefresh func(*oauth2.Token) error) (*compute.Service, *cloudresourcemanager.Service, error) {
	// Create token source that automatically refreshes
	tokenSource := config.TokenSource(ctx, token)

	// Get a fresh token (this will refresh if expired)
	freshToken, err := tokenSource.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get token: %w", err)
	}

	// Save the refreshed token if it changed
	if freshToken.AccessToken != token.AccessToken && onTokenRefresh != nil {
		if err := onTokenRefresh(freshToken); err != nil {
			// Non-fatal - just log it
			fmt.Fprintf(os.Stderr, "Warning: failed to save refreshed token: %v\n", err)
		}
	}

	// Create compute service
	computeService, err := compute.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	// Get resource manager service (needed for resolving project names)
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	return computeService, crmService, nil
}

// ProjectResult represents the result of fetching instances for a project
type ProjectResult struct {
	Project   *cloudresourcemanager.Project
	Instances []*compute.Instance
	Err       error
}

// FetchAllProjectInstances fetches instances for all projects in parallel
func FetchAllProjectInstances(computeService *compute.Service, projects []*cloudresourcemanager.Project) []ProjectResult {
	resultChan := make(chan ProjectResult, len(projects))
	var wg sync.WaitGroup

	for _, project := range projects {
		wg.Add(1)
		go func(proj *cloudresourcemanager.Project) {
			defer wg.Done()
			instances, err := GetAllInstances(computeService, proj.ProjectId)
			resultChan <- ProjectResult{
				Project:   proj,
				Instances: instances,
				Err:       err,
			}
		}(project)
	}

	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var results []ProjectResult
	for result := range resultChan {
		results = append(results, result)
	}

	// Sort results by project name
	sort.Slice(results, func(i, j int) bool {
		return results[i].Project.Name < results[j].Project.Name
	})

	return results
}
