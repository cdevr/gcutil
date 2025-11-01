package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

var projectID string

var listVMsCmd = &cobra.Command{
	Use:   "list [project]",
	Short: "List all VMs in Google Cloud projects",
	Long:  `List all virtual machine instances across all zones. If no project is specified, lists VMs from all accessible projects.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runListVMs,
}

func init() {
	listVMsCmd.Flags().StringVarP(&projectID, "project", "p", "", "Google Cloud project ID (optional - if not specified, lists all projects)")
}

func runListVMs(cmd *cobra.Command, args []string) error {
	// If a positional argument is provided, use it as the project
	if len(args) > 0 {
		projectID = args[0]
	}

	ctx := context.Background()

	// Load token, authenticate if needed
	token, err := loadOrAuthToken(cmd)
	if err != nil {
		return err
	}

	// Create OAuth2 config
	config := &oauth2.Config{
		ClientID:     "32555940559.apps.googleusercontent.com",
		ClientSecret: "ZmssLNjJy2998hD4CTg2ejr2",
		Endpoint:     google.Endpoint,
		Scopes: []string{
			compute.CloudPlatformScope,
		},
	}

	// Create token source that automatically refreshes
	tokenSource := config.TokenSource(ctx, token)

	// Get a fresh token (this will refresh if expired)
	freshToken, err := tokenSource.Token()
	if err != nil {
		// Token refresh failed - need to reauthenticate
		fmt.Fprintf(os.Stderr, "Token refresh failed: %v\n", err)
		fmt.Println("Reauthenticating...")

		if err := runAuth(cmd, nil); err != nil {
			return fmt.Errorf("reauthentication failed: %w", err)
		}

		// Load the new token
		token, err = loadToken()
		if err != nil {
			return fmt.Errorf("failed to load token after reauthentication: %w", err)
		}

		// Recreate token source with new token
		tokenSource = config.TokenSource(ctx, token)
		freshToken, err = tokenSource.Token()
		if err != nil {
			return fmt.Errorf("failed to get token after reauthentication: %w", err)
		}
	}

	// Save the refreshed token
	if freshToken.AccessToken != token.AccessToken {
		if err := saveToken(freshToken); err != nil {
			// Non-fatal - just log it
			fmt.Fprintf(os.Stderr, "Warning: failed to save refreshed token: %v\n", err)
		}
	}

	// Create compute service
	computeService, err := compute.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return fmt.Errorf("failed to create compute service: %w", err)
	}

	// Get resource manager service (needed for resolving project names)
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}

	// If project is specified, list VMs for that project only
	if projectID != "" {
		// Resolve project name to project ID
		allProjects, err := getAllProjects(crmService)
		if err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
		}

		// Find project by name or ID
		var resolvedProjectID string
		var resolvedProjectName string
		for _, proj := range allProjects {
			if proj.ProjectId == projectID || proj.Name == projectID {
				resolvedProjectID = proj.ProjectId
				resolvedProjectName = proj.Name
				break
			}
		}

		if resolvedProjectID == "" {
			return fmt.Errorf("project %s not found", projectID)
		}

		instances, err := getAllInstances(computeService, resolvedProjectID)
		if err != nil {
			return fmt.Errorf("failed to list instances: %w", err)
		}

		fmt.Printf("\n=== Project: %s (%s) ===\n", resolvedProjectName, resolvedProjectID)
		displayInstances(instances, resolvedProjectID)
		return nil
	}

	// Otherwise, list all projects and VMs in each
	projects, err := getAllProjects(crmService)
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}

	if len(projects) == 0 {
		fmt.Println("No accessible projects found.")
		return nil
	}

	// Fetch instances for all projects in parallel
	type projectResult struct {
		project   *cloudresourcemanager.Project
		instances []*compute.Instance
		err       error
	}

	resultChan := make(chan projectResult, len(projects))
	var wg sync.WaitGroup

	for _, project := range projects {
		wg.Add(1)
		go func(proj *cloudresourcemanager.Project) {
			defer wg.Done()
			instances, err := getAllInstances(computeService, proj.ProjectId)
			resultChan <- projectResult{
				project:   proj,
				instances: instances,
				err:       err,
			}
		}(project)
	}

	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var results []projectResult
	for result := range resultChan {
		results = append(results, result)
	}

	// Sort results by project name
	sort.Slice(results, func(i, j int) bool {
		return results[i].project.Name < results[j].project.Name
	})

	// Display results
	totalInstances := 0
	for _, result := range results {
		if result.err != nil {
			// Skip projects where we can't list instances (e.g., API not enabled)
			fmt.Printf("Skipping project %s (%s): %v\n", result.project.Name, result.project.ProjectId, result.err)
			continue
		}

		// Always display project header, even if no instances
		fmt.Printf("\n=== Project: %s (%s) ===\n", result.project.Name, result.project.ProjectId)

		if len(result.instances) > 0 {
			// Sort instances by name
			sortedInstances := make([]*compute.Instance, len(result.instances))
			copy(sortedInstances, result.instances)
			sort.Slice(sortedInstances, func(i, j int) bool {
				return sortedInstances[i].Name < sortedInstances[j].Name
			})

			displayInstances(sortedInstances, result.project.ProjectId)
			totalInstances += len(result.instances)
		} else {
			fmt.Println("No instances found.")
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total projects scanned: %d\n", len(projects))
	fmt.Printf("Total instances found: %d\n", totalInstances)

	return nil
}

func getAllInstances(service *compute.Service, project string) ([]*compute.Instance, error) {
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

func getAllProjects(service *cloudresourcemanager.Service) ([]*cloudresourcemanager.Project, error) {
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

func displayInstances(instances []*compute.Instance, projectID string) {
	if len(instances) == 0 {
		fmt.Println("No instances found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tZONE\tMACHINE TYPE\tSTATUS\tINTERNAL IP\tEXTERNAL IP")

	for _, instance := range instances {
		zone := getZoneFromURL(instance.Zone)
		machineType := getMachineTypeFromURL(instance.MachineType)
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

func getZoneFromURL(url string) string {
	// Extract zone name from URL like: https://www.googleapis.com/compute/v1/projects/PROJECT/zones/ZONE
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			return url[i+1:]
		}
	}
	return url
}

func getMachineTypeFromURL(url string) string {
	// Extract machine type from URL
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			return url[i+1:]
		}
	}
	return url
}
