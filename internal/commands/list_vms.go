package commands

import (
	"context"
	"fmt"
	"os"
	"sort"

	"gcutil/internal/auth"
	"gcutil/internal/compute"

	"github.com/spf13/cobra"
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
	token, err := auth.LoadOrAuthToken()
	if err != nil {
		return err
	}

	// Create OAuth2 config
	config := auth.GetOAuth2Config()

	// Create token source that automatically refreshes
	tokenSource := config.TokenSource(ctx, token)

	// Get a fresh token (this will refresh if expired)
	freshToken, err := tokenSource.Token()
	if err != nil {
		// Token refresh failed - need to reauthenticate
		fmt.Fprintf(os.Stderr, "Token refresh failed: %v\n", err)
		fmt.Println("Reauthenticating...")

		if err := auth.RunAuth(); err != nil {
			return fmt.Errorf("reauthentication failed: %w", err)
		}

		// Load the new token
		token, err = auth.LoadToken()
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
		if err := auth.SaveToken(freshToken); err != nil {
			// Non-fatal - just log it
			fmt.Fprintf(os.Stderr, "Warning: failed to save refreshed token: %v\n", err)
		}
	}

	// Create compute and CRM services
	computeService, crmService, err := compute.CreateServices(ctx, config, token, auth.SaveToken)
	if err != nil {
		return err
	}

	// If project is specified, list VMs for that project only
	if projectID != "" {
		// Resolve project name to project ID
		allProjects, err := compute.GetAllProjects(crmService)
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

		instances, err := compute.GetAllInstances(computeService, resolvedProjectID)
		if err != nil {
			return fmt.Errorf("failed to list instances: %w", err)
		}

		fmt.Printf("\n=== Project: %s (%s) ===\n", resolvedProjectName, resolvedProjectID)
		compute.DisplayInstances(instances, resolvedProjectID)
		return nil
	}

	// Otherwise, list all projects and VMs in each
	projects, err := compute.GetAllProjects(crmService)
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}

	if len(projects) == 0 {
		fmt.Println("No accessible projects found.")
		return nil
	}

	// Fetch instances for all projects in parallel
	results := compute.FetchAllProjectInstances(computeService, projects)

	// Display results
	totalInstances := 0
	for _, result := range results {
		if result.Err != nil {
			// Skip projects where we can't list instances (e.g., API not enabled)
			fmt.Printf("Skipping project %s (%s): %v\n", result.Project.Name, result.Project.ProjectId, result.Err)
			continue
		}

		// Always display project header, even if no instances
		fmt.Printf("\n=== Project: %s (%s) ===\n", result.Project.Name, result.Project.ProjectId)

		if len(result.Instances) > 0 {
			// Sort instances by name
			sort.Slice(result.Instances, func(i, j int) bool {
				return result.Instances[i].Name < result.Instances[j].Name
			})

			compute.DisplayInstances(result.Instances, result.Project.ProjectId)
			totalInstances += len(result.Instances)
		} else {
			fmt.Println("No instances found.")
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total projects scanned: %d\n", len(projects))
	fmt.Printf("Total instances found: %d\n", totalInstances)

	return nil
}
