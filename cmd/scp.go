package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

var (
	scpUser string
)

var scpCmd = &cobra.Command{
	Use:                "scp [scp-args...] [source] [destination]",
	Short:              "SCP to/from a Google Cloud VM instance",
	Long:               `SCP files to/from a Google Cloud VM instance. Use [project.]instance:path notation for remote paths. Additional arguments are passed to scp.`,
	Args:               cobra.MinimumNArgs(2),
	RunE:               runSCP,
	DisableFlagParsing: true,
}

func init() {
	// Note: flags are disabled for this command to allow passing through scp flags
}

func runSCP(cmd *cobra.Command, args []string) error {
	// Handle help flag
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return cmd.Help()
		}
	}

	ctx := context.Background()

	// Parse flags manually since DisableFlagParsing is true
	var positionalArgs []string
	var additionalArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-u" || arg == "--user" {
			if i+1 < len(args) {
				scpUser = args[i+1]
				i++ // Skip next arg
			}
		} else if strings.HasPrefix(arg, "-") {
			// This is a flag to pass to scp
			additionalArgs = append(additionalArgs, arg)
		} else {
			// This is a positional argument (source or destination)
			positionalArgs = append(positionalArgs, arg)
		}
	}

	if len(positionalArgs) < 2 {
		return fmt.Errorf("source and destination arguments are required")
	}

	// Source and destination are the last two positional arguments
	source := positionalArgs[len(positionalArgs)-2]
	destination := positionalArgs[len(positionalArgs)-1]

	// Resolve any instance references in source and destination
	resolvedSource, err := resolveScpPath(ctx, cmd, source)
	if err != nil {
		return err
	}

	resolvedDestination, err := resolveScpPath(ctx, cmd, destination)
	if err != nil {
		return err
	}

	// Build SCP command with additional args first, then source and destination
	scpArgs := append(additionalArgs, resolvedSource, resolvedDestination)

	// Execute SCP
	scpCommand := exec.Command("scp", scpArgs...)
	scpCommand.Stdin = os.Stdin
	scpCommand.Stdout = os.Stdout
	scpCommand.Stderr = os.Stderr

	return scpCommand.Run()
}

func resolveScpPath(ctx context.Context, cmd *cobra.Command, path string) (string, error) {
	// Check if path contains a colon (indicates remote path)
	if !strings.Contains(path, ":") {
		// Local path, return as-is
		return path, nil
	}

	// Split into host and path parts
	parts := strings.SplitN(path, ":", 2)
	hostPart := parts[0]
	pathPart := parts[1]

	// Parse the host part (project.instance or just instance)
	var projectName, instanceName string

	if strings.Contains(hostPart, ".") {
		hostParts := strings.SplitN(hostPart, ".", 2)
		projectName = hostParts[0]
		instanceName = hostParts[1]
	} else {
		instanceName = hostPart
	}

	// Load token, authenticate if needed
	token, err := loadOrAuthToken(cmd)
	if err != nil {
		return "", err
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
			return "", fmt.Errorf("reauthentication failed: %w", err)
		}

		// Load the new token
		token, err = loadToken()
		if err != nil {
			return "", fmt.Errorf("failed to load token after reauthentication: %w", err)
		}

		// Recreate token source with new token
		tokenSource = config.TokenSource(ctx, token)
		freshToken, err = tokenSource.Token()
		if err != nil {
			return "", fmt.Errorf("failed to get token after reauthentication: %w", err)
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
		return "", fmt.Errorf("failed to create compute service: %w", err)
	}

	// Get Cloud Resource Manager service
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", fmt.Errorf("failed to create resource manager service: %w", err)
	}

	var projectsToSearch []*cloudresourcemanager.Project

	// If project is specified, resolve it
	if projectName != "" {
		// Get all projects to find matching name or ID
		allProjects, err := getAllProjects(crmService)
		if err != nil {
			return "", fmt.Errorf("failed to list projects: %w", err)
		}

		// Find project by name or ID
		for _, proj := range allProjects {
			if proj.ProjectId == projectName || proj.Name == projectName {
				projectsToSearch = []*cloudresourcemanager.Project{proj}
				break
			}
		}

		if len(projectsToSearch) == 0 {
			return "", fmt.Errorf("project %s not found", projectName)
		}
	} else {
		// Search all projects
		projectsToSearch, err = getAllProjects(crmService)
		if err != nil {
			return "", fmt.Errorf("failed to list projects: %w", err)
		}
	}

	// Search for the instance
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
		return "", fmt.Errorf("instance %s not found in any accessible project", instanceName)
	}

	// Get the external IP
	var externalIP string
	if len(foundInstance.NetworkInterfaces) > 0 {
		if len(foundInstance.NetworkInterfaces[0].AccessConfigs) > 0 {
			externalIP = foundInstance.NetworkInterfaces[0].AccessConfigs[0].NatIP
		}
	}

	if externalIP == "" {
		return "", fmt.Errorf("instance %s (project: %s (%s)) has no external IP address", instanceName, foundProjectName, foundProjectID)
	}

	fmt.Printf("Resolved %s to %s in project %s (%s), IP: %s\n", instanceName, instanceName, foundProjectName, foundProjectID, externalIP)

	// Build the resolved path
	var resolvedHost string
	if scpUser != "" {
		resolvedHost = fmt.Sprintf("%s@%s", scpUser, externalIP)
	} else {
		resolvedHost = externalIP
	}

	return fmt.Sprintf("%s:%s", resolvedHost, pathPart), nil
}
