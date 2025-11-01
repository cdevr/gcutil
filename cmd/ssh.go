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
	sshUser string
)

var sshCmd = &cobra.Command{
	Use:                "ssh [project.]instance [ssh-args...]",
	Short:              "SSH to a Google Cloud VM instance",
	Long:               `SSH to a Google Cloud VM instance by name. Specify as 'instance' or 'project.instance'. Additional arguments are passed to ssh.`,
	Args:               cobra.MinimumNArgs(1),
	RunE:               runSSH,
	DisableFlagParsing: true,
}

func init() {
	// Note: flags are disabled for this command to allow passing through ssh flags
}

func runSSH(cmd *cobra.Command, args []string) error {
	// Handle help flag
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return cmd.Help()
		}
	}

	ctx := context.Background()

	// Parse flags manually since DisableFlagParsing is true
	var instanceArg string
	var sshArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-u" || arg == "--user" {
			if i+1 < len(args) {
				sshUser = args[i+1]
				i++ // Skip next arg
			}
		} else if instanceArg == "" {
			instanceArg = arg
		} else {
			sshArgs = append(sshArgs, arg)
		}
	}

	if instanceArg == "" {
		return fmt.Errorf("instance argument is required")
	}

	// Parse the instance argument (project.instance or just instance)
	var projectName, instanceName string

	if strings.Contains(instanceArg, ".") {
		parts := strings.SplitN(instanceArg, ".", 2)
		projectName = parts[0]
		instanceName = parts[1]
	} else {
		instanceName = instanceArg
	}

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

	// Get Cloud Resource Manager service
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}

	var projectsToSearch []*cloudresourcemanager.Project

	// If project is specified, resolve it
	if projectName != "" {
		// Get all projects to find matching name or ID
		allProjects, err := getAllProjects(crmService)
		if err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
		}

		// Find project by name or ID
		for _, proj := range allProjects {
			if proj.ProjectId == projectName || proj.Name == projectName {
				projectsToSearch = []*cloudresourcemanager.Project{proj}
				break
			}
		}

		if len(projectsToSearch) == 0 {
			return fmt.Errorf("project %s not found", projectName)
		}
	} else {
		// Search all projects
		projectsToSearch, err = getAllProjects(crmService)
		if err != nil {
			return fmt.Errorf("failed to list projects: %w", err)
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
		return fmt.Errorf("instance %s not found in any accessible project", instanceName)
	}

	// Get the external IP
	var externalIP string
	if len(foundInstance.NetworkInterfaces) > 0 {
		if len(foundInstance.NetworkInterfaces[0].AccessConfigs) > 0 {
			externalIP = foundInstance.NetworkInterfaces[0].AccessConfigs[0].NatIP
		}
	}

	if externalIP == "" {
		return fmt.Errorf("instance %s (project: %s (%s)) has no external IP address", instanceName, foundProjectName, foundProjectID)
	}

	// Build SSH command
	// sshArgs contains everything after the instance name
	// We need to separate SSH flags (starting with -) from the remote command
	var finalArgs []string
	var sshFlags []string
	var remoteCommand []string

	for _, arg := range sshArgs {
		if strings.HasPrefix(arg, "-") && len(remoteCommand) == 0 {
			// This is an SSH flag, add it before the hostname
			sshFlags = append(sshFlags, arg)
		} else {
			// This is part of the remote command
			remoteCommand = append(remoteCommand, arg)
		}
	}

	// Build final args: flags, then hostname, then remote command
	finalArgs = append(finalArgs, sshFlags...)

	// Add the host
	if sshUser != "" {
		finalArgs = append(finalArgs, fmt.Sprintf("%s@%s", sshUser, externalIP))
	} else {
		finalArgs = append(finalArgs, externalIP)
	}

	// Add remote command (if any)
	finalArgs = append(finalArgs, remoteCommand...)

	fmt.Printf("Connecting to %s in project %s (%s), IP: %s\n", instanceName, foundProjectName, foundProjectID, externalIP)

	// Execute SSH
	sshCommand := exec.Command("ssh", finalArgs...)
	sshCommand.Stdin = os.Stdin
	sshCommand.Stdout = os.Stdout
	sshCommand.Stderr = os.Stderr

	return sshCommand.Run()
}
