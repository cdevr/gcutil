package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gcutil/internal/auth"
	"gcutil/internal/compute"

	"github.com/spf13/cobra"
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

	// Determine which projects to search
	projectsToSearch, err := resolveProjectsToSearch(crmService, projectName)
	if err != nil {
		return err
	}

	// Search for the instance
	foundInstance, foundProjectName, foundProjectID, err := compute.FindInstanceInProjects(ctx, computeService, instanceName, projectsToSearch)
	if err != nil {
		return err
	}

	// Get the external IP
	externalIP := compute.GetExternalIP(foundInstance)

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
