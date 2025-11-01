package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

var (
	sshUsername   string
	sshPublicKey  string
	sshKeyFile    string
	sshProjectID  string
	sshInstanceID string
	sshZone       string
)

var addkeyCmd = &cobra.Command{
	Use:   "addkey [instance-name] [username] [key]",
	Short: "Add SSH key to a Google Cloud VM instance",
	Long:  `Add an SSH public key for a user to a Google Cloud VM instance.`,
	Args:  cobra.MaximumNArgs(3),
	RunE:  runAddkey,
}

func init() {
	addkeyCmd.Flags().StringVarP(&sshUsername, "username", "u", "", "Username for the SSH key (optional - can be specified as positional argument)")
	addkeyCmd.Flags().StringVarP(&sshPublicKey, "key", "k", "", "SSH public key (optional - can be specified as positional argument or use --key-file)")
	addkeyCmd.Flags().StringVarP(&sshKeyFile, "key-file", "f", "", "Path to SSH public key file (alternative to --key or positional key argument)")
	addkeyCmd.Flags().StringVarP(&sshProjectID, "project", "p", "", "Google Cloud project ID (optional - if not specified, searches all projects)")
	addkeyCmd.Flags().StringVarP(&sshInstanceID, "instance", "i", "", "Instance name (optional - can be specified as positional argument)")
	addkeyCmd.Flags().StringVarP(&sshZone, "zone", "z", "", "Zone of the instance (optional - will be auto-discovered if not specified)")
}

func runAddkey(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get parameters from positional arguments if provided
	if len(args) > 0 && sshInstanceID == "" {
		sshInstanceID = args[0]
	}
	if len(args) > 1 && sshUsername == "" {
		sshUsername = args[1]
	}
	if len(args) > 2 && sshPublicKey == "" {
		sshPublicKey = args[2]
	}

	// Validate instance name is provided
	if sshInstanceID == "" {
		return fmt.Errorf("instance name must be specified either as positional argument or with --instance flag")
	}

	// Validate username is provided
	if sshUsername == "" {
		return fmt.Errorf("username must be specified either as positional argument or with --username flag")
	}

	// Validate that either key or key-file is provided
	if sshPublicKey == "" && sshKeyFile == "" {
		return fmt.Errorf("SSH key must be specified either as positional argument, with --key flag, or with --key-file flag")
	}

	if sshPublicKey != "" && sshKeyFile != "" {
		return fmt.Errorf("cannot specify both --key and --key-file")
	}

	// Load key from file if specified
	var publicKey string
	if sshKeyFile != "" {
		keyBytes, err := os.ReadFile(sshKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}
		publicKey = strings.TrimSpace(string(keyBytes))
	} else {
		publicKey = sshPublicKey
	}

	// Validate key format (basic check)
	if !strings.HasPrefix(publicKey, "ssh-rsa") && !strings.HasPrefix(publicKey, "ssh-ed25519") && !strings.HasPrefix(publicKey, "ecdsa-sha2-") {
		return fmt.Errorf("invalid SSH public key format (must start with ssh-rsa, ssh-ed25519, or ecdsa-sha2-)")
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

	// If zone is not specified, find it by searching for the instance
	if sshZone == "" {
		fmt.Printf("Zone not specified, searching for instance %s...\n", sshInstanceID)

		var projectsToSearch []*cloudresourcemanager.Project

		// Get Cloud Resource Manager service to resolve project names
		crmService, err := cloudresourcemanager.NewService(ctx, option.WithTokenSource(tokenSource))
		if err != nil {
			return fmt.Errorf("failed to create resource manager service: %w", err)
		}

		// If project is specified, resolve it and search only that project
		if sshProjectID != "" {
			// Get all projects to find matching name or ID
			allProjects, err := getAllProjects(crmService)
			if err != nil {
				return fmt.Errorf("failed to list projects: %w", err)
			}

			// Find project by name or ID
			for _, proj := range allProjects {
				if proj.ProjectId == sshProjectID || proj.Name == sshProjectID {
					projectsToSearch = []*cloudresourcemanager.Project{proj}
					sshProjectID = proj.ProjectId // Use the actual project ID
					break
				}
			}

			if len(projectsToSearch) == 0 {
				return fmt.Errorf("project %s not found", sshProjectID)
			}
		} else {
			// Search all projects
			projectsToSearch, err = getAllProjects(crmService)
			if err != nil {
				return fmt.Errorf("failed to list projects: %w", err)
			}
		}

		// Search for the instance across projects/zones
		var foundInstance *compute.Instance
		var foundProject string
		var foundZone string

		for _, proj := range projectsToSearch {
			// Use aggregated list to search all zones at once
			req := computeService.Instances.AggregatedList(proj.ProjectId)
			err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
				for zone, instancesScopedList := range page.Items {
					for _, instance := range instancesScopedList.Instances {
						if instance.Name == sshInstanceID {
							foundInstance = instance
							foundProject = proj.ProjectId
							// Extract zone from the key (e.g., "zones/us-central1-a")
							foundZone = getZoneFromURL(zone)
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
			return fmt.Errorf("instance %s not found in any accessible project/zone", sshInstanceID)
		}

		sshProjectID = foundProject
		sshZone = foundZone
		fmt.Printf("Found instance %s in project %s, zone %s\n", sshInstanceID, sshProjectID, sshZone)
	} else if sshProjectID == "" {
		return fmt.Errorf("if zone is specified, project must also be specified")
	}

	// Get the instance to retrieve current metadata
	instance, err := computeService.Instances.Get(sshProjectID, sshZone, sshInstanceID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get instance: %w", err)
	}

	// Format the SSH key entry
	sshKeyEntry := fmt.Sprintf("%s:%s", sshUsername, publicKey)

	// Find or create ssh-keys metadata item
	var sshKeysItem *compute.MetadataItems
	for _, item := range instance.Metadata.Items {
		if item.Key == "ssh-keys" {
			sshKeysItem = item
			break
		}
	}

	if sshKeysItem == nil {
		// No existing ssh-keys, create new
		sshKeysItem = &compute.MetadataItems{
			Key:   "ssh-keys",
			Value: &sshKeyEntry,
		}
		instance.Metadata.Items = append(instance.Metadata.Items, sshKeysItem)
	} else {
		// Append to existing keys
		existingKeys := ""
		if sshKeysItem.Value != nil {
			existingKeys = *sshKeysItem.Value
		}

		// Check if this username already has a key
		lines := strings.Split(existingKeys, "\n")
		var updatedLines []string
		userKeyExists := false

		for _, line := range lines {
			if line == "" {
				continue
			}
			// Check if this line is for the same username
			if strings.HasPrefix(line, sshUsername+":") {
				// Replace existing key for this user
				updatedLines = append(updatedLines, sshKeyEntry)
				userKeyExists = true
				fmt.Printf("Replacing existing SSH key for user %s\n", sshUsername)
			} else {
				updatedLines = append(updatedLines, line)
			}
		}

		if !userKeyExists {
			updatedLines = append(updatedLines, sshKeyEntry)
			fmt.Printf("Adding SSH key for user %s\n", sshUsername)
		}

		newValue := strings.Join(updatedLines, "\n")
		sshKeysItem.Value = &newValue
	}

	// Update instance metadata
	op, err := computeService.Instances.SetMetadata(sshProjectID, sshZone, sshInstanceID, instance.Metadata).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to update instance metadata: %w", err)
	}

	// Wait for the operation to complete
	fmt.Printf("Updating instance metadata (operation: %s)...\n", op.Name)
	err = waitForOperation(computeService, sshProjectID, sshZone, op.Name)
	if err != nil {
		return fmt.Errorf("operation failed: %w", err)
	}

	fmt.Printf("Successfully added SSH key for user %s to instance %s\n", sshUsername, sshInstanceID)
	return nil
}

func waitForOperation(service *compute.Service, project, zone, operation string) error {
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
				return fmt.Errorf("operation errors: %s", strings.Join(errMsgs, ", "))
			}
			return nil
		}

		// Poll every 2 seconds
		fmt.Print(".")
	}
}
