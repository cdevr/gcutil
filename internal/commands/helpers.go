package commands

import (
	"fmt"

	"gcutil/internal/compute"

	"google.golang.org/api/cloudresourcemanager/v1"
)

// resolveProjectsToSearch determines which projects to search based on the project name/ID
func resolveProjectsToSearch(crmService *cloudresourcemanager.Service, projectName string) ([]*cloudresourcemanager.Project, error) {
	var projectsToSearch []*cloudresourcemanager.Project

	// If project is specified, resolve it
	if projectName != "" {
		// Get all projects to find matching name or ID
		allProjects, err := compute.GetAllProjects(crmService)
		if err != nil {
			return nil, fmt.Errorf("failed to list projects: %w", err)
		}

		// Find project by name or ID
		for _, proj := range allProjects {
			if proj.ProjectId == projectName || proj.Name == projectName {
				projectsToSearch = []*cloudresourcemanager.Project{proj}
				break
			}
		}

		if len(projectsToSearch) == 0 {
			return nil, fmt.Errorf("project %s not found", projectName)
		}
	} else {
		// Search all projects
		var err error
		projectsToSearch, err = compute.GetAllProjects(crmService)
		if err != nil {
			return nil, fmt.Errorf("failed to list projects: %w", err)
		}
	}

	return projectsToSearch, nil
}
