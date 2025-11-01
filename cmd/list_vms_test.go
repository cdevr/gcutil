package cmd

import (
	"testing"

	"google.golang.org/api/compute/v1"
)

func TestGetZoneFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Standard zone URL",
			url:      "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a",
			expected: "us-central1-a",
		},
		{
			name:     "Another zone URL",
			url:      "https://www.googleapis.com/compute/v1/projects/test-project/zones/europe-west1-b",
			expected: "europe-west1-b",
		},
		{
			name:     "Plain zone name",
			url:      "us-east1-c",
			expected: "us-east1-c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getZoneFromURL(tt.url)
			if result != tt.expected {
				t.Errorf("getZoneFromURL(%s) = %s, want %s", tt.url, result, tt.expected)
			}
		})
	}
}

func TestGetMachineTypeFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Standard machine type URL",
			url:      "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/machineTypes/n1-standard-1",
			expected: "n1-standard-1",
		},
		{
			name:     "E2 machine type",
			url:      "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-east1-b/machineTypes/e2-medium",
			expected: "e2-medium",
		},
		{
			name:     "Plain machine type",
			url:      "n2-standard-4",
			expected: "n2-standard-4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMachineTypeFromURL(tt.url)
			if result != tt.expected {
				t.Errorf("getMachineTypeFromURL(%s) = %s, want %s", tt.url, result, tt.expected)
			}
		})
	}
}

func TestDisplayInstancesEmpty(t *testing.T) {
	// Test that displayInstances doesn't panic with empty list
	instances := []*compute.Instance{}
	displayInstances(instances, "test-project")
	// If we reach here without panic, test passes
}

func TestDisplayInstancesWithData(t *testing.T) {
	// Test that displayInstances doesn't panic with valid data
	instances := []*compute.Instance{
		{
			Name:        "test-vm-1",
			Zone:        "https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-a",
			MachineType: "https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-a/machineTypes/n1-standard-1",
			Status:      "RUNNING",
			NetworkInterfaces: []*compute.NetworkInterface{
				{
					NetworkIP: "10.0.0.1",
					AccessConfigs: []*compute.AccessConfig{
						{
							NatIP: "35.1.2.3",
						},
					},
				},
			},
		},
		{
			Name:              "test-vm-2",
			Zone:              "https://www.googleapis.com/compute/v1/projects/test/zones/us-west1-b",
			MachineType:       "https://www.googleapis.com/compute/v1/projects/test/zones/us-west1-b/machineTypes/e2-medium",
			Status:            "TERMINATED",
			NetworkInterfaces: []*compute.NetworkInterface{
				{
					NetworkIP: "10.0.0.2",
				},
			},
		},
	}

	// This test ensures the function doesn't panic
	displayInstances(instances, "test-project")
	// If we reach here without panic, test passes
}

func TestDisplayInstancesNoNetworkInterface(t *testing.T) {
	// Test that displayInstances handles instances without network interfaces
	instances := []*compute.Instance{
		{
			Name:              "test-vm-no-network",
			Zone:              "https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-a",
			MachineType:       "https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-a/machineTypes/n1-standard-1",
			Status:            "STOPPED",
			NetworkInterfaces: []*compute.NetworkInterface{},
		},
	}

	// This test ensures the function doesn't panic when there are no network interfaces
	displayInstances(instances, "test-project")
	// If we reach here without panic, test passes
}
