package compute

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"
)

// captureOutput runs the given function and returns its stdout output as a string
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

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
			result := GetZoneFromURL(tt.url)
			if result != tt.expected {
				t.Errorf("GetZoneFromURL(%s) = %s, want %s", tt.url, result, tt.expected)
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
			result := GetMachineTypeFromURL(tt.url)
			if result != tt.expected {
				t.Errorf("GetMachineTypeFromURL(%s) = %s, want %s", tt.url, result, tt.expected)
			}
		})
	}
}

func TestDisplayInstancesEmpty(t *testing.T) {
	instances := []*compute.Instance{}
	output := captureOutput(func() {
		DisplayInstances(instances, "test-project")
	})

	// Verify output contains expected message
	if !strings.Contains(output, "No instances found") {
		t.Errorf("Expected 'No instances found' in output, got: %s", output)
	}
}

func TestDisplayInstancesWithData(t *testing.T) {
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

	output := captureOutput(func() {
		DisplayInstances(instances, "test-project")
	})

	// Verify output contains expected data
	expectedStrings := []string{
		"test-vm-1",
		"test-vm-2",
		"us-central1-a",
		"us-west1-b",
		"n1-standard-1",
		"e2-medium",
		"RUNNING",
		"TERMINATED",
		"10.0.0.1",
		"10.0.0.2",
		"35.1.2.3",
		"Total instances: 2",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected '%s' in output, got: %s", expected, output)
		}
	}
}

func TestDisplayInstancesNoNetworkInterface(t *testing.T) {
	instances := []*compute.Instance{
		{
			Name:              "test-vm-no-network",
			Zone:              "https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-a",
			MachineType:       "https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-a/machineTypes/n1-standard-1",
			Status:            "STOPPED",
			NetworkInterfaces: []*compute.NetworkInterface{},
		},
	}

	output := captureOutput(func() {
		DisplayInstances(instances, "test-project")
	})

	// Verify output contains VM name and status, but empty IPs
	if !strings.Contains(output, "test-vm-no-network") {
		t.Errorf("Expected 'test-vm-no-network' in output, got: %s", output)
	}
	if !strings.Contains(output, "STOPPED") {
		t.Errorf("Expected 'STOPPED' in output, got: %s", output)
	}
	if !strings.Contains(output, "Total instances: 1") {
		t.Errorf("Expected 'Total instances: 1' in output, got: %s", output)
	}
}
