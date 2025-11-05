package auth

import (
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/oauth2"
)

func TestSaveAndLoadToken(t *testing.T) {
	// Create a test token
	testToken := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
	}

	// Use a temporary file
	tmpFile := "test_token.json"
	defer os.Remove(tmpFile)

	// Override the GetTokenFile function for testing
	originalGetTokenFile := GetTokenFile
	defer func() {
		GetTokenFile = originalGetTokenFile
	}()
	GetTokenFile = func() (string, error) {
		return tmpFile, nil
	}

	// Test SaveToken
	err := SaveToken(testToken)
	if err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("Token file was not created")
	}

	// Test LoadToken
	loadedToken, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken failed: %v", err)
	}

	// Verify token contents
	if loadedToken.AccessToken != testToken.AccessToken {
		t.Errorf("Expected access token %s, got %s", testToken.AccessToken, loadedToken.AccessToken)
	}
	if loadedToken.RefreshToken != testToken.RefreshToken {
		t.Errorf("Expected refresh token %s, got %s", testToken.RefreshToken, loadedToken.RefreshToken)
	}
	if loadedToken.TokenType != testToken.TokenType {
		t.Errorf("Expected token type %s, got %s", testToken.TokenType, loadedToken.TokenType)
	}
}

func TestLoadTokenNotFound(t *testing.T) {
	// Override the GetTokenFile function for testing
	originalGetTokenFile := GetTokenFile
	defer func() {
		GetTokenFile = originalGetTokenFile
	}()
	GetTokenFile = func() (string, error) {
		return "nonexistent_token.json", nil
	}

	_, err := LoadToken()
	if err == nil {
		t.Fatal("Expected error when loading non-existent token file, got nil")
	}
}

func TestSaveTokenInvalidPath(t *testing.T) {
	testToken := &oauth2.Token{
		AccessToken: "test-token",
	}

	// Override the GetTokenFile function with an invalid path
	originalGetTokenFile := GetTokenFile
	defer func() {
		GetTokenFile = originalGetTokenFile
	}()
	GetTokenFile = func() (string, error) {
		return "/nonexistent_directory/token.json", nil
	}

	err := SaveToken(testToken)
	if err == nil {
		t.Fatal("Expected error when saving to invalid path, got nil")
	}
}

func TestTokenJSONFormat(t *testing.T) {
	testToken := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
	}

	tmpFile := "test_token_format.json"
	defer os.Remove(tmpFile)

	originalGetTokenFile := GetTokenFile
	defer func() {
		GetTokenFile = originalGetTokenFile
	}()
	GetTokenFile = func() (string, error) {
		return tmpFile, nil
	}

	// Save token
	if err := SaveToken(testToken); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Read raw JSON
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	// Parse JSON
	var parsedToken oauth2.Token
	if err := json.Unmarshal(data, &parsedToken); err != nil {
		t.Fatalf("Failed to parse token JSON: %v", err)
	}

	// Verify it's valid JSON with correct structure
	if parsedToken.AccessToken != testToken.AccessToken {
		t.Errorf("JSON parsing mismatch: expected %s, got %s", testToken.AccessToken, parsedToken.AccessToken)
	}
}
