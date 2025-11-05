package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
)

func GetConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(homeDir, ".gcutil")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}

	return configDir, nil
}

var GetTokenFile = func() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "token.json"), nil
}

func RunAuth() error {
	ctx := context.Background()

	// Use Google's built-in OAuth2 client credentials
	config := &oauth2.Config{
		ClientID:     "32555940559.apps.googleusercontent.com",
		ClientSecret: "ZmssLNjJy2998hD4CTg2ejr2",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes: []string{
			compute.CloudPlatformScope,
		},
		Endpoint: google.Endpoint,
	}

	// Create a channel to receive the authorization code
	codeChan := make(chan string)
	errChan := make(chan error)

	// Start HTTP server
	server := &http.Server{Addr: ":8080"}
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errChan <- fmt.Errorf("no code in callback")
			return
		}
		w.Write([]byte("Authentication successful! You can close this window."))
		codeChan <- code
	})

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Generate auth URL
	authURL := config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Printf("Visit this URL to authenticate:\n%s\n", authURL)

	// Wait for code or error
	var code string
	select {
	case code = <-codeChan:
	case err := <-errChan:
		return err
	}

	// Shutdown server
	server.Shutdown(ctx)

	// Exchange code for token
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Save token to file
	if err := SaveToken(token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	fmt.Println("Authentication successful!")
	return nil
}

func SaveToken(token *oauth2.Token) error {
	tokenFile, err := GetTokenFile()
	if err != nil {
		return err
	}

	f, err := os.Create(tokenFile)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

func LoadToken() (*oauth2.Token, error) {
	tokenFile, err := GetTokenFile()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(tokenFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	token := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(token)
	return token, err
}

// LoadOrAuthToken loads the token, and if it fails, triggers authentication
func LoadOrAuthToken() (*oauth2.Token, error) {
	token, err := LoadToken()
	if err != nil {
		// Token doesn't exist or failed to load, authenticate
		fmt.Println("No valid token found. Authenticating...")
		if err := RunAuth(); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
		// Load the newly created token
		token, err = LoadToken()
		if err != nil {
			return nil, fmt.Errorf("failed to load token after authentication: %w", err)
		}
	}
	return token, nil
}

func GetOAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "32555940559.apps.googleusercontent.com",
		ClientSecret: "ZmssLNjJy2998hD4CTg2ejr2",
		Endpoint:     google.Endpoint,
		Scopes: []string{
			compute.CloudPlatformScope,
		},
	}
}
