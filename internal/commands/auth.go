package commands

import (
	"gcutil/internal/auth"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with Google Cloud",
	Long:  `Authenticate with Google Cloud using OAuth2 web flow.`,
	RunE:  runAuthCmd,
}

func runAuthCmd(cmd *cobra.Command, args []string) error {
	return auth.RunAuth()
}
