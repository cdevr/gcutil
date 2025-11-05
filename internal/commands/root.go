package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gcutil",
	Short: "A CLI tool for managing Google Cloud VMs",
	Long:  `gcutil is a command-line tool that allows you to authenticate and manage Google Cloud VM instances.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(listVMsCmd)
	rootCmd.AddCommand(addkeyCmd)
	rootCmd.AddCommand(sshCmd)
	rootCmd.AddCommand(scpCmd)
}
