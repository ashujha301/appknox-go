package cmd

import (
	"errors"
	"os"
	"strconv"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// analysesCmd represents the analyses command
var analysesCmd = &cobra.Command{
	Use:   "analyses",
	Short: "List analyses for file",
	Long:  `List analyses for file`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			helper.PrintError("valid file id is required")
			os.Exit(1)
		}

		//Get the value of the ghas flag
		sarif, _ := cmd.Flags().GetBool("sarif")

		helper.ProcessAnalyses(fileID,sarif)
	},
}

func init() {
	RootCmd.AddCommand(analysesCmd)

	//Add the ghas flag with a default value of false
	analysesCmd.Flags().BoolP(
		"sarif", "s", false, "Enable SARIF format")
}
