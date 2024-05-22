package cmd

import (
	"errors"
	"os"
	"strconv"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// analysesCmd represents the analyses command
var sarifCmd = &cobra.Command{
	Use:   "sarif",
	Short: "Create SARIF report",
	Long:  `Create SARIF report`,
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
		outputFilePath, _ := cmd.Flags().GetString("output")
		if outputFilePath == "" {
			helper.PrintError(errors.New(`Error: Required flag "output" not set`))
			return
		}

		helper.ConvertToSARIFReport(fileID,outputFilePath)
	},
}

func init() {
	RootCmd.AddCommand(sarifCmd)
	sarifCmd.PersistentFlags().StringP("output", "o", "", "Output file path to save reports")
}
