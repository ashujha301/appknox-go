package cmd

import (
	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// projectsCmd represents the projects command
var projectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "List projects",
	Long:  `List projects`,
	Run: func(cmd *cobra.Command, args []string) {
		platform := cmd.Flag("platform").Value.String()
		packageName := cmd.Flag("package_name").Value.String()
		query := cmd.Flag("query").Value.String()
		offset, _ := RootCmd.Flags().GetInt("offset")
		limit, _ := RootCmd.Flags().GetInt("limit")
		helper.ProcessProjects(platform, packageName, query, offset, limit)
	},
}

func init() {
	RootCmd.AddCommand(projectsCmd)
	projectsCmd.Flags().StringP("platform", "p", "", "Filter with project platform")
	projectsCmd.Flags().StringP("package_name", "g", "", "Filter with package name")
	projectsCmd.Flags().StringP("query", "q", "", "Filter with search query")
}
