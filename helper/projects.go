package helper

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/landoop/tableprinter"
)

// ProjectData represents a struct which will be printed to the CLI.
type ProjectData struct {
	ID          int        `header:"id"`
	CreatedOn   *time.Time `header:"created-on"`
	UpdatedOn   *time.Time `header:"updated-on"`
	PackageName string     `header:"package-name"`
	Platform    int        `header:"platform"`
	FileCount   int        `header:"file-count"`
}

// ProcessProjects takes the list of files and print it to CLI.
func ProcessProjects(platform, packageName, query string, offset, limit int) {
	ctx := context.Background()
	client := getClient()
	options := &appknox.ProjectListOptions{
		Platform:    *appknox.String(platform),
		PackageName: *appknox.String(packageName),
		Search:      *appknox.String(query),
		ListOptions: appknox.ListOptions{
			Offset: *appknox.Int(offset),
			Limit:  *appknox.Int(limit)},
	}
	projects, _, err := client.Projects.List(ctx, options)
	if err != nil {
		fmt.Println(err.Error())
	}
	items := []ProjectData{}
	for i := 0; i < len(projects); i++ {
		items = append(items,
			ProjectData{
				projects[i].ID,
				projects[i].CreatedOn,
				projects[i].UpdatedOn,
				projects[i].PackageName,
				projects[i].Platform,
				projects[i].FileCount,
			})
	}
	tableprinter.Print(os.Stdout, items)
}
