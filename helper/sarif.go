package helper

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
)

type SARIF struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
	Tool    Tool   `json:"tool"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver ToolComponent `json:"driver"`
}

type ToolComponent struct {
	Name string `json:"name"`
}

type VulnerabilityInfo struct {
	VulnerabilityID          int       `json:"vulnerabilityID,omitempty"`
	VulnerabilityDescription string    `json:"vulnerabilityDescription,omitempty"`
	UpdatedOn                time.Time `json:"updatedOn,omitempty"`
}

type MessageInfo struct {
	Text string `json:"text,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Result struct {
	RuleID        int               `json:"ruleId,omitempty"`
	Level         string            `json:"level,omitempty"`
	Message       MessageInfo       `json:"message,omitempty"`
	Vulnerability VulnerabilityInfo `json:"Vulnerability,omitempty"`
	Location      []Location        `json:"location,omitempty"`
}

// ConvertToSARIF converts analysis data to SARIF format
func ConvertToSARIF(analysisData []appknox.Analysis, filePath string) error {

	ctx := context.Background()
	client := getClient()

	sarif := SARIF{
		Schema:  "https://raw.githubusercontent.com/schemastore/schemastore/master/src/schemas/json/sarif-2.1.0-rtm.5.json",
		Version: "2.1.0",
		Tool: Tool{
			Driver: ToolComponent{
				Name: "Appknox",
			},
		},
	}

	for _, analysis := range analysisData {
		vulnerability, _, err := client.Vulnerabilities.GetByID(
			ctx, analysis.VulnerabilityID,
		)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}

		result := Result{
			RuleID: analysis.ID,
			Level:  analysis.ComputedRisk.String(),
			Message: MessageInfo{
				Text: vulnerability.Name,
			},
			Vulnerability: VulnerabilityInfo{
				VulnerabilityID:          vulnerability.ID,
				VulnerabilityDescription: vulnerability.Description,
				UpdatedOn:                *analysis.UpdatedOn, // Update with actual time
			},
			Location: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: "file path to source location",
						},
					},
				},
			},
		}

		sarif.Runs = append(sarif.Runs, Run{
			Tool:    sarif.Tool,
			Results: []Result{result},
		})
	}
	sarifJSON, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	// Write SARIF JSON data to file
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write SARIF JSON data to file
	_, err = file.Write(sarifJSON)
	if err != nil {
		return err
	}

	return nil
}
