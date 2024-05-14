package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
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
	Name    string `json:"name"`
	Version string `json:"version"`
}

type VulnerabilityInfo struct {
	VulnerabilityName        string    `json:"vulnerabilityName,omitempty"`
	VulnerabilityDescription string    `json:"vulnerabilityDescription,omitempty"`
	Message                  string    `json:"message,omitempty"`
	UpdatedOn                time.Time `json:"updatedOn,omitempty"`
}

type Result struct {
	RuleID          int                     `json:"ruleID,omitempty"`
	OverRiddenRisk  enums.RiskType          `json:"overridden_risk,omitempty"`
	ComputedRisk    enums.RiskType          `json:"computed_risk,omitempty"`
	Status          enums.AnalysisStateType `json:"status,omitempty"`
	VulnerabilityID int                     `json:"vulnerabilityID,omitempty"`
	Vulnerability   VulnerabilityInfo       `json:"vulnerability,omitempty"`
}

// ConvertToSARIF converts analysis data to SARIF format
func ConvertToSARIF(analysisData []appknox.Analysis, filePath string) error {

	ctx := context.Background()
	client := getClient()

	sarif := SARIF{
		Schema:  "SARIF",
		Version: "2.1.0",
		Tool: Tool{
			Driver: ToolComponent{
				Name:    "Appknox",
				Version: "1.0.0",
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
			RuleID:         analysis.ID,
			OverRiddenRisk: analysis.OverRiddenRisk,
			ComputedRisk:   analysis.ComputedRisk,
			Status:         analysis.Status,

			VulnerabilityID: analysis.VulnerabilityID,
			Vulnerability: VulnerabilityInfo{
				VulnerabilityName:        vulnerability.Name,
				VulnerabilityDescription: vulnerability.Description,
				Message:                  fmt.Sprintf("CVSS Vector: %s, CVSS Base: %f, CVSS Version: %d, OWASP: %s", analysis.CvssVector, analysis.CvssBase, analysis.CvssVersion, analysis.Owasp),
				UpdatedOn:                *analysis.UpdatedOn,
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
