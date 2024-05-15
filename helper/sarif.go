package helper

import (
	"context"
	"encoding/json"
	"fmt"
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
	Name    string `json:"name"`
}

type VulnerabilityInfo struct {
	VulnerabilityName        string    `json:"vulnerabilityName,omitempty"`
	VulnerabilityDescription string    `json:"vulnerabilityDescription,omitempty"`
	UpdatedOn                time.Time `json:"updatedOn,omitempty"`
}

type RuleIDInfo struct {
	OverRiddenRisk 	string		`json:"ruleID,omitempty"`
	ComputedRisk	string		`json:"overridden_risk,omitempty"`
	Status 			string		`json:"status,omitempty"`
	Message         string    	`json:"message,omitempty"`
	VulnerabilityID int                     `json:"vulnerabilityID,omitempty"`
	Vulnerability   VulnerabilityInfo       `json:"vulnerability,omitempty"`

}

type Result struct {
	RuleID          int                     `json:"ruleID,omitempty"`
	RuleIDProperties RuleIDInfo				`json:"RuleIDProperties,omitempty"`
	
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
			RuleIDProperties: RuleIDInfo{
				OverRiddenRisk: analysis.OverRiddenRisk.String(),
				ComputedRisk:   analysis.ComputedRisk.String(),
				Status:         analysis.Status.String(),
				Message:        fmt.Sprintf("CVSS Vector: %s, CVSS Base: %f, CVSS Version: %d, OWASP: %s", analysis.CvssVector, analysis.CvssBase, analysis.CvssVersion, analysis.Owasp),
				VulnerabilityID: analysis.VulnerabilityID,
				Vulnerability: VulnerabilityInfo{
					VulnerabilityName:        vulnerability.Name,
					VulnerabilityDescription: vulnerability.Description,
					UpdatedOn:                *analysis.UpdatedOn,
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
