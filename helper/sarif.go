package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/iancoleman/strcase"
)

type SARIF struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    ToolComponent `json:"tool"`
	Results []Result      `json:"results"`
}

type ToolComponent struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type Rule struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	ShortDescription Description `json:"shortDescription"`
	FullDescription  Description `json:"fullDescription"`
	Help             Help        `json:"help,omitempty"`
}

type Description struct {
	Text string `json:"text"`
}

type RuleProperties struct {
	Precision string `json:"precision"`
	Severity  string `json:"severity"`
}

type Result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Properties          RuleProperties    `json:"properties"`
	Locations           []Location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type Message struct {
	ID        string   `json:"id,omitempty"`
	Arguments []string `json:"arguments,omitempty"`
	Text      string   `json:"text,omitempty"`
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

type Help struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// ConvertToSARIF converts analysis data to SARIF format
func ConvertToSARIF(analysisData []appknox.Analysis, filePath string) error {
	ctx := context.Background()
	client := getClient()

	sarif := SARIF{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	driver := Driver{
		Name:  "Appknox",
		Rules: []Rule{},
	}

	results := []Result{}

	for _, analysis := range analysisData {
		vulnerability, _, err := client.Vulnerabilities.GetByID(ctx, analysis.VulnerabilityID)
		if err != nil {
			return err
		}

		ruleID := fmt.Sprintf("APX0%d", vulnerability.ID)
		var level string
		switch analysis.ComputedRisk {
		case enums.Risk.Low:
			level = "note"
		case enums.Risk.Medium:
			level = "warning"
		case enums.Risk.High, enums.Risk.Critical:
			level = "error"
		default:
			level = "none"
		}

		rule := Rule{
			ID:   ruleID,
			Name: strcase.ToCamel(vulnerability.Name),
			ShortDescription: Description{
				Text: vulnerability.Intro,
			},
			FullDescription: Description{
				Text: vulnerability.Description,
			},
			Help: Help{
				Text:     "Recommendations",
				Markdown: fmt.Sprintf("## Recommendations\n\n### Compliant:\n%s\n\n### Non-Compliant:\n%s", vulnerability.Compliant, vulnerability.NonCompliant),
			},
		}

		driver.Rules = append(driver.Rules, rule)

		result := Result{
			RuleID: ruleID,
			Level:  level,
			Message: Message{
				Text: vulnerability.Intro,
			},
			Properties: RuleProperties{
				Precision: "medium",
				Severity:  fmt.Sprintf("%d", analysis.ComputedRisk),
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: "unknown",
						},
					},
				},
			},
			PartialFingerprints: map[string]string{
				"vulnerabilityId": fmt.Sprintf("%d", vulnerability.ID),
			},
		}

		results = append(results, result)
	}

	run := Run{
		Tool: ToolComponent{
			Driver: driver,
		},
		Results: results,
	}

	sarif.Runs = []Run{run}

	sarifJSON, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(sarifJSON)
	if err != nil {
		return err
	}

	return nil
}
