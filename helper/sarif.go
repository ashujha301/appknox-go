package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/iancoleman/strcase"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
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
	Name    string `json:"name"`
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription Description    `json:"shortDescription"`
	FullDescription  Description    `json:"fullDescription"`
	Help             Help           `json:"help,omitempty"`
	Properties       RuleProperties `json:"properties"`
}

type Description struct {
	Text string `json:"text"`
}

type RuleProperties struct {
	Tags             []string `json:"tags"`
	Kind             string   `json:"kind"`
	Precision        string   `json:"precision"`
	ProblemSeverity  string   `json:"problem.severity"`
	SecuritySeverity string   `json:"security-severity"`
}

type Result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
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
	URI     string `json:"uri"`
	URIBase string `json:"uriBaseId"`
}

type Help struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// ConvertToSARIF converts analysis data to SARIF format
func ConvertToSARIFReport(fileID int, filePath string) error {
	ctx := context.Background()
	client := getClient()
	var sarifReportProgess int
	start := time.Now()
	p := mpb.New(
		mpb.WithWidth(60),
		mpb.WithRefreshRate(180*time.Millisecond),
		mpb.WithOutput(os.Stderr),
	)
	name := "Creating SARIF Formatted Report: "
	bar := p.AddBar(100, mpb.BarStyle("[=>-|"),
		mpb.PrependDecorators(
			decor.Name(name, decor.WC{W: len(name) + 1, C: decor.DidentRight}),
			decor.Percentage(),
		),
		mpb.AppendDecorators(
			decor.Name("] "),
		),
	)

	for sarifReportProgess < 100 {
		file, _, err := client.Files.GetByID(ctx, fileID)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		sarifReportProgess = file.StaticScanProgress
		bar.SetCurrent(int64(sarifReportProgess), time.Since(start))
		if time.Since(start) > 15*time.Minute {
			err := errors.New("Request timed out")
			PrintError(err)
			os.Exit(1)
		}
	}

	_, analysisResponse, err := client.Analyses.ListByFile(ctx, fileID, nil)
	analysisCount := analysisResponse.GetCount()
	options := &appknox.AnalysisListOptions{
		ListOptions: appknox.ListOptions{
			Limit: analysisCount},
	}
	finalAnalyses, _, err := client.Analyses.ListByFile(ctx, fileID, options)
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}

	analysisData := make([]appknox.Analysis, 0)
	for _, analysis := range finalAnalyses {
		{
			analysisData = append(analysisData, *analysis)
		}
	}

	sarif := SARIF{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	driver := Driver{
		Name:    "Appknox",
		Version: "1.4.6",
		Rules:   []Rule{},
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

		compliantMessage := "No security risks identified."
		nonCompliantMessage := "Security issues identified. Please review and mitigate."

		if vulnerability.Compliant != "" {
			compliantMessage = vulnerability.Compliant
		}
		if vulnerability.NonCompliant != "" {
			nonCompliantMessage = vulnerability.NonCompliant
		}

		markdown := "## Summary of Findings\n\n"
		markdown += "### Description:\n" + vulnerability.Description + "\n\n"
		markdown += "### Recommendations\n\n"
		markdown += "#### Compliant:\n" + compliantMessage + "\n\n"
		markdown += "#### Non-Compliant:\n" + nonCompliantMessage

		tags := []string{"security"}
		if len(analysis.Cwe) > 0 {
			for _, cwe := range analysis.Cwe {
				transformedCWE := strings.Replace(cwe, "_", "-", 1)

				tags = append(tags, transformedCWE)
			}
		}

		rule := Rule{
			ID:   ruleID,
			Name: strcase.ToCamel(vulnerability.Name),
			ShortDescription: Description{
				Text: vulnerability.Name,
			},
			FullDescription: Description{
				Text: vulnerability.Intro,
			},
			Help: Help{
				Text:     "Summary of Findings",
				Markdown: markdown,
			},
			Properties: RuleProperties{
				Tags:             tags,
				Precision:        "high",
				ProblemSeverity:  level,
				SecuritySeverity: fmt.Sprintf("%.1f", analysis.CvssBase),
			},
		}

		driver.Rules = append(driver.Rules, rule)

		result := Result{
			RuleID: ruleID,
			Level:  level,
			Message: Message{
				Text: vulnerability.Intro,
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: "SRCROOT",
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
	fmt.Println("SARIF report created successfully at:", filePath)
	return nil
}
