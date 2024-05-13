package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/appknox/enums"
	"github.com/cheynewallace/tabby"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

// SARIFResult represents sarif formatted data
type SARIFResult struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Risk    string `json:"risk"`
			Message string `json:"message"`
		} `json:"results"`
	} `json:"runs"`
}

// ProcessCiCheck takes the list of analyses and print it to CLI.
func ProcessCiCheck(fileID, riskThreshold int, sarifBool bool) {
	ctx := context.Background()
	client := getClient()
	var staticScanProgess int
	start := time.Now()
	p := mpb.New(
		mpb.WithWidth(60),
		mpb.WithRefreshRate(180*time.Millisecond),
		mpb.WithOutput(os.Stderr),
	)
	name := "Static Scan Progress: "
	bar := p.AddBar(100, mpb.BarStyle("[=>-|"),
		mpb.PrependDecorators(
			decor.Name(name, decor.WC{W: len(name) + 1, C: decor.DidentRight}),
			decor.Percentage(),
		),
		mpb.AppendDecorators(
			decor.Name("] "),
		),
	)

	for staticScanProgess < 100 {
		file, _, err := client.Files.GetByID(ctx, fileID)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		staticScanProgess = file.StaticScanProgress
		bar.SetCurrent(int64(staticScanProgess), time.Since(start))
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
	t := tabby.New()
	t.AddHeader(
		"ANALYSIS-ID",
		"RISK",
		"CVSS-VECTOR",
		"CVSS-BASE",
		"VULNERABILITY-ID",
		"VULNERABILITY-NAME",
	)
	vulnerableAnalyses := make([]appknox.Analysis, 0)
	var sarif SARIFResult
	for _, analysis := range finalAnalyses {
		if int(analysis.ComputedRisk) >= riskThreshold {
			vulnerableAnalyses = append(vulnerableAnalyses, *analysis)
		}
	}
	for _, analysis := range vulnerableAnalyses {
		vulnerability, _, err := client.Vulnerabilities.GetByID(
			ctx, analysis.VulnerabilityID,
		)
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		t.AddLine(
			analysis.ID,
			analysis.ComputedRisk,
			analysis.CvssVector,
			analysis.CvssBase,
			analysis.VulnerabilityID,
			vulnerability.Name,
		)

		sarif.Runs = append(sarif.Runs, struct {
			Results []struct {
				RuleID  string "json:\"ruleId\""
				Risk    string "json:\"risk\""
				Message string "json:\"message\""
			} "json:\"results\""
		}{
			Results: []struct {
				RuleID  string `json:"ruleId"`
				Risk    string "json:\"risk\""
				Message string `json:"message"`
			}{
				{
					RuleID:  fmt.Sprintf("%d", analysis.ID),
					Risk:    fmt.Sprintf("%d", analysis.ComputedRisk),
					Message: fmt.Sprintf("Vulnerability Name: %s, CVSS Vector: %s, CVSS Base: %s, Vulnerability ID: %s", vulnerability.Name, analysis.CvssVector, analysis.CvssBase, analysis.VulnerabilityID),
				},
			},
		})
	}

	// Print SARIF formatted result if sarif is true
	if sarifBool{
		jsonSARIF, err := json.MarshalIndent(sarif, "", "  ")
		if err != nil {
			PrintError(err)
			os.Exit(1)
		}
		fmt.Println("SARIF FORMATTED RESULT:")
		fmt.Println(string(jsonSARIF))
	}

	vulLen := len(vulnerableAnalyses)

	msg := fmt.Sprintf("\nCheck file ID %d on appknox dashboard for more details.\n", fileID)
	if vulLen > 0 {
		errmsg := fmt.Sprintf("Found %d vulnerabilities with risk >= %s\n", vulLen, enums.RiskType(riskThreshold))
		PrintError(errmsg)
		t.Print()
		fmt.Printf(msg)
		os.Exit(1)
	} else {
		fmt.Println("\nNo vulnerabilities found with risk threshold >= ", enums.RiskType(riskThreshold))
		fmt.Printf(msg)
	}
}
