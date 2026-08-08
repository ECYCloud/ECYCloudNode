package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ECYCloud/ECYCloudNode/common/unlockcheck"
	"github.com/spf13/cobra"
)

// UnlockCheckResults represents all unlock check results
type UnlockCheckResults struct {
	YouTubePremium string `json:"YouTube_Premium"`
	Netflix        string `json:"Netflix"`
	DisneyPlus     string `json:"DisneyPlus"`
	HBOMax         string `json:"HBOMax"`
	AmazonPrime    string `json:"AmazonPrime"`
	OpenAI         string `json:"OpenAI"`
	Gemini         string `json:"Gemini"`
	Claude         string `json:"Claude"`
	TikTok         string `json:"TikTok"`
}

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "unlockcheck",
		Short: "Manually run streaming unlock detection",
		Long:  "Run streaming unlock detection manually and display results. This uses the same detection logic as the automatic check.",
		Run: func(cmd *cobra.Command, args []string) {
			runManualUnlockCheck()
		},
	})
}

func runManualUnlockCheck() {
	fmt.Println("========================================")
	fmt.Println("  ECYCloudNode Unlock Detection")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Starting detection (parallel execution)...")
	fmt.Println()

	startTime := time.Now()

	// Get the embedded script from unlockcheck package
	scriptPath := "/tmp/ecycloudnode_manual_check.sh"
	resultPath := "/tmp/ecycloudnode_unlock_check_result.json"

	// Get the script content from unlockcheck package
	script := unlockcheck.GetCSMScript()

	// Write script to temp file
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		fmt.Printf("Error: Failed to write script file: %v\n", err)
		return
	}
	defer os.Remove(scriptPath)

	// Execute the script
	execCmd := exec.Command("bash", scriptPath)
	execCmd.Env = append(os.Environ(), "LANG=en_US.UTF-8")
	output, err := execCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error: Failed to execute script: %v\n", err)
		fmt.Printf("Output: %s\n", string(output))
		return
	}

	// Read result JSON file
	resultData, err := os.ReadFile(resultPath)
	if err != nil {
		fmt.Printf("Error: Failed to read result file: %v\n", err)
		return
	}
	defer os.Remove(resultPath)

	// Parse JSON results
	var results UnlockCheckResults
	if err := json.Unmarshal(resultData, &results); err != nil {
		fmt.Printf("Error: Failed to parse result JSON: %v\n", err)
		return
	}

	elapsed := time.Since(startTime)

	// Display results
	fmt.Println("Detection Results:")
	fmt.Println("----------------------------------------")
	printResult("Netflix", results.Netflix)
	printResult("YouTube Premium", results.YouTubePremium)
	printResult("Disney+", results.DisneyPlus)
	printResult("HBO Max", results.HBOMax)
	printResult("Prime Video", results.AmazonPrime)
	printResult("OpenAI", results.OpenAI)
	printResult("Google Gemini", results.Gemini)
	printResult("Claude", results.Claude)
	printResult("TikTok", results.TikTok)
	fmt.Println("----------------------------------------")
	fmt.Printf("Detection completed in %.2f seconds\n", elapsed.Seconds())
	fmt.Println()

	// Output JSON
	fmt.Println("JSON Result:")
	jsonOutput, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(jsonOutput))
}

func printResult(service, result string) {
	status := "[ ]"
	if strings.HasPrefix(result, "Yes") {
		status = "[Y]"
	} else if strings.HasPrefix(result, "No") {
		status = "[N]"
	} else if result == "Unknown" {
		status = "[?]"
	}
	fmt.Printf("  %s %-16s: %s\n", status, service, result)
}
