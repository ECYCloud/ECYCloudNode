package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ECYCloud/ECYCloudNode/common/unlockcheck"
	"github.com/ECYCloud/ECYCloudNode/panel"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "unlockcheck",
		Short: "Manually run streaming unlock detection",
		Long:  "Run streaming unlock detection manually, display results and report them to the configured panel nodes. This uses the same detection logic as the automatic check.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runManualUnlockCheck()
		},
	})
}

func runManualUnlockCheck() error {
	configPath := cfgFile
	if configPath == "" {
		configPath = "/etc/ECYCloudNode/config.yml"
	}
	config := viper.New()
	config.SetConfigFile(configPath)
	if err := config.ReadInConfig(); err != nil {
		return fmt.Errorf("读取节点配置失败：%w", err)
	}
	panelConfig := &panel.Config{}
	if err := config.Unmarshal(panelConfig); err != nil {
		return fmt.Errorf("解析节点配置失败：%w", err)
	}
	if len(panelConfig.NodesConfig) == 0 {
		return fmt.Errorf("节点配置中没有 Nodes，无法上报检测结果")
	}

	fmt.Println("========================================")
	fmt.Println("  ECYCloudNode Unlock Detection")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Starting detection (parallel execution)...")
	fmt.Println()

	startTime := time.Now()

	// 手动检测与后台定时检测使用各自的私有目录，避免上报另一轮结果。
	resultData, output, err := unlockcheck.RunScript("ecycloudnode-manual-")
	if err != nil {
		if len(output) > 0 {
			fmt.Printf("Output: %s\n", string(output))
		}
		return err
	}

	// Parse JSON results
	var results unlockcheck.UnlockCheckResults
	if err := json.Unmarshal(resultData, &results); err != nil {
		return fmt.Errorf("解析检测结果失败：%w", err)
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

	reported, err := panel.New(panelConfig).ReportUnlockCheckResult(results.ToJSON())
	fmt.Printf("已向面板上报 %d 个节点的检测结果。\n", reported)
	if err != nil {
		return fmt.Errorf("检测已完成，但结果上报失败：%w", err)
	}
	return nil
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
