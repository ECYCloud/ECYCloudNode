package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	// 手动检测与后台定时检测使用独立文件，避免上报另一轮结果。
	workDir, err := os.MkdirTemp("", "ecycloudnode-manual-")
	if err != nil {
		return fmt.Errorf("创建检测临时目录失败：%w", err)
	}
	defer os.RemoveAll(workDir)
	scriptPath := filepath.Join(workDir, "check.sh")
	resultPath := filepath.Join(workDir, "unlock_check_result.json")

	// Get the script content from unlockcheck package
	script := unlockcheck.GetCSMScript()
	script = strings.ReplaceAll(script, "/tmp/ecycloudnode_unlock_check", "${ECYCLOUDNODE_UNLOCK_TMP}/unlock_check")

	// Write script to temp file
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("写入检测脚本失败：%w", err)
	}

	// Execute the script
	execCmd := exec.Command("bash", scriptPath)
	execCmd.Env = append(os.Environ(), "LANG=en_US.UTF-8", "ECYCLOUDNODE_UNLOCK_TMP="+filepath.ToSlash(workDir))
	output, err := execCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Output: %s\n", string(output))
		return fmt.Errorf("执行检测脚本失败：%w", err)
	}

	// Read result JSON file
	resultData, err := os.ReadFile(resultPath)
	if err != nil {
		return fmt.Errorf("读取检测结果失败：%w", err)
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
