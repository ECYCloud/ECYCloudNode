package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
	"github.com/xtls/xray-core/core"
)

var (
	// version will be overridden by -ldflags "-X" during CI build
	version  = "dev"
	codename = "ECYCloudNode"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print ECYCloudNode and embedded kernel versions",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Printf("%s %s\n", codename, version)
	// 面板部署时据此判断能否写入独立凭据：旧版本把 ApiKey 放进查询串，面板不接受这样提交的凭据。
	fmt.Println("Features: node-credential")
	showKernels()
}

func showKernels() {
	fmt.Printf("Xray-core: %s\n", core.Version())
	fmt.Printf("sing-box:  %s\n", moduleVersion("github.com/sagernet/sing-box"))
	fmt.Printf("Hysteria2: %s\n", moduleVersion("github.com/apernet/hysteria/core/v2"))
}

func moduleVersion(path string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path != path {
			continue
		}
		if dep.Replace != nil && dep.Replace.Version != "" {
			return dep.Replace.Version
		}
		if dep.Version != "" {
			return dep.Version
		}
		break
	}
	return "unknown"
}
