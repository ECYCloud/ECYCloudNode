package panel

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ECYCloud/ECYCloudNode/api/sspanel"
)

// ReportUnlockCheckResult 按当前配置立即上报，无需启动代理服务或等待定时任务。
func (p *Panel) ReportUnlockCheckResult(result string) (int, error) {
	nodes := expandNodesConfig(p.panelConfig.NodesConfig)
	if len(nodes) == 0 {
		return 0, fmt.Errorf("没有可上报的节点配置")
	}
	type target struct {
		host string
		id   int
	}
	reported := make(map[target]bool)
	var failures []error
	for i, node := range nodes {
		if node == nil || node.ApiConfig == nil {
			failures = append(failures, fmt.Errorf("第 %d 项节点配置缺少 ApiConfig", i+1))
			continue
		}
		config := *node.ApiConfig
		id, err := strconv.Atoi(strings.TrimSpace(config.NodeID))
		if err != nil || id <= 0 {
			failures = append(failures, fmt.Errorf("第 %d 项节点配置的 NodeID 无效：%q", i+1, config.NodeID))
			continue
		}
		config.APIHost = strings.TrimRight(strings.TrimSpace(config.APIHost), "/")
		if config.APIHost == "" || strings.TrimSpace(config.Key) == "" {
			failures = append(failures, fmt.Errorf("节点 %d 缺少 ApiHost 或 ApiKey", id))
			continue
		}
		t := target{host: config.APIHost, id: id}
		if reported[t] {
			continue
		}
		// 上报只需要面板连接信息，不加载代理服务使用的审计规则文件。
		config.RuleListPath = ""
		if err := sspanel.New(&config).ReportUnlockCheckResult(result); err != nil {
			failures = append(failures, fmt.Errorf("面板 %s，节点 %d：%w", config.APIHost, id, err))
			continue
		}
		reported[t] = true
	}
	return len(reported), errors.Join(failures...)
}
