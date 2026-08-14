package panel

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"

	"dario.cat/mergo"
	"github.com/r3labs/diff/v2"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/ECYCloud/ECYCloudNode/api"
	"github.com/ECYCloud/ECYCloudNode/api/sspanel"
	"github.com/ECYCloud/ECYCloudNode/app/mydispatcher"
	_ "github.com/ECYCloud/ECYCloudNode/cmd/distro/all"
	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	"github.com/ECYCloud/ECYCloudNode/common/mylego"
	"github.com/ECYCloud/ECYCloudNode/common/unlockcheck"
	"github.com/ECYCloud/ECYCloudNode/service"
	"github.com/ECYCloud/ECYCloudNode/service/anytls"
	"github.com/ECYCloud/ECYCloudNode/service/controller"
	"github.com/ECYCloud/ECYCloudNode/service/hysteria2"
	"github.com/ECYCloud/ECYCloudNode/service/tuic"
)

// Panel Structure
type Panel struct {
	access      sync.Mutex
	panelConfig *Config
	Server      *core.Instance
	Service     []service.Service
	Running     bool
}

func New(panelConfig *Config) *Panel {
	p := &Panel{panelConfig: panelConfig}
	return p
}

// expandNodesConfig 将单条 Nodes 配置中声明的多个 NodeID 表达式展开为多个逻辑节点。
// 这样用户可以在同一份 ApiConfig/ControllerConfig 下，通过 NodeID: "41,42,43"
// 一次性启动多个面板节点，避免复制大段重复配置。
//
// 注意：该函数是 *纯函数*，不会修改传入的 nodes 切片本身，而是返回一份新的
// 展开结果。这样可以避免在多次热重载或重复调用 Start 时，对底层配置结构体
// 进行不可预期的原地修改。
func expandNodesConfig(nodes []*NodesConfig) []*NodesConfig {
	if len(nodes) == 0 {
		return nodes
	}

	expanded := make([]*NodesConfig, 0, len(nodes))
	for _, nodeConfig := range nodes {
		// 保持对空指针的兼容处理
		if nodeConfig == nil || nodeConfig.ApiConfig == nil {
			expanded = append(expanded, nodeConfig)
			continue
		}

		apiCfg := nodeConfig.ApiConfig

		// 从 NodeID 表达式中解析出所有有效的节点 ID：
		//   NodeID: 41
		//   NodeID: "41,42,43"
		//
		// 对于值为 "0" 的情况（面板端按 IP 自动匹配节点），不做展开，保持原始配置。
		ids := parseNodeIDExpr(apiCfg.NodeID)

		// 如果最终没有合法的 NodeID，则保持原行为，后续逻辑会按之前的方式报错/处理。
		// 包括：
		//   - NodeID 为空字符串；
		//   - NodeID 为 "0"（自动按 IP 匹配节点）；
		//   - NodeID 中所有条目都无法解析为合法整数。
		if len(ids) == 0 {
			expanded = append(expanded, nodeConfig)
			continue
		}

		// 为每一个 NodeID 复制一份节点配置，共享 ControllerConfig
		for _, id := range ids {
			ncCopy := *nodeConfig             // 结构体浅拷贝
			apiCopy := *apiCfg                // ApiConfig 浅拷贝
			apiCopy.NodeID = strconv.Itoa(id) // 为该实例设置独立的 NodeID 字符串
			ncCopy.ApiConfig = &apiCopy
			expanded = append(expanded, &ncCopy)
		}
	}

	return expanded
}

// parseNodeIDExpr 解析 NodeID 字段中的表达式，返回去重后的正整数 ID 列表。
//
// 支持以下形式：
//
//	NodeID: 41
//	NodeID: "41,42,43"
//
// 返回值仅包含 > 0 的整数；解析失败或为空时返回 nil。
// 特殊地，当 NodeID 为 "0" 时，视为按 IP 自动匹配节点的旧行为，本函数也返回 nil，
// 以便上层逻辑保持原始配置而不做展开。
func parseNodeIDExpr(expr string) []int {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "0" {
		return nil
	}

	parts := strings.Split(expr, ",")
	ids := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil || id <= 0 {
			continue
		}
		// 去重
		exists := false
		for _, existing := range ids {
			if existing == id {
				exists = true
				break
			}
		}
		if !exists {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return ids
}

func (p *Panel) loadCore(panelConfig *Config) *core.Instance {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if panelConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, panelConfig.LogConfig, logConfig); err != nil {
			log.Panicf("Read Log config failed: %s", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if panelConfig.DnsConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.DnsConfigPath); err != nil {
			log.Panicf("Failed to read DNS config file at: %s", panelConfig.DnsConfigPath)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Panicf("Failed to unmarshal DNS config: %s", panelConfig.DnsConfigPath)
			}
		}
	}

	// init controller's DNS config
	// for _, config := range p.panelConfig.NodesConfig {
	// 	config.ControllerConfig.DNSConfig = coreDnsConfig
	// }

	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand DNS config, Please check: https://xtls.github.io/config/dns.html for help: %s", err)
	}

	// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if panelConfig.RouteConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.RouteConfigPath); err != nil {
			log.Panicf("Failed to read Routing config file at: %s", panelConfig.RouteConfigPath)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				log.Panicf("Failed to unmarshal Routing config: %s", panelConfig.RouteConfigPath)
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand Routing config  Please check: https://xtls.github.io/config/routing.html for help: %s", err)
	}
	// Custom Inbound config
	var coreCustomInboundConfig []conf.InboundDetourConfig
	if panelConfig.InboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.InboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Inbound config file at: %s", panelConfig.OutboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom Inbound config: %s", panelConfig.OutboundConfigPath)
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.Panicf("Failed to understand Inbound config, Please check: https://xtls.github.io/config/inbound.html for help: %s", err)
		}
		inBoundConfig = append(inBoundConfig, oc)
	}
	// Custom Outbound config
	var coreCustomOutboundConfig []conf.OutboundDetourConfig
	if panelConfig.OutboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.OutboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Outbound config file at: %s", panelConfig.OutboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom Outbound config: %s", panelConfig.OutboundConfigPath)
			}
		}
	}
	var outBoundConfig []*core.OutboundHandlerConfig
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.Panicf("Failed to understand Outbound config, Please check: https://xtls.github.io/config/outbound.html for help: %s", err)
		}
		outBoundConfig = append(outBoundConfig, oc)
	}
	// Policy config
	levelPolicyConfig := parseConnectionConfig(panelConfig.ConnectionConfig)
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Core Config
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			// IMPORTANT: Register the official dispatcher FIRST so that upstream
			// code (e.g., mux.Server, vless inbound) that expects *dispatcher.DefaultDispatcher
			// receives the correct type. Our custom mydispatcher is registered
			// separately and accessed via mydispatcher.Type() in controller.go.
			// The dataPathWrapper.Dispatch method handles VLESS same-node routing.
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		log.Panicf("failed to create instance: %s", err)
	}

	return server
}

// Start the panel
func (p *Panel) Start() {
	p.access.Lock()
	defer p.access.Unlock()

	// 先记录一次从配置文件反序列化得到的原始节点列表，方便排查热重载
	// 时 Nodes 为空或结构异常的问题。
	rawNodes := p.panelConfig.NodesConfig
	log.Printf("Start the panel.. (raw nodes = %d)", len(rawNodes))
	for i, n := range rawNodes {
		if n == nil || n.ApiConfig == nil {
			log.Printf("  raw node[%d]: <nil>", i)
			continue
		}
		log.Printf("  raw node[%d]: PanelType=%s, ApiHost=%s, NodeID=%q", i, n.PanelType, n.ApiConfig.APIHost, n.ApiConfig.NodeID)
	}

	// 在启动之前先展开可能包含多个 NodeID 的节点配置；为了避免修改原始配置，
	// 这里在本地生成一份展开后的节点列表。
	nodes := expandNodesConfig(rawNodes)
	log.Printf("Start the panel.. (logical nodes = %d)", len(nodes))

	// 预先注册所有节点 ID 用于媒体检测共享
	// 这必须在任何节点启动之前完成，确保第一个执行检测的节点能为所有节点上报结果
	for _, nodeConfig := range nodes {
		if nodeConfig == nil || nodeConfig.ApiConfig == nil {
			continue
		}
		nodeIDStr := strings.TrimSpace(nodeConfig.ApiConfig.NodeID)
		if nodeIDStr == "" || nodeIDStr == "0" {
			continue
		}
		if nodeID, err := strconv.Atoi(nodeIDStr); err == nil && nodeID > 0 {
			unlockcheck.RegisterNodeID(nodeID)
		}
	}
	log.Printf("[UnlockCheck] Pre-registered all %d node IDs for shared detection", len(unlockcheck.GetRegisteredNodeIDs()))

	// Load Core
	server := p.loadCore(p.panelConfig)
	if err := server.Start(); err != nil {
		log.Panicf("Failed to start instance: %s", err)
	}
	p.Server = server

	// Load Nodes config
	for _, nodeConfig := range nodes {
		var apiClient api.API
		switch nodeConfig.PanelType {
		case "SSPanel":
			apiClient = sspanel.New(nodeConfig.ApiConfig)
			if webAPI, err := apiClient.GetWebAPIConfig(); err != nil {
				log.Warnf("Failed to get webapi config from panel: %v", err)
			} else if webAPI != nil && nodeConfig.ApiConfig != nil {
				newHost := strings.TrimSpace(webAPI.APIHost)
				oldHost := strings.TrimSpace(nodeConfig.ApiConfig.APIHost)
				if newHost != "" && strings.TrimRight(newHost, "/") != strings.TrimRight(oldHost, "/") {
					log.Infof("ApiHost updated from panel: %s -> %s", oldHost, newHost)
					nodeConfig.ApiConfig.APIHost = newHost
					apiClient = sspanel.New(nodeConfig.ApiConfig)
				}
			}
		default:
			log.Panicf("Unsupport panel type: %s", nodeConfig.PanelType)
		}

		limiter.SetReclaimConsumer(func(uid int, ip string) bool {
			ok, err := apiClient.ConsumeIpReclaim(uid, ip)
			if err != nil {
				log.Warnf("ConsumeIpReclaim uid=%d ip=%s: %v", uid, ip, err)
				return false
			}
			return ok
		})

		// Register service for this node
		controllerConfig := getDefaultControllerConfig()
		if nodeConfig.ControllerConfig != nil {
			if err := mergo.Merge(controllerConfig, nodeConfig.ControllerConfig, mergo.WithOverride); err != nil {
				log.Panicf("Read Controller Config Failed")
			}
		}
		// 证书相关配置改为完全由面板下发和自动推导，不再支持通过
		// config.yml 的 ControllerConfig.CertConfig 手动填写。为避免旧
		// 配置产生干扰，这里直接丢弃来自本地配置文件的 CertConfig。
		if nodeConfig.PanelType == "SSPanel" {
			controllerConfig.CertConfig = nil
		}

		var svc service.Service
		var nodeInfo *api.NodeInfo

		// If the panel exposes global ECYCloudNode cert settings, merge Provider/Email/
		// DNSEnv into the controller's CertConfig. When CertConfig is missing
		// from config.yml (which is common now that certificate settings are
		// managed from the panel), allocate a minimal struct on demand and
		// default CertMode to "dns" so that TLS nodes work out-of-the-box.
		if nodeConfig.PanelType == "SSPanel" {
			panelCert, err := apiClient.GetECYCloudNodeCertConfig()
			if err != nil {
				log.Warnf("Failed to get ECYCloudNode cert config from panel: %v", err)
			} else if panelCert != nil {
				if controllerConfig.CertConfig == nil {
					controllerConfig.CertConfig = &mylego.CertConfig{}
				}
				// panel 仅下发 Provider/Email/DNSEnv，不关心 CertMode，若此时
				// 仍为空则默认使用 DNS-01 ACME（"dns"），避免后续出现
				// "unsupported certmode: " 之类错误。
				if controllerConfig.CertConfig.CertMode == "" {
					controllerConfig.CertConfig.CertMode = "dns"
				}
				if panelCert.Provider != "" {
					controllerConfig.CertConfig.Provider = panelCert.Provider
				}
				if panelCert.Email != "" {
					controllerConfig.CertConfig.Email = panelCert.Email
				}
				if len(panelCert.DNSEnv) > 0 {
					if controllerConfig.CertConfig.DNSEnv == nil {
						controllerConfig.CertConfig.DNSEnv = make(map[string]string)
					}
					for k, v := range panelCert.DNSEnv {
						controllerConfig.CertConfig.DNSEnv[k] = v
					}
				}
			}
		}

		// 全局设备限制的 Redis 连接信息由面板下发（设置中心-节点相关：
		// 站点IP、RedisPassword）。config.yml 中 RedisAddr/RedisPassword
		// 留空时自动读取面板值；本地填写值优先，便于特殊网络拓扑覆盖。
		if nodeConfig.PanelType == "SSPanel" {
			if glc := controllerConfig.GlobalDeviceLimitConfig; glc != nil && glc.Enable && (glc.RedisAddr == "" || glc.RedisPassword == "") {
				panelGlobal, err := apiClient.GetGlobalLimitConfig()
				if err != nil {
					log.Warnf("Failed to get global limit config from panel: %v", err)
				} else if panelGlobal != nil {
					if glc.RedisAddr == "" && panelGlobal.SiteIP != "" {
						glc.RedisAddr = panelGlobal.SiteIP + ":6379"
					}
					if glc.RedisPassword == "" && panelGlobal.RedisPassword != "" {
						glc.RedisPassword = panelGlobal.RedisPassword
					}
				}
				if glc.RedisAddr == "" {
					log.Warn("GlobalDeviceLimitConfig enabled but RedisAddr is empty (config.yml 未填且面板“站点IP”为空), global device limit will not work")
				}
			}
		}

		// Hysteria2 and AnyTLS are implemented as independent services and
		// currently only supported for SSPanel.
		if nodeConfig.PanelType == "SSPanel" {
			var err error
			nodeInfo, err = apiClient.GetNodeInfo()
			if err != nil {
				// 对于单个节点的拉取失败，不再直接 panic 终止整个进程，而是
				// 打印错误并跳过该节点，保证其它已正确配置的节点仍然可以正常
				// 启动和提供服务。
				apiCfg := nodeConfig.ApiConfig
				log.Errorf("Get node info failed, skip this node (PanelType=%s, ApiHost=%s, NodeID=%s): %v",
					nodeConfig.PanelType,
					func() string {
						if apiCfg != nil {
							return apiCfg.APIHost
						}
						return ""
					}(),
					func() string {
						if apiCfg != nil {
							return apiCfg.NodeID
						}
						return ""
					}(),
					err,
				)
				continue
			}

			// Derive per-node certificate configuration from panel SNI / Host
			// when TLS is enabled and REALITY is not in use. This allows using
			// different certificates per node without duplicating config.yml.
			if nodeInfo != nil && nodeInfo.EnableTLS && !nodeInfo.EnableREALITY {
				// When CertConfig is missing, create one; if CertMode is still
				// empty at this point, default it to dns so that DNS-01 ACME is
				// used by default for TLS nodes.
				if controllerConfig.CertConfig == nil {
					controllerConfig.CertConfig = &mylego.CertConfig{}
				}
				if controllerConfig.CertConfig.CertMode == "" {
					controllerConfig.CertConfig.CertMode = "dns"
				}

				sni := nodeInfo.SNI
				if sni == "" {
					// Fallback to Host when SNI is not explicitly provided
					sni = nodeInfo.Host
				}
				if sni != "" {
					baseCert := *controllerConfig.CertConfig // copy value
					nodeCert := &baseCert

					switch nodeCert.CertMode {
					case "file":
						// When CertFile/KeyFile are not explicitly configured, use a
						// simple convention based on SNI under /etc/ECYCloudNode/cert.
						if nodeCert.CertFile == "" && nodeCert.KeyFile == "" {
							nodeCert.CertDomain = sni
							nodeCert.CertFile = "/etc/ECYCloudNode/cert/" + sni + ".cert"
							nodeCert.KeyFile = "/etc/ECYCloudNode/cert/" + sni + ".key"
						} else if nodeCert.CertDomain == "" {
							// If a static path is configured but CertDomain is empty,
							// still record the logical domain for ACME/renewal logs.
							nodeCert.CertDomain = sni
						}
					case "dns", "http", "tls":
						// For ACME modes, prefer panel SNI as CertDomain when it is
						// not explicitly specified in config.yml.
						if nodeCert.CertDomain == "" {
							nodeCert.CertDomain = sni
						}
					}

					controllerConfig.CertConfig = nodeCert
				}
			}

			if nodeInfo != nil {
				switch nodeInfo.NodeType {
				case "Hysteria2":
					// For Hysteria2 we don't use xray-core controller, instead we
					// start a dedicated Hysteria2 service.
					serviceConfig := *controllerConfig // shallow copy
					serviceConfig.CertConfig = controllerConfig.CertConfig
					svc = hysteria2.New(apiClient, &serviceConfig)
				case "AnyTLS":
					// AnyTLS uses a sing-box based independent service.
					serviceConfig := *controllerConfig // shallow copy
					serviceConfig.CertConfig = controllerConfig.CertConfig
					svc = anytls.New(apiClient, &serviceConfig)
				case "Tuic":
					// TUIC uses a sing-box based independent service.
					serviceConfig := *controllerConfig // shallow copy
					serviceConfig.CertConfig = controllerConfig.CertConfig
					svc = tuic.New(apiClient, &serviceConfig)
				}
			}
		}

		if svc == nil {
			// Default behaviour: use the original controller service.
			svc = controller.New(server, apiClient, controllerConfig, nodeConfig.PanelType)
		}

		p.Service = append(p.Service, svc)

	}

	// Start all the service
	if len(p.Service) == 0 {
		log.Warn("No services started for any node; please check your Nodes config and panel connectivity")
	} else {
		for _, s := range p.Service {
			if err := s.Start(); err != nil {
				// 同样不再因为单个 service 启动失败而直接 panic，避免影响其它
				// 已经可以正常工作的节点。
				log.Errorf("Panel Start failed for a service: %s", err)
			}
		}
	}
	p.Running = true
	return
}

// Close the panel
func (p *Panel) Close() {
	p.access.Lock()
	defer p.access.Unlock()
	for _, s := range p.Service {
		err := s.Close()
		if err != nil {
			log.Panicf("Panel Close failed: %s", err)
		}
	}
	p.Service = nil
	p.Server.Close()
	p.Running = false
	return
}

func parseConnectionConfig(c *ConnectionConfig) (policy *conf.Policy) {
	connectionConfig := getDefaultConnectionConfig()
	if c != nil {
		if _, err := diff.Merge(connectionConfig, c, connectionConfig); err != nil {
			log.Panicf("Read ConnectionConfig failed: %s", err)
		}
	}
	policy = &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connectionConfig.Handshake,
		ConnectionIdle:    &connectionConfig.ConnIdle,
		UplinkOnly:        &connectionConfig.UplinkOnly,
		DownlinkOnly:      &connectionConfig.DownlinkOnly,
		BufferSize:        &connectionConfig.BufferSize,
	}

	return
}
