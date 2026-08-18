package api

import (
	"encoding/json"
	"regexp"
	"strings"
)

const (
	UserNotModified = "users not modified"
	NodeNotModified = "node not modified"
	RuleNotModified = "rules not modified"

	// MaxConsecutiveFailures 是触发服务自动重启的连续 API 失败阈值。
	// 当 monitor 连续检测到 API 通讯失败达到此次数后，服务会自动执行
	// Close + Start 重启循环，以便在面板更新白名单后自动恢复通讯。
	MaxConsecutiveFailures = 3
)

// IsAPIFailure 判断 API 调用返回的错误是否代表与面板的通讯失败
// （区别于 "数据未变更" 等正常逻辑错误）。
func IsAPIFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	switch msg {
	case UserNotModified, NodeNotModified, RuleNotModified:
		return false
	}
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "ret") && strings.Contains(lower, "invalid") {
		return true
	}
	if strings.Contains(lower, "failed") {
		return true
	}
	return false
}

// Config API config
//
// VLESS 相关配置（是否启用 VLESS、flow 等）不再从本地配置文件读取，
// 而是完全由面板的 custom_config / NodeType 决定。这样可以避免面板与
// ECYCloudNode 配置不一致带来的混乱，因此这里不再包含任何与 VLESS 开关相关
// 的字段。
type Config struct {
	APIHost string `mapstructure:"ApiHost"`
	// NodeID 支持单个或多个节点 ID：
	//   NodeID: 41
	//   NodeID: "41,42,43"
	//
	// 当 NodeID 为空字符串时，视为未配置；
	// 当仅为数字时表示单个节点；当包含逗号时会在 Panel.expandNodesConfig
	// 中被拆分为多个逻辑节点，每个逻辑节点拥有独立的 NodeID。
	NodeID       string  `mapstructure:"NodeID"`
	Key          string  `mapstructure:"ApiKey"`
	Timeout      int     `mapstructure:"Timeout"`
	SpeedLimit   float64 `mapstructure:"SpeedLimit"`
	DeviceLimit  int     `mapstructure:"DeviceLimit"`
	RuleListPath string  `mapstructure:"RuleListPath"`
}

// NodeStatus Node status
type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

type NodeInfo struct {
	AcceptProxyProtocol bool
	NodeType            string // Must be Vmess, VLESS, Trojan, Shadowsocks, Hysteria2, AnyTLS, Tuic
	NodeID              int
	Port                uint32
	SpeedLimit          uint64 // Bps
	TransportProtocol   string
	Host                string
	Path                string
	// SNI is the Server Name Indication derived from panel configuration.
	// For custom_config nodes it prefers `sni` / `server_name`; for legacy
	// nodes it falls back to the parsed Host when available.
	SNI              string
	EnableTLS        bool
	RouteOnly        bool
	VlessFlow        string
	VlessDecryption  string
	CypherMethod     string
	ServerKey        string
	ServiceName      string
	Method           string
	Header           json.RawMessage
	Headers          map[string]string
	Seed             string
	EnableREALITY    bool
	REALITYConfig    *REALITYConfig
	Dest             string
	ProxyProtocolVer uint64
	ServerNames      []string
	PrivateKey       string
	MinClientVer     string
	MaxClientVer     string
	MaxTimeDiff      uint64
	ShortIds         []string
	Flow             string
	Security         string
	Key              string
	Hysteria2Config  *Hysteria2Config
	AnyTLSConfig     *AnyTLSConfig
	TuicConfig       *TuicConfig
}

// ECYCloudNodeCertConfig describes the certificate-related configuration
// that ECYCloudNode can load from the panel (e.g. Cloudflare DNS provider
// and its environment variables for lego/ACME).
type ECYCloudNodeCertConfig struct {
	Provider string            `json:"provider"`
	Email    string            `json:"email"`
	DNSEnv   map[string]string `json:"dns_env"`
}

// GlobalLimitConfig describes the panel-managed Redis connection info
// (设置中心-节点相关) used by the cross-node global device limit.
type GlobalLimitConfig struct {
	SiteIP        string `json:"site_ip"`
	RedisPassword string `json:"redis_password"`
}

// WebAPIConfig is the panel-managed API host (设置中心「订阅域名」subUrl).
type WebAPIConfig struct {
	APIHost string `json:"api_host"`
}

type Hysteria2Config struct {
	Obfs                  string
	ObfsPassword          string
	UpMbps                int
	DownMbps              int
	IgnoreClientBandwidth bool

	// Port hopping configuration for Hysteria2. These fields are populated
	// from the panel custom_config when the node type is Hysteria2.
	//
	// PortHopPorts is a canonical, comma-separated expression such as
	// "30000-50000,60000" mirroring the panel-side representation.
	PortHopEnabled bool
	PortHopPorts   string
}

type AnyTLSConfig struct {
	PaddingScheme []string
}

type TuicConfig struct {
	CongestionControl string
	UDPRelayMode      string
	ZeroRTTHandshake  bool
	Heartbeat         int
	ALPN              []string
}

type UserInfo struct {
	UID         int
	Email       string
	UUID        string
	Passwd      string
	Port        uint32
	Method      string
	SpeedLimit  uint64 // Bps
	DeviceLimit int
}

type OnlineUser struct {
	UID int
	IP  string
}

type UserTraffic struct {
	UID      int
	Email    string
	Upload   int64
	Download int64
}

type ClientInfo struct {
	APIHost string
	NodeID  int
	Key     string
}

type DetectRule struct {
	ID      int
	Pattern *regexp.Regexp
}

type DetectResult struct {
	UID    int
	RuleID int
	IP     string
}

// ExemptUser represents a user's audit exemption configuration.
// Rules dimension: GlobalExempt=true means exempt from all rules; otherwise ExemptRuleIDs lists allowed rule IDs.
// Nodes dimension: GlobalNode=true means exempt on all nodes; otherwise ExemptNodeIDs lists nodes where the exemption applies.
type ExemptUser struct {
	UID           int
	GlobalExempt  bool  // true = exempt from all rules
	ExemptRuleIDs []int // non-nil only when GlobalExempt is false
	GlobalNode    bool  // true = exemption applies on all nodes
	ExemptNodeIDs []int // non-nil only when GlobalNode is false
}

type REALITYConfig struct {
	Dest             string
	ProxyProtocolVer uint64
	ServerNames      []string
	PrivateKey       string
	MinClientVer     string
	MaxClientVer     string
	MaxTimeDiff      uint64
	ShortIds         []string
	Mldsa65Seed      string
}

// UnlockCheckConfig represents the streaming unlock check configuration
// retrieved from the panel.
type UnlockCheckConfig struct {
	// Enabled indicates whether unlock check is enabled
	Enabled bool `json:"enabled"`
	// CheckInterval is the interval between checks in hours
	CheckInterval int `json:"check_interval"`
}
