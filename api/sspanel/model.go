package sspanel

import "encoding/json"

// NodeInfoResponse is the response of node
type NodeInfoResponse struct {
	SpeedLimit   float64         `json:"node_speedlimit"`
	Sort         int             `json:"sort"`
	CustomConfig json.RawMessage `json:"custom_config"`
}

type CustomConfig struct {
	OffsetPortNode        looseString    `json:"offset_port_node"`
	Host                  string         `json:"host"`
	Method                string         `json:"method"`
	ServerKey             string         `json:"server_key"`
	Network               string         `json:"network"`
	Security              string         `json:"security"`
	Path                  string         `json:"path"`
	Obfs                  string         `json:"obfs"`
	HeaderType            string         `json:"header_type"`
	Seed                  string         `json:"seed"`
	Servicename           string         `json:"servicename"`
	Flow                  string         `json:"flow"`
	EnableREALITY         looseBool      `json:"enable_reality"`
	RealityOpts           *REALITYConfig `json:"reality-opts"`
	ObfsPassword          string         `json:"obfs_password"`
	UpMbps                looseString    `json:"up_mbps"`
	DownMbps              looseString    `json:"down_mbps"`
	ServerName            string         `json:"server_name"`
	Sni                   string         `json:"sni"`
	Alpn                  looseList      `json:"alpn"`
	IgnoreClientBandwidth looseBool      `json:"ignore_client_bandwidth"`
	PaddingScheme         []string       `json:"padding_scheme"`
	// Hysteria2 port hopping specific fields. We keep them as RawMessage so
	// that the panel can store booleans, numbers or strings without breaking
	// JSON decoding, mirroring the loose handling in the PHP panel
	// implementation.
	PortHopEnableRaw json.RawMessage `json:"port_hop_enable"`
	PortHopPortsRaw  json.RawMessage `json:"port_hop_ports"`
	// TUIC specific fields
	CongestionControl string      `json:"congestion_control"`
	UDPRelayMode      string      `json:"udp_relay_mode"`
	ZeroRTTHandshake  looseString `json:"zero_rtt_handshake"` // "0" or "1" from SSPanel
	Heartbeat         looseString `json:"heartbeat"`

	EnableProxyProtocol looseBool `json:"enable_proxy_protocol"`
	// 请求带有其中任一请求头时才采信 X-Forwarded-For（套 CDN / 反代时由面板配置）
	TrustedXForwardedFor []string `json:"trusted_x_forwarded_for"`
	// VLESS Encryption 加密配置
	Decryption string `json:"decryption"`
}

// 面板可能把下列字段存成数字、布尔或字符串，按宽松口径解析，避免整份 custom_config 解析失败。
type looseString string

func (v *looseString) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		*v = looseString(s)
	} else if string(raw) != "null" {
		*v = looseString(raw)
	}
	return nil
}

type looseBool bool

func (v *looseBool) UnmarshalJSON(raw []byte) error {
	*v = looseBool(parseBoolLooseJSON(raw))
	return nil
}

// looseList 兼容字符串数组与逗号分隔的字符串
type looseList []string

func (v *looseList) UnmarshalJSON(raw []byte) error {
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		*v = list
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		*v = splitPortsExprString(s)
	}
	return nil
}

// UserResponse is the response of user
type UserResponse struct {
	TrafficIdentity string  `json:"traffic_identity"`
	ValidUntil      int64   `json:"valid_until"`
	KickVersion     uint64  `json:"kick_version"`
	ID              int     `json:"id"`
	ClientID        int     `json:"client_id"`
	Passwd          string  `json:"passwd"`
	Port            uint32  `json:"port"`
	Method          string  `json:"method"`
	SpeedLimit      float64 `json:"node_speedlimit"`
	DeviceLimit     int     `json:"node_connector"`
	UUID            string  `json:"uuid"`
}

// Response is the common response
type Response struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
}

// PostData is the data structure of post data
type PostData struct {
	Data interface{} `json:"data"`
}

// SystemLoad is the data structure of system load
type SystemLoad struct {
	Uptime string `json:"uptime"`
	Load   string `json:"load"`
}

// OnlineUser is the data structure of online user
type OnlineUser struct {
	UID      int    `json:"user_id"`
	IP       string `json:"ip,omitempty"`
	ClientID int    `json:"client_id,omitempty"`
}

type RuleItem struct {
	ID      int    `json:"id"`
	Content string `json:"regex"`
}

// RuleListResponse is the response of detect_rules API, including exempt_users
type RuleListResponse struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
	// ExemptUsers may be a JSON object (map) or an empty JSON array [] when no
	// exempt users are configured (PHP encodes empty associative arrays as []).
	// Use json.RawMessage and parse manually to handle both cases.
	ExemptUsers json.RawMessage `json:"exempt_users"`
}

type IllegalItem struct {
	ID  int    `json:"list_id"`
	UID int    `json:"user_id"`
	IP  string `json:"ip,omitempty"`
}

type REALITYConfig struct {
	Dest             string   `json:"dest,omitempty"`
	ProxyProtocolVer uint64   `json:"proxy_protocol_ver,omitempty"`
	ServerNames      []string `json:"server_names,omitempty"`
	PrivateKey       string   `json:"private_key,omitempty"`
	MinClientVer     string   `json:"min_client_ver,omitempty"`
	MaxClientVer     string   `json:"max_client_ver,omitempty"`
	MaxTimeDiff      uint64   `json:"max_time_diff,omitempty"`
	ShortIds         []string `json:"short_ids,omitempty"`
	Mldsa65Seed      string   `json:"mldsa65_seed,omitempty"`
}

// UnlockCheckResultPost is the data structure for posting unlock check result
type UnlockCheckResultPost struct {
	NodeID int    `json:"node_id"`
	Result string `json:"result"`
}
