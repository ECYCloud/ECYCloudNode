// Package controller Package generate the InboundConfig used by add inbound
package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/ECYCloud/ECYCloudNode/api"
	"github.com/ECYCloud/ECYCloudNode/common/mylego"
)

// InboundBuilder build Inbound config for different protocol
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	// Build Listen IP address
	if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}

	// Build Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: nodeInfo.Port, To: nodeInfo.Port}},
	}
	inboundDetourConfig.PortList = portList
	// Build Tag
	inboundDetourConfig.Tag = tag
	// SniffingConfig
	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls", "quic", "fakedns"},
	}
	if config.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	// Build Protocol and Protocol setting
	switch nodeInfo.NodeType {
	case "Vmess", "VLESS":
		// 协议的选择完全由 NodeType 决定：
		//   - "VLESS"  => VLESS inbound
		//   - "Vmess"  => VMess inbound
		if nodeInfo.NodeType == "VLESS" {
			protocol = "vless"
			// VLESS decryption：优先使用面板配置，未配置时默认 "none"
			vlessDecryption := "none"
			if nodeInfo.VlessDecryption != "" {
				vlessDecryption = nodeInfo.VlessDecryption
			}
			// Enable fallback
			if config.EnableFallback {
				fallbackConfigs, err := buildVlessFallbacks(config.FallBackConfigs)
				if err == nil {
					proxySetting = &conf.VLessInboundConfig{
						Decryption: vlessDecryption,
						Fallbacks:  fallbackConfigs,
					}
				} else {
					return nil, err
				}
			} else {
				proxySetting = &conf.VLessInboundConfig{
					Decryption: vlessDecryption,
				}
			}
		} else {
			protocol = "vmess"
			proxySetting = &conf.VMessInboundConfig{}
		}
	case "Trojan":
		protocol = "trojan"
		// Enable fallback
		if config.EnableFallback {
			fallbackConfigs, err := buildTrojanFallbacks(config.FallBackConfigs)
			if err == nil {
				proxySetting = &conf.TrojanServerConfig{
					Fallbacks: fallbackConfigs,
				}
			} else {
				return nil, err
			}
		} else {
			proxySetting = &conf.TrojanServerConfig{}
		}
	case "Shadowsocks":
		protocol = "shadowsocks"
		cipher := strings.ToLower(nodeInfo.CypherMethod)

		proxySetting = &conf.ShadowsocksServerConfig{
			Cipher:   cipher,
			Password: nodeInfo.ServerKey, // shadowsocks2022 shareKey
		}

		proxySetting, _ := proxySetting.(*conf.ShadowsocksServerConfig)
		// shadowsocks must have a random password
		// shadowsocks2022's password == user PSK, thus should a length of string >= 32 and base64 encoder
		b := make([]byte, 32)
		rand.Read(b)
		randPasswd := hex.EncodeToString(b)
		if C.Contains(shadowaead_2022.List, cipher) {
			proxySetting.Users = append(proxySetting.Users, &conf.ShadowsocksUserConfig{
				Password: base64.StdEncoding.EncodeToString(b),
			})
		} else {
			proxySetting.Password = randPasswd
		}

		proxySetting.NetworkList = &conf.NetworkList{"tcp", "udp"}

	default:
		return nil, fmt.Errorf("unsupported node type: %s, Only support: Vmess, VLESS, Trojan, and Shadowsocks", nodeInfo.NodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", nodeInfo.NodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting

	// Build streamSettings
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.TransportProtocol)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}

	switch networkType {
	case "tcp":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
			HeaderConfig:        nodeInfo.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "mkcp":
		// xray 已移除 mKCP 的伪装头与 seed，两者只要非空就会构建失败。
		// 这里照原样下发，让内核报出移除原因，而不是起一个客户端连不上的 inbound。
		kcpSetting := &conf.KCPConfig{
			HeaderConfig: nodeInfo.Header,
		}
		if nodeInfo.Seed != "" {
			kcpSetting.Seed = &nodeInfo.Seed
		}
		streamSetting.KCPSettings = kcpSetting
	case "websocket":
		headers := make(map[string]string)
		headers["Host"] = nodeInfo.Host
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
			Host:                nodeInfo.Host,
			Path:                nodeInfo.Path,
			Headers:             headers,
		}
		streamSetting.WSSettings = wsSettings
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
		}
		streamSetting.GRPCSettings = grpcSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
			Headers:             nodeInfo.Headers,
			Path:                nodeInfo.Path,
			Host:                nodeInfo.Host,
			AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings
	case "splithttp", "xhttp":
		splithttpSetting := &conf.SplitHTTPConfig{
			Path: nodeInfo.Path,
			Host: nodeInfo.Host,
		}
		streamSetting.SplitHTTPSettings = splithttpSetting
	}
	streamSetting.Network = &transportProtocol

	// Build TLS and REALITY settings
	var isREALITY bool
	// 现在的逻辑：**只使用 SSPanel 下发的 Reality 配置，不再从 config.yml 中回退任何公钥/私钥/short_id**
	if nodeInfo.REALITYConfig != nil && nodeInfo.EnableREALITY {
		r := nodeInfo.REALITYConfig
		// 服务端必需字段：Dest 与 PrivateKey 必须由面板提供
		if r.Dest != "" && r.PrivateKey != "" {
			isREALITY = true
			streamSetting.Security = "reality"
			streamSetting.REALITYSettings = &conf.REALITYConfig{
				Show:         true,
				Dest:         []byte(`"` + r.Dest + `"`),
				Xver:         r.ProxyProtocolVer,
				ServerNames:  r.ServerNames,
				PrivateKey:   r.PrivateKey,
				MinClientVer: r.MinClientVer,
				MaxClientVer: r.MaxClientVer,
				MaxTimeDiff:  r.MaxTimeDiff,
				ShortIds:     r.ShortIds,
				Mldsa65Seed:  r.Mldsa65Seed,
			}
		}
	}

	// Only build TLS settings when TLS is enabled, REALITY is not used, and
	// a non-nil certificate configuration is available. Older configs might
	// omit CertConfig entirely, in which case we should gracefully skip TLS
	// here instead of panicking on a nil pointer.
	if !isREALITY && nodeInfo.EnableTLS && config.CertConfig != nil && config.CertConfig.CertMode != "none" {
		streamSetting.Security = "tls"
		certFile, keyFile, err := getCertFile(config.CertConfig)
		if err != nil {
			return nil, err
		}
		tlsSettings := &conf.TLSConfig{
			RejectUnknownSNI: config.CertConfig.RejectUnknownSni,
		}
		tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})
		streamSetting.TLSSettings = tlsSettings
	}

	// Support ProxyProtocol for any transport protocol (per-node)
	if networkType != "tcp" && networkType != "ws" && nodeInfo.AcceptProxyProtocol {
		sockoptConfig := &conf.SocketConfig{
			AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
		}
		streamSetting.SocketSettings = sockoptConfig
	}
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func getCertFile(certConfig *mylego.CertConfig) (certFile string, keyFile string, err error) {
	switch certConfig.CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("cert file path or key file path not exist")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "dns":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.DNSCert()
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.HTTPCert()
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}

func buildVlessFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	vlessFallBacks := make([]*conf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		vlessFallBacks[i] = &conf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*conf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		trojanFallBacks[i] = &conf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}
