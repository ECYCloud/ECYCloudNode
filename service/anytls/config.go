package anytls

import (
	"context"
	"fmt"
	"net/netip"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/ECYCloud/ECYCloudNode/common/mylego"
)

func (s *AnyTLSService) buildSingBox() (*box.Box, string, error) {
	listenIP := s.config.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(listenIP)
	if err != nil {
		return nil, "", fmt.Errorf("invalid ListenIP %s: %w", listenIP, err)
	}
	port := s.nodeInfo.Port
	if port == 0 || port > 65535 {
		return nil, "", fmt.Errorf("invalid port %d", port)
	}

	certFile, keyFile, err := getOrIssueCert(s.config.CertConfig)
	if err != nil {
		return nil, "", err
	}

	ctx := context.Background()
	ctx = box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())

	opts := option.Options{
		Log: &option.LogOptions{
			Level:     "warn",
			Timestamp: true,
		},
	}

	// sing-box 自 1.6.0 起移除了内建 Proxy Protocol 支持，节点开启该选项时，
	// AnyTLS inbound 自身只监听一个外部不可达的回环端口，真实端口改由
	// startProxyProtocolFrontend 监听、解析并剥离 PROXY 头后再注入连接。
	useProxyProtocol := s.nodeInfo.AcceptProxyProtocol
	listenAddr := addr
	listenPort := uint16(port)
	if useProxyProtocol {
		listenAddr = netip.MustParseAddr("127.0.0.1")
		listenPort = 0
	}
	listen := option.ListenOptions{
		Listen:     (*badoption.Addr)(&listenAddr),
		ListenPort: listenPort,
	}

	tlsOpt := &option.InboundTLSOptions{
		Enabled:         true,
		CertificatePath: certFile,
		KeyPath:         keyFile,
	}

	padding := []string{}
	if s.nodeInfo.AnyTLSConfig != nil && len(s.nodeInfo.AnyTLSConfig.PaddingScheme) > 0 {
		padding = s.nodeInfo.AnyTLSConfig.PaddingScheme
	}

	s.mu.Lock()
	users := make([]option.AnyTLSUser, len(s.authUsers))
	copy(users, s.authUsers)
	built := make(map[string]struct{}, len(users))
	for _, u := range users {
		built[u.Name] = struct{}{}
	}
	s.builtAuthUsers = built
	s.mu.Unlock()

	inOpts := &option.AnyTLSInboundOptions{
		ListenOptions: listen,
		Users:         users,
		PaddingScheme: padding,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: tlsOpt,
		},
	}

	opts.Inbounds = []option.Inbound{
		{
			Type:    "anytls",
			Tag:     s.inboundTag,
			Options: inOpts,
		},
	}
	opts.Outbounds = []option.Outbound{
		{
			Type:    "direct",
			Tag:     "direct",
			Options: &option.DirectOutboundOptions{},
		},
	}

	boxInstance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, "", err
	}

	tracker := &anyTLSTracker{svc: s}
	boxInstance.Router().AppendTracker(tracker)

	if useProxyProtocol {
		frontListener, err := s.startProxyProtocolFrontend(boxInstance, addr, uint16(port))
		if err != nil {
			boxInstance.Close()
			return nil, "", err
		}
		s.frontListener = frontListener
	} else {
		s.frontListener = nil
	}

	return boxInstance, s.inboundTag, nil
}

func getOrIssueCert(certConfig *mylego.CertConfig) (string, string, error) {
	if certConfig == nil {
		return "", "", fmt.Errorf("CertConfig is nil")
	}
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
		return lego.DNSCert()
	case "http", "tls":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		return lego.HTTPCert()
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}

// certMonitor checks and renews the AnyTLS certificate when needed. When a
// renewal actually happens (ok == true), the AnyTLS sing-box instance is
// hot-reloaded so the new certificate is picked up without restarting the
// whole ECYCloudNode process.
func (s *AnyTLSService) certMonitor() error {
	if s.config == nil || s.config.CertConfig == nil {
		return nil
	}

	current := s.currentNodeInfo()
	if current == nil || !current.EnableTLS {
		return nil
	}

	switch s.config.CertConfig.CertMode {
	case "dns", "http", "tls":
		lego, err := mylego.New(s.config.CertConfig)
		if err != nil {
			s.logger.Print(err)
			return nil
		}
		certPath, keyPath, ok, err := lego.RenewCert()
		if err != nil {
			s.logger.Print(err)
			return nil
		}
		if ok {
			s.logger.Infof("AnyTLS certificate renewed for %s, reloading node (cert=%s, key=%s)", s.config.CertConfig.CertDomain, certPath, keyPath)
			if err := s.reloadNode(current); err != nil {
				s.logger.Printf("AnyTLS certificate reload failed: %v", err)
			}
		}
	}

	return nil
}
