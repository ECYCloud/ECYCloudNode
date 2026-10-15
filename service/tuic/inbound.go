package tuic

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	protocol "github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type deviceInbound struct {
	inbound.Adapter
	listener *listener.Listener
	tls      tls.ServerConfig
	router   adapter.ConnectionRouterEx
	settings protocol.ServiceOptions
	server   *protocol.Service[string]
	pending  *protocol.Service[string]
	started  bool
	mu       sync.RWMutex
	current  *userListener
	closed   bool
}

type userListener struct {
	connections chan *quic.Conn
	done        chan struct{}
	once        sync.Once
	addr        net.Addr
}

func (l *userListener) Accept(ctx context.Context) (*quic.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *userListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *userListener) Addr() net.Addr { return l.addr }

type dispatchListener struct {
	qtls.Listener
	inbound *deviceInbound
}

func (l *dispatchListener) Accept(ctx context.Context) (*quic.Conn, error) {
	for {
		conn, err := l.Listener.Accept(ctx)
		if err != nil {
			return nil, err
		}
		l.inbound.mu.RLock()
		if l.inbound.closed {
			l.inbound.mu.RUnlock()
			conn.CloseWithError(0, "")
			return nil, net.ErrClosed
		}
		select {
		case l.inbound.current.connections <- conn:
		case <-ctx.Done():
			conn.CloseWithError(0, "")
		}
		l.inbound.mu.RUnlock()
	}
}

type snapshotTLS struct {
	tls.ServerConfig
	listen func(net.PacketConn, *quic.Config, bool) (qtls.Listener, error)
}

func (c *snapshotTLS) Listen(conn net.PacketConn, config *quic.Config) (qtls.Listener, error) {
	return c.listen(conn, config, false)
}
func (c *snapshotTLS) ListenEarly(conn net.PacketConn, config *quic.Config) (qtls.EarlyListener, error) {
	return c.listen(conn, config, true)
}
func (c *snapshotTLS) ConfigureHTTP3() {}

func newDeviceInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICInboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, *options.TLS)
	if err != nil {
		return nil, err
	}
	h := &deviceInbound{Adapter: inbound.NewAdapter("tuic", tag), tls: tlsConfig, router: uot.NewRouter(router, logger)}
	h.listener = listener.New(listener.Options{Context: ctx, Logger: logger, Listen: options.ListenOptions})
	udpTimeout := time.Duration(options.UDPTimeout)
	if udpTimeout == 0 {
		udpTimeout = C.UDPTimeout
	}
	h.settings = protocol.ServiceOptions{Context: ctx, Logger: logger, TLSConfig: tlsConfig,
		QUICOptions:       qtls.QUICOptions{IdleTimeout: options.IdleTimeout.Build(), KeepAlivePeriod: options.KeepAlivePeriod.Build(), StreamReceiveWindow: options.StreamReceiveWindow.Value(), ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(), MaxConcurrentStreams: options.MaxConcurrentStreams, InitialPacketSize: options.InitialPacketSize, DisablePathMTUDiscovery: options.DisablePathMTUDiscovery},
		CongestionControl: options.CongestionControl, AuthTimeout: time.Duration(options.AuthTimeout), ZeroRTTHandshake: options.ZeroRTTHandshake, Heartbeat: time.Duration(options.Heartbeat), UDPTimeout: udpTimeout, Handler: h}
	if err := h.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	settings := h.settings
	settings.TLSConfig = &snapshotTLS{ServerConfig: tlsConfig, listen: func(conn net.PacketConn, config *quic.Config, early bool) (qtls.Listener, error) {
		var actual qtls.Listener
		var err error
		if early {
			actual, err = qtls.ListenEarly(conn, tlsConfig, config)
		} else {
			actual, err = qtls.Listen(conn, tlsConfig, config)
		}
		if err != nil {
			return nil, err
		}
		return &dispatchListener{Listener: actual, inbound: h}, nil
	}}
	h.server, err = protocol.NewService[string](settings)
	if err != nil {
		h.current.Close()
		return nil, err
	}
	return h, nil
}

func (h *deviceInbound) UpdateUsers(users []option.TUICUser) error {
	names := make([]string, len(users))
	ids := make([][16]byte, len(users))
	passwords := make([]string, len(users))
	for i, user := range users {
		id, err := uuid.FromString(user.UUID)
		if err != nil {
			return err
		}
		names[i], ids[i], passwords[i] = user.Name, id, user.Password
	}
	acceptor := &userListener{connections: make(chan *quic.Conn), done: make(chan struct{}), addr: h.listener.UDPAddr()}
	settings := h.settings
	settings.TLSConfig = &snapshotTLS{ServerConfig: h.tls, listen: func(net.PacketConn, *quic.Config, bool) (qtls.Listener, error) { return acceptor, nil }}
	next, err := protocol.NewService[string](settings)
	if err != nil {
		return err
	}
	next.UpdateUsers(names, ids, passwords)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	if h.started {
		if err := next.Start(nil); err != nil {
			return err
		}
	} else {
		h.pending = next
	}
	previous := h.current
	h.current = acceptor
	if previous != nil {
		previous.Close()
	}
	return nil
}

func (h *deviceInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error {
			h.mu.Lock()
			h.closed = true
			h.current.Close()
			h.mu.Unlock()
			return nil
		})
	}
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.tls.Start(); err != nil {
		return err
	}
	scope.Add(h.tls.Close)
	packets, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	h.mu.Lock()
	err = h.pending.Start(nil)
	if err == nil {
		h.pending = nil
		h.started = true
	}
	h.mu.Unlock()
	if err != nil {
		return err
	}
	if err := h.server.Start(packets); err != nil {
		return err
	}
	scope.Add(h.server.Close)
	return nil
}

func (h *deviceInbound) metadata(ctx context.Context, source, destination M.Socksaddr) adapter.InboundContext {
	user, _ := auth.UserFromContext[string](ctx)
	return adapter.InboundContext{Inbound: h.Tag(), InboundType: h.Type(), InboundDetour: h.listener.ListenOptions().Detour, OriginDestination: h.listener.UDPAddr(), Source: source, Destination: destination, User: user}
}

func (h *deviceInbound) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.router.RouteConnectionEx(ctx, conn, h.metadata(ctx, source, destination), onClose)
}

func (h *deviceInbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.router.RoutePacketConnectionEx(ctx, conn, h.metadata(ctx, source, destination), onClose)
}

func (s *TuicService) updateInboundUsers() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if s.closed || s.box == nil {
		return nil
	}
	h, ok := s.box.Inbound().Get(s.inboundTag)
	if !ok {
		return nil
	}
	s.mu.RLock()
	users := append([]option.TUICUser(nil), s.authUsers...)
	s.mu.RUnlock()
	if err := h.(*deviceInbound).UpdateUsers(users); err != nil {
		return err
	}
	s.recordBuiltUsers(users)
	return nil
}

func (s *TuicService) recordBuiltUsers(users []option.TUICUser) {
	built := make(map[string]struct{}, len(users))
	for _, user := range users {
		built[user.Name] = struct{}{}
	}
	s.mu.Lock()
	s.builtAuthUsers = built
	s.mu.Unlock()
}
