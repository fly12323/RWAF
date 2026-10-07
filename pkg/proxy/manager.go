package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/net/idna"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/certificates"
	"github.com/fly12323/RWAF/pkg/coraza"
)

type ProxyManager struct {
	proxies   map[uint]*ReverseProxy
	servers   map[int]*http.Server
	portSites map[int]map[uint]*siteRoute
	mu        sync.RWMutex
	wafEngine *coraza.WAFEngine
}

func NewProxyManager(engine *coraza.WAFEngine) *ProxyManager {
	return &ProxyManager{proxies: map[uint]*ReverseProxy{}, servers: map[int]*http.Server{}, portSites: map[int]map[uint]*siteRoute{}, wafEngine: engine}
}
func (m *ProxyManager) GetWAFEngine() *coraza.WAFEngine { return m.wafEngine }
func (m *ProxyManager) LoadSites() error {
	var sites []model.Site
	if err := dao.GetDB().Where("enabled = ?", true).Find(&sites).Error; err != nil {
		return err
	}
	desired := map[uint]bool{}
	for _, site := range sites {
		desired[site.ID] = true
		if err := m.UpdateSite(&site); err != nil {
			return err
		}
	}
	for _, id := range m.GetAllSites() {
		if !desired[id] {
			m.RemoveSite(id)
		}
	}
	return nil
}
func (m *ProxyManager) AddSite(site *model.Site) error { return m.UpdateSite(site) }

type siteRoute struct {
	id          uint
	domains     []string
	tlsEnabled  bool
	certificate *tls.Certificate
}

func NormalizeDomains(raw string) ([]string, error) {
	var values []string
	if raw != "" && raw != "null" {
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, fmt.Errorf("域名列表格式错误")
		}
	}
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		domain, err := normalizeHost(value)
		if err != nil {
			return nil, fmt.Errorf("无效域名 %q", value)
		}
		if seen[domain] {
			continue
		}
		seen[domain] = true
		result = append(result, domain)
	}
	if len(result) > 100 {
		return nil, fmt.Errorf("每个站点最多 100 个域名")
	}
	return result, nil
}
func normalizeHost(raw string) (string, error) {
	raw = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("invalid host")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", fmt.Errorf("invalid host character")
			}
		}
	}
	return ascii, nil
}
func requestHost(raw string) (string, error) {
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	return normalizeHost(raw)
}
func (m *ProxyManager) UpdateSite(site *model.Site) error {
	if !site.Enabled {
		m.RemoveSite(site.ID)
		return nil
	}
	if site.ListenPort < 1 || site.ListenPort > 65535 {
		return fmt.Errorf("无效的监听端口")
	}
	if site.ListenPort == config.GetConfig().Server.Port {
		return fmt.Errorf("站点端口不可与管理 API 相同")
	}
	domains, err := NormalizeDomains(site.Domains)
	if err != nil {
		return err
	}
	route := &siteRoute{id: site.ID, domains: domains, tlsEnabled: site.TLSEnabled}
	if site.TLSEnabled {
		route.certificate, err = certificates.ForSite(site, domains)
		if err != nil {
			return err
		}
	}
	var targets []Target
	if err := json.Unmarshal([]byte(site.UpstreamTargets), &targets); err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("站点至少需要一个后端")
	}
	for _, target := range targets {
		if target.Host == "" || target.Port < 1 || target.Port > 65535 || target.Weight < 0 {
			return fmt.Errorf("无效的后端配置")
		}
	}
	p := NewReverseProxy(site.ID, targets, site.LoadBalanceStrategy, m.wafEngine)
	m.mu.Lock()
	port := site.ListenPort
	for id, other := range m.portSites[port] {
		if id == site.ID {
			continue
		}
		if route.tlsEnabled != other.tlsEnabled {
			m.mu.Unlock()
			p.Close()
			return fmt.Errorf("同一端口的站点必须使用相同 HTTP/HTTPS 协议")
		}
		if len(route.domains) == 0 && len(other.domains) == 0 {
			m.mu.Unlock()
			p.Close()
			return fmt.Errorf("同一端口只能有一个未指定域名的默认站点")
		}
		for _, a := range domains {
			for _, b := range other.domains {
				if a == b {
					m.mu.Unlock()
					p.Close()
					return fmt.Errorf("域名 %s 已被站点 %d 使用", a, id)
				}
			}
		}
	}
	var newServer *http.Server
	var listener net.Listener
	if m.servers[port] == nil {
		listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			m.mu.Unlock()
			p.Close()
			return err
		}
		router := gin.New()
		router.Use(gin.Recovery())
		_ = router.SetTrustedProxies(nil)
		router.NoRoute(func(c *gin.Context) { m.handleRequest(c, port) })
		newServer = &http.Server{Addr: listener.Addr().String(), Handler: router, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Duration(config.GetConfig().Server.ReadTimeout) * time.Second, IdleTimeout: time.Duration(config.GetConfig().Proxy.IdleTimeout) * time.Second, MaxHeaderBytes: 65536}
		m.servers[port] = newServer
	}
	oldProxy := m.proxies[site.ID]
	var oldServers []*http.Server
	for oldPort, routes := range m.portSites {
		if oldPort == port {
			continue
		}
		delete(routes, site.ID)
		if len(routes) == 0 {
			oldServers = append(oldServers, m.servers[oldPort])
			delete(m.servers, oldPort)
			delete(m.portSites, oldPort)
		}
	}
	m.proxies[site.ID] = p
	if m.portSites[port] == nil {
		m.portSites[port] = map[uint]*siteRoute{}
	}
	m.portSites[port][site.ID] = route
	m.mu.Unlock()
	if newServer != nil {
		go func() {
			if err := newServer.Serve(&siteListener{Listener: listener, manager: m, port: port}); err != nil && err != http.ErrServerClosed {
				log.Printf("site listener failed: %v", err)
			}
		}()
	}
	if oldProxy != nil {
		oldProxy.Close()
	}
	for _, server := range oldServers {
		shutdownServer(server)
	}
	return nil
}
func (m *ProxyManager) routeLocked(port int, host string) *siteRoute {
	var fallback *siteRoute
	for _, route := range m.portSites[port] {
		if len(route.domains) == 0 {
			fallback = route
		}
		for _, domain := range route.domains {
			if domain == host {
				return route
			}
		}
	}
	return fallback
}
func (m *ProxyManager) handleRequest(c *gin.Context, port int) {
	host, err := requestHost(c.Request.Host)
	if err != nil {
		c.AbortWithStatus(400)
		return
	}
	m.mu.RLock()
	route := m.routeLocked(port, host)
	if route == nil {
		m.mu.RUnlock()
		c.AbortWithStatus(404)
		return
	}
	p := m.proxies[route.id]
	mismatch := route.tlsEnabled != (c.Request.TLS != nil)
	if c.Request.TLS != nil {
		sni, _ := normalizeHost(c.Request.TLS.ServerName)
		tlsRoute := m.routeLocked(port, sni)
		mismatch = mismatch || tlsRoute == nil || tlsRoute.id != route.id
	}
	m.mu.RUnlock()
	if mismatch {
		c.Header("Connection", "close")
		c.AbortWithStatus(421)
		return
	}
	if p == nil {
		c.AbortWithStatus(404)
		return
	}
	p.Handler()(c)
}

// Snapshot protocol on accept; resolve SNI certificates during handshake.
type siteListener struct {
	net.Listener
	manager *ProxyManager
	port    int
}

func (l *siteListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.manager.mu.RLock()
	secure := false
	for _, route := range l.manager.portSites[l.port] {
		secure = route.tlsEnabled
		break
	}
	l.manager.mu.RUnlock()
	if !secure {
		return conn, nil
	}
	return tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host, err := normalizeHost(hello.ServerName)
		if err != nil {
			return nil, fmt.Errorf("missing or invalid SNI")
		}
		l.manager.mu.RLock()
		defer l.manager.mu.RUnlock()
		route := l.manager.routeLocked(l.port, host)
		if route == nil || !route.tlsEnabled || route.certificate == nil {
			return nil, fmt.Errorf("unknown TLS domain")
		}
		if time.Now().Before(route.certificate.Leaf.NotBefore) || !time.Now().Before(route.certificate.Leaf.NotAfter) {
			return nil, fmt.Errorf("TLS certificate is outside validity period")
		}
		return route.certificate, nil
	}}), nil
}
func shutdownServer(server *http.Server) {
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
	}
}
func (m *ProxyManager) RemoveSite(id uint) {
	m.mu.Lock()
	p := m.proxies[id]
	delete(m.proxies, id)
	var servers []*http.Server
	for port, routes := range m.portSites {
		delete(routes, id)
		if len(routes) == 0 {
			servers = append(servers, m.servers[port])
			delete(m.servers, port)
			delete(m.portSites, port)
		}
	}
	m.mu.Unlock()
	for _, server := range servers {
		shutdownServer(server)
	}
	if p != nil {
		p.Close()
	}
}
func (m *ProxyManager) GetAllSites() []uint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]uint, 0, len(m.proxies))
	for id := range m.proxies {
		ids = append(ids, id)
	}
	return ids
}
func (m *ProxyManager) GetListeningPorts() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ports := make([]int, 0, len(m.servers))
	for port := range m.servers {
		ports = append(ports, port)
	}
	return ports
}
func (m *ProxyManager) StopAll() {
	for _, id := range m.GetAllSites() {
		m.RemoveSite(id)
	}
}
