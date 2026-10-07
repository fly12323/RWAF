package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/fly12323/RWAF/internal/ser/protection"
	"github.com/fly12323/RWAF/internal/service"
	"github.com/fly12323/RWAF/pkg/events"
	"github.com/fly12323/RWAF/pkg/proxy"
)

func testCertificate(t *testing.T, names []string, serial int64) (string, string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), cert
}

func TestHTTPSDomainsStatisticsAndRetention(t *testing.T) {
	if os.Getenv("WAF_INTEGRATION") != "1" {
		t.Skip("requires isolated integration stack")
	}
	for k, v := range map[string]string{"DB_HOST": "127.0.0.1", "DB_PORT": "15432", "DB_USER": "waf_test", "DB_PASSWORD": "waf-test-only", "DB_NAME": "waf_test", "REDIS_HOST": "127.0.0.1", "REDIS_PORT": "16379", "REDIS_PASSWORD": "", "KAFKA_BROKERS": "127.0.0.1:29094"} {
		t.Setenv(k, v)
	}
	if err := config.LoadConfig("../../configs/config.yaml"); err != nil {
		t.Fatal(err)
	}
	config.GetConfig().Proxy.TLSKeyFile = filepath.Join(t.TempDir(), "master.key")
	if err := dao.InitDB(); err != nil {
		t.Fatal(err)
	}
	defer dao.CloseDB()
	if err := dao.InitRedis(); err != nil {
		t.Fatal(err)
	}
	defer dao.CloseRedis()
	policy := model.DefaultProtectionConfig("monitor", 15)
	policy.Enabled = false
	if err := protection.SaveConfig(&policy); err != nil {
		t.Fatal(err)
	}
	manager := proxy.NewProxyManager(nil)
	defer manager.StopAll()
	service.SetProxyManager(manager)
	defer service.SetProxyManager(nil)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.Host) }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	backendPort, _ := strconv.Atoi(u.Port())
	targets := []proxy.Target{{Host: u.Hostname(), Port: backendPort, Weight: 1}}
	port := freePort(t)
	svc := service.NewSiteService()
	certPEM, keyPEM, cert := testCertificate(t, []string{"alpha.test", "beta.test"}, 1)
	sites := []*model.Site{}
	for _, name := range []string{"alpha.test", "beta.test"} {
		site, err := svc.CreateSite(&service.CreateSiteRequest{Name: name, Domains: []string{name}, ListenPort: port, UpstreamTargets: targets, LoadBalanceStrategy: "round_robin", TLSEnabled: true, TLSCertificate: certPEM, TLSPrivateKey: keyPEM})
		if err != nil {
			t.Fatal(err)
		}
		sites = append(sites, site)
		defer svc.DeleteSite(site.ID)
		encoded, _ := json.Marshal(site)
		if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), "tls_private_key") || strings.Contains(site.TLSPrivateKey, "PRIVATE KEY") {
			t.Fatal("private key exposed")
		}
	}
	if _, err := svc.CreateSite(&service.CreateSiteRequest{Name: "conflict", Domains: []string{"ALPHA.TEST."}, ListenPort: port, UpstreamTargets: targets, TLSEnabled: true, TLSCertificate: certPEM, TLSPrivateKey: keyPEM}); err == nil {
		t.Fatal("duplicate domain accepted")
	}
	if _, err := svc.CreateSite(&service.CreateSiteRequest{Name: "mixed", Domains: []string{"gamma.test"}, ListenPort: port, UpstreamTargets: targets}); err == nil {
		t.Fatal("mixed protocol accepted")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	makeClient := func(sni string) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", port))
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	for _, name := range []string{"alpha.test", "beta.test"} {
		resp, err := makeClient(name).Get(fmt.Sprintf("https://%s:%d/", name, port))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.HasPrefix(string(body), name) {
			t.Fatalf("routing %s: %d %s", name, resp.StatusCode, body)
		}
	}
	resp, err := makeClient("alpha.test").Get(fmt.Sprintf("https://beta.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 421 {
		t.Fatal("domain fronting allowed", resp.StatusCode)
	}
	if _, err := makeClient("unknown.test").Get(fmt.Sprintf("https://unknown.test:%d/", port)); err == nil {
		t.Fatal("unknown SNI accepted")
	}
	newCert, newKey, newRoot := testCertificate(t, []string{"alpha.test"}, 2)
	roots.AddCert(newRoot)
	if _, err := svc.UpdateSite(sites[0].ID, &service.UpdateSiteRequest{TLSCertificate: &newCert, TLSPrivateKey: newKey}); err != nil {
		t.Fatal(err)
	}
	resp, err = makeClient("alpha.test").Get(fmt.Sprintf("https://alpha.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.TLS.PeerCertificates[0].SerialNumber.Int64() != 2 {
		t.Fatal("certificate did not rotate")
	}
	// A failed replacement must preserve both the database row and active certificate.
	if _, err := svc.UpdateSite(sites[0].ID, &service.UpdateSiteRequest{TLSCertificate: &certPEM, TLSPrivateKey: newKey}); err == nil {
		t.Fatal("mismatched key accepted")
	}
	stored, err := svc.GetSiteByID(sites[0].ID)
	if err != nil || stored.TLSCertificate != newCert {
		t.Fatal("failed update changed stored certificate", err)
	}
	if err := svc.ToggleSiteStatus(sites[0].ID, false); err != nil {
		t.Fatal(err)
	}
	resp, err = makeClient("beta.test").Get(fmt.Sprintf("https://beta.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("disabling sibling closed shared port")
	}
	if err := svc.ToggleSiteStatus(sites[0].ID, true); err != nil {
		t.Fatal(err)
	}
	// Plain HTTP shares a port by Host and returns 404 for unmatched domains.
	httpPort := freePort(t)
	for _, name := range []string{"one.test", "two.test"} {
		site, err := svc.CreateSite(&service.CreateSiteRequest{Name: name, Domains: []string{name}, ListenPort: httpPort, UpstreamTargets: targets})
		if err != nil {
			t.Fatal(err)
		}
		defer svc.DeleteSite(site.ID)
	}
	for _, name := range []string{"ONE.TEST.", "two.test", "unknown.test"} {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
		req.Host = name
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := 200
		if name == "unknown.test" {
			want = 404
		}
		if resp.StatusCode != want {
			t.Fatalf("HTTP domain %s got %d", name, resp.StatusCode)
		}
	}
	testLogAggregationAndRetention(t)
}

func testLogAggregationAndRetention(t *testing.T) {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	id := fmt.Sprintf("query-%d", now.UnixNano())
	logs := []events.Event{
		events.RequestEvent(&model.RequestLog{RequestID: id + "-1", SiteID: 900001, CreatedAt: now, Action: "block", RiskScore: 10, Duration: 20, AttackType: "SQL Injection", ClientIP: "192.0.2.8"}, []model.RuleMatch{{RuleID: "test-rule"}}),
		events.RequestEvent(&model.RequestLog{RequestID: id + "-2", SiteID: 900001, CreatedAt: now, Action: "pass", RiskScore: 0, Duration: 10}, nil),
	}
	if err := events.PersistBatch(context.Background(), dao.GetDB(), logs); err != nil {
		t.Fatal(err)
	}
	svc := service.NewLogService()
	stats, err := svc.GetStatistics(&start, &end)
	if err != nil || stats.Total < 2 {
		t.Fatal("statistics", stats, err)
	}
	stats.Total = 0
	stats, err = svc.GetStatistics(&start, &end)
	if err != nil || stats.Total < 2 {
		t.Fatal("cache mutation", err)
	}
	daily, err := svc.GetDailyStatistics(3)
	if err != nil || len(daily) != 3 || daily[2].Total < 2 {
		t.Fatal("daily", daily, err)
	}
	trend, err := svc.GetTrend(&start, &end)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, row := range trend {
		total += row.Total
	}
	if total < 2 {
		t.Fatal("trend lost boundary events")
	}
	old := events.RequestEvent(&model.RequestLog{RequestID: id + "-old", CreatedAt: now.AddDate(0, 0, -60), Action: "block"}, []model.RuleMatch{{RuleID: "old-rule"}})
	if err := events.PersistBatch(context.Background(), dao.GetDB(), []events.Event{old}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RunLogRetention(context.Background(), dao.GetDB(), now.AddDate(0, 0, -30), 1); err != nil {
		t.Fatal(err)
	}
	if err := events.PersistBatch(context.Background(), dao.GetDB(), []events.Event{old}); err != nil {
		t.Fatal(err)
	}
	var count int64
	dao.GetDB().Model(&model.RequestLog{}).Where("request_id = ?", old.Request.RequestID).Count(&count)
	if count != 0 {
		t.Fatal("replay resurrected retired log")
	}
	dao.GetDB().Model(&model.RuleMatch{}).Where("rule_id = ?", "old-rule").Count(&count)
	if count != 0 {
		t.Fatal("retention left orphan detail")
	}
	dao.GetDB().Model(&model.ProcessedEvent{}).Where("event_id = ?", old.ID).Count(&count)
	if count != 1 {
		t.Fatal("retention deleted replay receipt")
	}
}
