package proxy

import (
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
	"github.com/fly12323/RWAF/internal/config"
)

func TestGETBodyIsBoundedAndRestored(t *testing.T) {
	for _, tc := range []struct {
		body  string
		limit int64
		fail  bool
	}{{"attack", 6, false}, {"attack", 5, true}} {
		r := httptest.NewRequest("GET", "/", strings.NewReader(tc.body))
		data, err := readRequestBody(httptest.NewRecorder(), r, tc.limit)
		if (err != nil) != tc.fail {
			t.Fatalf("limit=%d: %v", tc.limit, err)
		}
		if !tc.fail {
			forwarded, _ := io.ReadAll(r.Body)
			if string(data) != tc.body || string(forwarded) != tc.body {
				t.Fatal("GET body was not preserved")
			}
		}
	}
}

func TestProxyStreamsBeforeBackendCompletes(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("hello"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("done"))
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	port, _ := strconv.Atoi(u.Port())
	config.GlobalConfig = &config.Config{Proxy: config.ProxyConfig{ConnectTimeout: 1, ReadTimeout: 1, IdleTimeout: 1, MaxIdleConns: 10, MaxIdleConnsPerHost: 2}}
	p := NewReverseProxy(1, []Target{{Host: u.Hostname(), Port: port, Weight: 1}}, "round_robin", nil)
	defer p.Close()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/", func(c *gin.Context) { p.forward(c, "test", "127.0.0.1", time.Now(), nil, nil) })
	front := httptest.NewServer(router)
	defer front.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatal("response buffered until backend completed", err)
	}
	if string(buf) != "hello" {
		t.Fatal(string(buf))
	}
}
