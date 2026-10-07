package weakpassword

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"github.com/fly12323/RWAF/pkg/password"
)

func TestRepresentationsAndPreciseFields(t *testing.T) {
	c := DefaultConfig()
	c.Endpoints[0].PasswordFields = []string{"data.password"}
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ticket := e.Match(httptest.NewRequest("POST", "http://example.com/login", nil))
	if ticket == nil {
		t.Fatal("endpoint missed")
	}
	for _, format := range password.Formats {
		t.Run(format, func(t *testing.T) {
			c.Representations = []string{format}
			single, _ := New(c)
			ticket := single.Match(httptest.NewRequest("POST", "http://example.com/login", nil))
			value := password.Encode("123456", format)
			if format == "md5" || format == "sha1" || format == "sha256" {
				value = strings.ToUpper(value)
			}
			body, _ := json.Marshal(map[string]any{"data": map[string]string{"password": value}})
			event, err := single.detect(job{ticket: ticket, body: body, contentType: "application/json", id: "test", created: time.Now()})
			if err != nil || event == nil || event.Representation != format || event.Outcome != "unknown" {
				t.Fatalf("format %s: event=%+v error=%v", format, event, err)
			}
			encoded, _ := json.Marshal(event)
			if strings.Contains(string(encoded), value) {
				t.Fatal("password leaked in event")
			}
		})
	}
	for _, body := range []string{`{"data":{"password":"strong unique passphrase"},"note":"123456"}`, `{"data":{"password":"x123456x"}}`} {
		event, err := e.detect(job{ticket: ticket, body: []byte(body), contentType: "application/json"})
		if err != nil || event != nil {
			t.Fatalf("non-password substring produced match: %v %v", event, err)
		}
	}
	if _, err := e.detect(job{ticket: ticket, body: []byte(`{"password":"123456"}`), contentType: "application/json"}); err == nil {
		t.Fatal("missing configured field not accounted")
	}
	if _, err := e.detect(job{ticket: ticket, body: []byte(`{"data":`), contentType: "application/json"}); err == nil {
		t.Fatal("malformed JSON not accounted")
	}
}
func TestEndpointGatingAndForm(t *testing.T) {
	c := DefaultConfig()
	c.Endpoints[0].Host = "example.com"
	c.Endpoints[0].Path = "/api/login*"
	c.Endpoints[0].PasswordFields = []string{"pwd"}
	e, _ := New(c)
	for _, req := range []*http.Request{httptest.NewRequest("GET", "http://example.com/api/login", nil), httptest.NewRequest("POST", "http://other.com/api/login", nil), httptest.NewRequest("POST", "http://example.com/products", nil)} {
		if e.Match(req) != nil {
			t.Fatal("unrelated request matched")
		}
	}
	ticket := e.Match(httptest.NewRequest("POST", "http://EXAMPLE.com:9000/api/login/v1", nil))
	if ticket == nil {
		t.Fatal("host/prefix matching failed")
	}
	event, err := e.detect(job{ticket: ticket, contentType: "application/x-www-form-urlencoded; charset=utf-8", body: []byte("pwd=cGFzc3dvcmQ%3D"), id: "form", created: time.Now()})
	if err != nil || event == nil || event.Representation != "base64" {
		t.Fatalf("form base64: %v %v", event, err)
	}
	if _, err := e.detect(job{ticket: ticket, contentType: "multipart/form-data", body: []byte("pwd=123456")}); err == nil {
		t.Fatal("multipart should be skipped")
	}
}
func TestBoundedQueueAndDisabled(t *testing.T) {
	e, _ := New(DefaultConfig())
	old := active.Swap(e)
	defer active.Store(old)
	ticket := e.Match(httptest.NewRequest("POST", "http://example.com/login", nil))
	body := []byte(`{"password":"123456"}`)
	Submit(ticket, body, "application/json", "copy", "", 1, time.Now())
	body[0] = '!'
	j := <-e.queue
	if j.body[0] != '{' {
		t.Fatal("queued body aliases caller")
	}
	clear(j.body)
	for i := 0; i < cap(e.queue); i++ {
		Submit(ticket, []byte(`{}`), "application/json", "", "", 1, time.Now())
	}
	start := time.Now()
	Submit(ticket, body, "application/json", "full", "", 1, time.Now())
	if e.dropped.Load() != 1 || time.Since(start) > 100*time.Millisecond {
		t.Fatal("full queue blocked forwarding")
	}
	Submit(ticket, make([]byte, MaxBody+1), "application/json", "oversize", "", 1, time.Now())
	if e.skipped.Load() != 1 {
		t.Fatal("size limit not counted")
	}
	c := DefaultConfig()
	c.Enabled = false
	off, _ := compile(c)
	e.state.Store(off)
	t2 := e.Match(httptest.NewRequest("POST", "http://example.com/login", nil))
	if t2 == nil {
		t.Fatal("disabled detection must still identify sensitive logs")
	}
	before := e.accepted.Load()
	Submit(t2, body, "application/json", "off", "", 1, time.Now())
	if e.accepted.Load() != before {
		t.Fatal("disabled detector accepted job")
	}
}
func BenchmarkEndpointMiss(b *testing.B) {
	e, _ := New(DefaultConfig())
	r := httptest.NewRequest("GET", "http://example.com/products", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Match(r)
	}
}
func BenchmarkMatchedMD5(b *testing.B) {
	e, _ := New(DefaultConfig())
	ticket := e.Match(httptest.NewRequest("POST", "http://example.com/login", nil))
	j := job{ticket: ticket, contentType: "application/json", body: []byte(`{"password":"e10adc3949ba59abbe56e057f20f883e"}`)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.detect(j)
	}
}
