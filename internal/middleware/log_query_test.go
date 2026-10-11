package middleware

import (
	"context"
	"github.com/fly12323/RWAF/pkg/response"
	"github.com/fly12323/RWAF/pkg/telemetry"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
)

func TestLogMetricsDetectHTTP200ErrorEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	telemetry.Logs.Sample()
	r := gin.New()
	r.Use(LogQueryMetrics())
	r.GET("/logs", func(c *gin.Context) {
		if _, ok := c.Request.Context().Deadline(); !ok {
			t.Error("missing query deadline")
		}
		response.Fail(c, 500, "database unavailable")
	})
	r.POST("/logs", func(c *gin.Context) { response.Success(c, nil) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/logs", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	s := telemetry.Logs.Sample()
	if s.Count != 1 || s.Errors != 1 {
		t.Fatal(s)
	}
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/logs", nil))
	if s := telemetry.Logs.Sample(); s.Count != 0 {
		t.Fatal("counted writes", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/logs", nil).WithContext(ctx))
	if s := telemetry.Logs.Sample(); s.Errors != 0 || s.Canceled != 1 || s.Count != 1 {
		t.Fatal("client cancellation became a server error", s)
	}
}
