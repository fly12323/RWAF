package middleware

import (
	"context"
	"github.com/fly12323/RWAF/pkg/telemetry"
	"github.com/gin-gonic/gin"
	"time"
)

func LogQueryMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != "GET" {
			c.Next()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		start := time.Now()
		defer func() {
			canceled := ctx.Err() == context.Canceled
			failed := !canceled && (ctx.Err() == context.DeadlineExceeded || c.Writer.Status() >= 500 || c.GetInt("response_code") >= 500)
			telemetry.Logs.ObserveResult(time.Since(start), failed, canceled)
		}()
		c.Next()
	}
}
