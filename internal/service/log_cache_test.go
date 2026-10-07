package service

import (
	"testing"
	"time"
)

func TestStatisticsRangeKeysPreservePrecisionAndInstant(t *testing.T) {
	first := time.Date(2026, 10, 7, 0, 0, 0, 100, time.UTC)
	second := first.Add(time.Nanosecond)
	if logRangeKey(&first) == logRangeKey(&second) {
		t.Fatal("different query boundaries share a cache key")
	}
	same := first.In(time.FixedZone("Asia/Shanghai", 8*3600))
	if logRangeKey(&first) != logRangeKey(&same) {
		t.Fatal("same instant differs across zones")
	}
	if logRangeKey(nil) == logRangeKey(&first) {
		t.Fatal("unbounded range collides")
	}
}
