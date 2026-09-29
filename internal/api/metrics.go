package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Границы гистограммы задержки скоринга, микросекунды.
var latBounds = [...]int64{25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 50000}

type latencyHist struct {
	buckets [len(latBounds) + 1]atomic.Uint64
	sumUS   atomic.Uint64
	count   atomic.Uint64
}

func (h *latencyHist) observe(d time.Duration) {
	us := d.Microseconds()
	i := 0
	for i < len(latBounds) && us > latBounds[i] {
		i++
	}
	h.buckets[i].Add(1)
	h.sumUS.Add(uint64(us))
	h.count.Add(1)
}

// handleMetrics отдаёт метрики в текстовом формате Prometheus.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var b strings.Builder
	m := &s.Engine.Metrics
	fmt.Fprintf(&b, "# TYPE redflag_decisions_total counter\n")
	fmt.Fprintf(&b, "redflag_decisions_total{decision=\"allow\"} %d\n", m.Allow.Load())
	fmt.Fprintf(&b, "redflag_decisions_total{decision=\"review\"} %d\n", m.Review.Load())
	fmt.Fprintf(&b, "redflag_decisions_total{decision=\"block\"} %d\n", m.Block.Load())
	counter := func(name string, v uint64) {
		fmt.Fprintf(&b, "# TYPE %s counter\n%s %d\n", name, name, v)
	}
	counter("redflag_emergency_total", m.Emergency.Load())
	counter("redflag_block_suppressed_total", m.Suppressed.Load())
	counter("redflag_duplicates_total", m.Duplicates.Load())
	counter("redflag_errors_total", m.Errors.Load())
	counter("redflag_score_panics_total", s.panics.Load())
	counter("redflag_ml_calls_total", m.MLCalls.Load())
	counter("redflag_ml_decisions_total", m.MLDecisions.Load())
	counter("redflag_ml_errors_total", m.MLErrors.Load())
	counter("redflag_ml_skipped_total", m.MLSkipped.Load()) // breaker открыт: откат на стадию 1
	gauge := func(name string, v int) {
		fmt.Fprintf(&b, "# TYPE %s gauge\n%s %d\n", name, name, v)
	}
	gauge("redflag_tracked_numbers", s.Engine.Windows().Len())
	if fan := s.Engine.Fan(); fan != nil {
		gauge("redflag_fan_groups", fan.Groups())
		gauge("redflag_fan_members", fan.Members())
	}
	if s.Journal != nil {
		counter("redflag_journal_written_total", s.Journal.Written.Load())
		counter("redflag_journal_dropped_total", s.Journal.Dropped.Load())
		counter("redflag_journal_failed_total", s.Journal.Failed.Load())
	}
	fmt.Fprintf(&b, "# TYPE redflag_score_latency_seconds histogram\n")
	var cum uint64
	for i, bound := range latBounds {
		cum += s.lat.buckets[i].Load()
		fmt.Fprintf(&b, "redflag_score_latency_seconds_bucket{le=\"%g\"} %d\n", float64(bound)/1e6, cum)
	}
	cum += s.lat.buckets[len(latBounds)].Load()
	fmt.Fprintf(&b, "redflag_score_latency_seconds_bucket{le=\"+Inf\"} %d\n", cum)
	fmt.Fprintf(&b, "redflag_score_latency_seconds_sum %g\n", float64(s.lat.sumUS.Load())/1e6)
	fmt.Fprintf(&b, "redflag_score_latency_seconds_count %d\n", s.lat.count.Load())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
