package api

import (
	"context"
	"log/slog"

	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
)

// logDecision пишет решение в лог как бизнес-событие. Рискованные решения (review, block) — уровень info с полями,
// по которым их легко искать; allow — только при LogDecisions=all и на уровне debug. Номера — только маскированные.
// Ограничение частоты (чтобы поток не съедал производительность) настраивается обработчиком логгера (logx.RateLimit).
func (s *Server) logDecision(ctx context.Context, r *engine.Response) {
	mode := s.LogDecisions
	if mode == "off" {
		return
	}
	level := slog.LevelInfo
	if r.Decision == "allow" {
		if mode != "all" {
			return
		}
		level = slog.LevelDebug
	}
	if !s.Log.Enabled(ctx, level) {
		return
	}
	top := ""
	for _, x := range r.Reasons {
		if x.Effect == "raises" {
			top = x.Text
			break
		}
	}
	attrs := []slog.Attr{
		slog.String("call_id", r.CallID),
		slog.String("decision", r.Decision),
		slog.String("stage", r.Stage),
		slog.Float64("score", r.Score),
		slog.String("caller", r.Caller.Masked),
		slog.String("callee", r.Callee.Masked),
		slog.Int64("latency_us", r.LatencyUS),
	}
	if len(r.Signals) > 0 {
		attrs = append(attrs, slog.Any("signals", r.Signals))
	}
	if r.Summary != "" && r.Decision != "allow" {
		attrs = append(attrs, slog.String("summary", r.Summary))
	}
	if top != "" {
		attrs = append(attrs, slog.String("top_reason", top))
	}
	if r.RuleFloor {
		attrs = append(attrs, slog.Bool("rule_floor", true))
	}
	if r.BlockSuppressed {
		attrs = append(attrs, slog.Bool("block_suppressed", true))
	}
	if r.SafeClass != "" {
		attrs = append(attrs, slog.String("safe_class", r.SafeClass))
	}
	s.Log.LogAttrs(ctx, level, "decision", attrs...)
}
