package logx

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// RateLimit оборачивает обработчик ограничением частоты: не более perSecond записей в секунду на одно сообщение
// (ключ — текст сообщения). Превышение отбрасывается и считается; раз в секунду, если что-то отброшено, пишется одна
// сводка `log_dropped`. Ошибки и предупреждения не ограничиваются никогда: их потеря хуже лишних строк.
func RateLimit(next slog.Handler, perSecond int) slog.Handler {
	return &limiter{next: next, per: int64(perSecond), state: &limiterState{buckets: map[string]*bucket{}}}
}

type bucket struct {
	sec     atomic.Int64
	count   atomic.Int64
	dropped atomic.Int64
}

type limiterState struct {
	mu      sync.RWMutex
	buckets map[string]*bucket
}

type limiter struct {
	next  slog.Handler
	per   int64
	state *limiterState
}

func (l *limiter) Enabled(ctx context.Context, lv slog.Level) bool { return l.next.Enabled(ctx, lv) }

func (l *limiter) WithAttrs(a []slog.Attr) slog.Handler {
	return &limiter{next: l.next.WithAttrs(a), per: l.per, state: l.state}
}

func (l *limiter) WithGroup(n string) slog.Handler {
	return &limiter{next: l.next.WithGroup(n), per: l.per, state: l.state}
}

func (l *limiter) bucketFor(msg string) *bucket {
	l.state.mu.RLock()
	b := l.state.buckets[msg]
	l.state.mu.RUnlock()
	if b != nil {
		return b
	}
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if b = l.state.buckets[msg]; b == nil {
		b = &bucket{}
		l.state.buckets[msg] = b
	}
	return b
}

func (l *limiter) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn || l.per <= 0 {
		return l.next.Handle(ctx, r)
	}
	b := l.bucketFor(r.Message)
	now := r.Time.Unix()
	if prev := b.sec.Load(); prev != now && b.sec.CompareAndSwap(prev, now) {
		// новая секунда: сводка об отброшенном в предыдущей и сброс счётчика
		if d := b.dropped.Swap(0); d > 0 {
			sum := slog.NewRecord(r.Time, slog.LevelInfo, "log_dropped", 0)
			sum.AddAttrs(slog.String("message", r.Message), slog.Int64("dropped", d))
			_ = l.next.Handle(ctx, sum)
		}
		b.count.Store(0)
	}
	if b.count.Add(1) > l.per {
		b.dropped.Add(1)
		return nil
	}
	return l.next.Handle(ctx, r)
}
