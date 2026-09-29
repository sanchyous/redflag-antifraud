package logx

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pretty — читаемый вывод для консоли:
//
//	15:04:05.123 INFO  api         decision  call_id=c-1 decision=review score=0.15
//
// Колонки фиксированной ширины (время, уровень, компонент), поля после сообщения. Значения с пробелами
// заключаются в кавычки. Цвет — только уровню и имени компонента, чтобы поля оставались копируемыми.
type pretty struct {
	mu    *sync.Mutex
	out   io.Writer
	opts  slog.HandlerOptions
	color bool
	attrs []slog.Attr
	group string
}

// NewPretty создаёт обработчик читаемого формата.
func NewPretty(w io.Writer, opts *slog.HandlerOptions, color bool) slog.Handler {
	h := &pretty{mu: &sync.Mutex{}, out: w, color: color}
	if opts != nil {
		h.opts = *opts
	}
	return h
}

func (h *pretty) Enabled(_ context.Context, l slog.Level) bool {
	min := slog.LevelInfo
	if h.opts.Level != nil {
		min = h.opts.Level.Level()
	}
	return l >= min
}

func (h *pretty) WithAttrs(a []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr(nil), h.attrs...), qualify(h.group, a)...)
	return &c
}

func (h *pretty) WithGroup(name string) slog.Handler {
	c := *h
	if h.group != "" {
		c.group = h.group + "." + name
	} else {
		c.group = name
	}
	return &c
}

func qualify(group string, attrs []slog.Attr) []slog.Attr {
	if group == "" {
		return attrs
	}
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		a.Key = group + "." + a.Key
		out[i] = a
	}
	return out
}

const (
	reset  = "\x1b[0m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	yellow = "\x1b[33m"
	green  = "\x1b[32m"
	cyan   = "\x1b[36m"
	gray   = "\x1b[90m"
)

func levelText(l slog.Level) (string, string) {
	switch {
	case l >= slog.LevelError:
		return "ERROR", red
	case l >= slog.LevelWarn:
		return "WARN ", yellow
	case l >= slog.LevelInfo:
		return "INFO ", green
	}
	return "DEBUG", gray
}

func (h *pretty) Handle(_ context.Context, r slog.Record) error {
	var b bytes.Buffer
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	lvl, lc := levelText(r.Level)
	if h.color {
		b.WriteString(dim)
	}
	b.WriteString(t.Format("15:04:05.000"))
	if h.color {
		b.WriteString(reset)
	}
	b.WriteByte(' ')
	if h.color {
		b.WriteString(lc)
	}
	b.WriteString(lvl)
	if h.color {
		b.WriteString(reset)
	}
	b.WriteByte(' ')

	// component — в отдельную колонку, остальные атрибуты — после сообщения
	comp := ""
	var fields []slog.Attr
	collect := func(a slog.Attr) bool {
		if a.Key == "component" {
			comp = a.Value.String()
			return true
		}
		fields = append(fields, a)
		return true
	}
	for _, a := range h.attrs {
		collect(a)
	}
	r.Attrs(collect)

	if h.color {
		b.WriteString(cyan)
	}
	b.WriteString(pad(comp, 10))
	if h.color {
		b.WriteString(reset)
	}
	b.WriteByte(' ')
	b.WriteString(r.Message)
	for _, a := range fields {
		b.WriteByte(' ')
		if h.color {
			b.WriteString(dim)
		}
		b.WriteString(qualifyKey(h.group, a.Key))
		b.WriteByte('=')
		if h.color {
			b.WriteString(reset)
		}
		b.WriteString(formatValue(a.Value))
	}
	b.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.Write(b.Bytes())
	return err
}

func qualifyKey(group, key string) string {
	if group == "" || strings.HasPrefix(key, group+".") {
		return key
	}
	return group + "." + key
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func formatValue(v slog.Value) string {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return quoteIfNeeded(v.String())
	case slog.KindFloat64:
		return strconv.FormatFloat(v.Float64(), 'g', 6, 64)
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().Format(time.RFC3339)
	case slog.KindAny:
		if ss, ok := v.Any().([]string); ok { // списки (например, сигналы) — компактно: [a,b]
			return "[" + strings.Join(ss, ",") + "]"
		}
	}
	return quoteIfNeeded(v.String())
}

func quoteIfNeeded(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\n\"=") {
		return strconv.Quote(s)
	}
	return s
}
