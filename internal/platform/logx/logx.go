// Package logx — единая настройка структурированного логирования (log/slog).
//
// Форматы:
//   - pretty — для разработки и консоли: время, уровень, компонент, сообщение и поля key=value в колонках,
//     цвет включается только на терминале;
//   - json   — для продакшена и сбора логов: одна строка JSON на событие;
//   - text   — стандартный slog-текст (key=value).
//
// Правила: сообщение — короткий идентификатор события в snake_case (`ml_breaker_opened`), всё переменное — в полях;
// персональные данные (номера) — только маскированные. Общий контекст события — request_id, component — добавляется
// автоматически. На горячем пути события ограничиваются по частоте (см. RateLimit), чтобы логи не съедали производительность.
package logx

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Config — параметры логгера.
type Config struct {
	Level   string    // debug | info | warn | error (по умолчанию info)
	Format  string    // pretty | json | text (по умолчанию json, если stdout не терминал, иначе pretty)
	Service string    // имя сервиса в каждой записи (json/text)
	Version string    // версия сборки
	Out     io.Writer // куда писать (по умолчанию stdout)
	Color   *bool     // принудительно включить/выключить цвет (nil — по терминалу)
}

// ParseLevel разбирает уровень; неизвестное значение — info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// New создаёт логгер по конфигурации.
func New(cfg Config) *slog.Logger {
	out := cfg.Out
	if out == nil {
		out = os.Stdout
	}
	opts := &slog.HandlerOptions{Level: ParseLevel(cfg.Level)}
	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		if isTerminal(out) {
			format = "pretty"
		} else {
			format = "json"
		}
	}
	var h slog.Handler
	switch format {
	case "pretty":
		color := isTerminal(out)
		if cfg.Color != nil {
			color = *cfg.Color
		}
		h = NewPretty(out, opts, color)
	case "text":
		h = slog.NewTextHandler(out, opts)
	default:
		h = slog.NewJSONHandler(out, opts)
	}
	h = &contextHandler{Handler: h}
	l := slog.New(h)
	if format != "pretty" {
		if cfg.Service != "" {
			l = l.With("service", cfg.Service)
		}
		if cfg.Version != "" {
			l = l.With("version", cfg.Version)
		}
	}
	return l
}

// Discard возвращает логгер, который ничего не пишет (для тестов и необязательных зависимостей).
func Discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Component возвращает логгер с полем component — так записи легко фильтровать по подсистеме.
func Component(l *slog.Logger, name string) *slog.Logger {
	if l == nil {
		return Discard()
	}
	return l.With("component", name)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

type ctxKey struct{}

// WithRequestID кладёт идентификатор запроса в контекст: все записи с этим контекстом получат поле request_id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestID возвращает идентификатор запроса из контекста.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// contextHandler добавляет к записи поля из контекста (request_id).
type contextHandler struct{ slog.Handler }

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithAttrs(a)}
}

func (h *contextHandler) WithGroup(n string) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithGroup(n)}
}
