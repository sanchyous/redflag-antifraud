// Package store — журнал решений по вызовам в Postgres (некритический путь: ошибка записи
// не влияет на вердикт). В журнал попадают только маскированные номера.
package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS call_decisions (
	id              BIGSERIAL PRIMARY KEY,
	call_id         TEXT NOT NULL,
	caller_masked   TEXT NOT NULL,
	callee_masked   TEXT NOT NULL,
	decision        TEXT NOT NULL,
	score           DOUBLE PRECISION NOT NULL,
	reasons         JSONB NOT NULL DEFAULT '[]',
	signals         TEXT[] NOT NULL DEFAULT '{}',
	safe_class      TEXT NOT NULL DEFAULT '',
	model_version   TEXT NOT NULL DEFAULT '',
	numplan_version TEXT NOT NULL DEFAULT '',
	latency_us      BIGINT NOT NULL DEFAULT 0,
	created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Идемпотентность журнала: повторная доставка вызова не пишет дубль.
-- Миграция обязана быть повторяемой: сервис запускается заново при каждом деплое. Повторное
-- ADD CONSTRAINT UNIQUE даёт ошибку 42P07 (duplicate_table: индекс уже есть), а не 42710
-- (duplicate_object), поэтому проверяем наличие ограничения явно, а не ловим конкретный код.
DO $$ BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'call_decisions_call_id_unique') THEN
		ALTER TABLE call_decisions ADD CONSTRAINT call_decisions_call_id_unique UNIQUE (call_id);
	END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_call_decisions_created_at ON call_decisions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_call_decisions_decision ON call_decisions (decision, id DESC);
`

// Store — соединение с Postgres.
type Store struct {
	pool *pgxpool.Pool
}

// Open подключается и гарантирует схему.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close закрывает пул.
func (s *Store) Close() { s.pool.Close() }

// Record — решение для журнала.
type Record struct {
	CallID         string
	CallerMasked   string
	CalleeMasked   string
	Decision       string
	Score          float64
	Reasons        json.RawMessage // JSON-массив причин
	Signals        []string
	SafeClass      string
	ModelVersion   string
	NumplanVersion string
	LatencyUS      int64
	CreatedAt      time.Time
}

// Entry — строка журнала для выдачи наружу.
type Entry struct {
	CallID         string          `json:"call_id"`
	Caller         string          `json:"caller"`
	Callee         string          `json:"callee"`
	Decision       string          `json:"decision"`
	Score          float64         `json:"score"`
	Reasons        json.RawMessage `json:"reasons"`
	Signals        []string        `json:"signals"`
	SafeClass      string          `json:"safe_class,omitempty"`
	ModelVersion   string          `json:"model_version"`
	NumplanVersion string          `json:"numplan_version,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// SaveBatch пишет пачку решений одним round-trip. Дубли по call_id молча пропускаются.
func (s *Store) SaveBatch(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, r := range recs {
		reasons := r.Reasons
		if len(reasons) == 0 {
			reasons = json.RawMessage("[]")
		}
		signals := r.Signals
		if signals == nil {
			signals = []string{}
		}
		created := r.CreatedAt
		if created.IsZero() {
			created = time.Now()
		}
		batch.Queue(`INSERT INTO call_decisions
			(call_id, caller_masked, callee_masked, decision, score, reasons, signals, safe_class, model_version, numplan_version, latency_us, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (call_id) DO NOTHING`,
			r.CallID, r.CallerMasked, r.CalleeMasked, r.Decision, r.Score, []byte(reasons), signals,
			r.SafeClass, r.ModelVersion, r.NumplanVersion, r.LatencyUS, created)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range recs {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// Recent — последние решения; decision != "" фильтрует по вердикту.
func (s *Store) Recent(ctx context.Context, limit int, decision string) ([]Entry, error) {
	q := `SELECT call_id, caller_masked, callee_masked, decision, score, reasons, signals, safe_class, model_version, numplan_version, created_at
	      FROM call_decisions`
	args := []any{}
	if decision != "" {
		q += ` WHERE decision = $1`
		args = append(args, decision)
	}
	q += ` ORDER BY id DESC LIMIT ` + itoa(limit)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var reasons []byte
		if err := rows.Scan(&e.CallID, &e.Caller, &e.Callee, &e.Decision, &e.Score, &reasons, &e.Signals,
			&e.SafeClass, &e.ModelVersion, &e.NumplanVersion, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Reasons = reasons
		out = append(out, e)
	}
	return out, rows.Err()
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
