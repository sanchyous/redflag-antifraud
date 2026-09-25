// Package store — журнал решений в Postgres (некритический путь: ошибка записи не влияет на вердикт).
package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS decisions (
	id             BIGSERIAL PRIMARY KEY,
	request_id     TEXT NOT NULL,
	transaction_id TEXT NOT NULL,
	user_id        TEXT NOT NULL,
	amount         NUMERIC(18,2) NOT NULL,
	currency       TEXT NOT NULL,
	ip             TEXT NOT NULL,
	decision       TEXT NOT NULL,
	reasons        TEXT[] NOT NULL DEFAULT '{}',
	latency_ms     BIGINT NOT NULL DEFAULT 0,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Идемпотентность: повторный transaction_id не пишет дубль.
-- DO-блок — безопасная миграция для уже созданных баз.
DO $$ BEGIN
	ALTER TABLE decisions ADD CONSTRAINT decisions_txn_unique UNIQUE (transaction_id);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS idx_decisions_created_at ON decisions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_user_id ON decisions (user_id);
`

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

func (s *Store) Close() { s.pool.Close() }

// Record — решение, которое пишем в журнал.
type Record struct {
	RequestID     string
	TransactionID string
	UserID        string
	Amount        float64
	Currency      string
	IP            string
	Decision      string
	Reasons       []string
	LatencyMS     int64
}

// Entry — строка журнала для выдачи наружу.
type Entry struct {
	TransactionID string    `json:"transaction_id"`
	UserID        string    `json:"user_id"`
	Amount        float64   `json:"amount"`
	Currency      string    `json:"currency"`
	IP            string    `json:"ip"`
	Decision      string    `json:"decision"`
	Reasons       []string  `json:"reasons"`
	CreatedAt     time.Time `json:"created_at"`
}

// Save пишет решение.
func (s *Store) Save(ctx context.Context, r Record) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO decisions (request_id, transaction_id, user_id, amount, currency, ip, decision, reasons, latency_ms)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (transaction_id) DO NOTHING`,
		r.RequestID, r.TransactionID, r.UserID, r.Amount, r.Currency, r.IP, r.Decision, r.Reasons, r.LatencyMS)
	return err
}

// Recent — последние решения (для демо и отладки).
func (s *Store) Recent(ctx context.Context, limit int) ([]Entry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT transaction_id, user_id, amount, currency, ip, decision, reasons, created_at
		 FROM decisions ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var reasons []string
		if err := rows.Scan(&e.TransactionID, &e.UserID, &e.Amount, &e.Currency, &e.IP, &e.Decision, &reasons, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Reasons = reasons
		out = append(out, e)
	}
	return out, rows.Err()
}
