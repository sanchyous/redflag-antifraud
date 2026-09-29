package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sanchyous/redflag-antifraud/internal/platform/telemetry"
)

// Минутные агрегаты телеметрии хранятся, чтобы панель не обнулялась при перезапуске (деплое) сервиса.
const telemetrySchema = `
CREATE TABLE IF NOT EXISTS telemetry_minutes (
	ts         BIGINT PRIMARY KEY,
	allow      BIGINT NOT NULL DEFAULT 0,
	review     BIGINT NOT NULL DEFAULT 0,
	block      BIGINT NOT NULL DEFAULT 0,
	linear     BIGINT NOT NULL DEFAULT 0,
	ml         BIGINT NOT NULL DEFAULT 0,
	emergency  BIGINT NOT NULL DEFAULT 0,
	duplicates BIGINT NOT NULL DEFAULT 0,
	floors     BIGINT NOT NULL DEFAULT 0,
	suppressed BIGINT NOT NULL DEFAULT 0,
	lat_sum_us BIGINT NOT NULL DEFAULT 0,
	lat        BIGINT[] NOT NULL DEFAULT '{}'
);
`

// telemetryKeep — сколько хранить минутные агрегаты (панель показывает сутки).
const telemetryKeep = 48 * time.Hour

// SaveMinutes upsert-ит минутные агрегаты и удаляет устаревшие.
func (s *Store) SaveMinutes(ctx context.Context, rows []telemetry.MinuteRow) error {
	batch := &pgx.Batch{}
	for _, m := range rows {
		lat := make([]int64, len(m.Lat))
		for i, c := range m.Lat {
			lat[i] = int64(c)
		}
		batch.Queue(`INSERT INTO telemetry_minutes (ts, allow, review, block, linear, ml, emergency, duplicates, floors, suppressed, lat_sum_us, lat)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (ts) DO UPDATE SET allow=EXCLUDED.allow, review=EXCLUDED.review, block=EXCLUDED.block, linear=EXCLUDED.linear,
				ml=EXCLUDED.ml, emergency=EXCLUDED.emergency, duplicates=EXCLUDED.duplicates, floors=EXCLUDED.floors,
				suppressed=EXCLUDED.suppressed, lat_sum_us=EXCLUDED.lat_sum_us, lat=EXCLUDED.lat`,
			m.TS, int64(m.Allow), int64(m.Review), int64(m.Block), int64(m.Linear), int64(m.ML), int64(m.Emergency),
			int64(m.Duplicates), int64(m.Floors), int64(m.Suppressed), int64(m.LatSumUS), lat)
	}
	batch.Queue(`DELETE FROM telemetry_minutes WHERE ts < $1`, time.Now().Add(-telemetryKeep).Unix())
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// LoadMinutes возвращает минутные агрегаты не старше since (unix-секунды) по возрастанию времени.
func (s *Store) LoadMinutes(ctx context.Context, since int64) ([]telemetry.MinuteRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT ts, allow, review, block, linear, ml, emergency, duplicates, floors, suppressed, lat_sum_us, lat
		FROM telemetry_minutes WHERE ts >= $1 ORDER BY ts`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []telemetry.MinuteRow
	for rows.Next() {
		var m telemetry.MinuteRow
		var v [10]int64
		var lat []int64
		if err := rows.Scan(&m.TS, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &lat); err != nil {
			return nil, err
		}
		m.Allow, m.Review, m.Block, m.Linear, m.ML = uint64(v[0]), uint64(v[1]), uint64(v[2]), uint64(v[3]), uint64(v[4])
		m.Emergency, m.Duplicates, m.Floors, m.Suppressed, m.LatSumUS = uint64(v[5]), uint64(v[6]), uint64(v[7]), uint64(v[8]), uint64(v[9])
		for i := 0; i < len(m.Lat) && i < len(lat); i++ {
			m.Lat[i] = uint64(lat[i])
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RiskyEvents возвращает последние рискованные решения (review и block) для списка «проблем», от старых к новым.
func (s *Store) RiskyEvents(ctx context.Context, limit int) ([]telemetry.Event, error) {
	rows, err := s.pool.Query(ctx, `SELECT call_id, caller_masked, callee_masked, decision, score, reasons, signals, safe_class, latency_us, created_at
		FROM call_decisions WHERE decision <> 'allow' ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []telemetry.Event
	for rows.Next() {
		var ev telemetry.Event
		var reasons []byte
		if err := rows.Scan(&ev.CallID, &ev.Caller, &ev.Callee, &ev.Decision, &ev.Score, &reasons, &ev.Signals, &ev.SafeClass, &ev.LatencyUS, &ev.Time); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(reasons, &ev.Reasons) // формат reasons совпадает с telemetry.Reason; непонятное — пустой список
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 { // старые первыми: так кольцо событий заполняется в правильном порядке
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}
