// Package journal — асинхронная запись решений в журнал. Горячий путь скоринга не ждёт
// базу: решение кладётся в буферизованный канал, фоновая горутина пишет пачками. Переполнение
// не блокирует скоринг: запись отбрасывается и считается в Dropped.
package journal

import (
	"context"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/platform/store"
)

// Sink — приёмник пачек (реализуется *store.Store; в тестах — заглушка).
type Sink interface {
	SaveBatch(ctx context.Context, recs []store.Record) error
}

// Config — параметры журнала.
type Config struct {
	Buffer      int           // ёмкость очереди (по умолчанию 8192)
	BatchSize   int           // максимум записей в пачке (по умолчанию 500)
	FlushEvery  time.Duration // период сброса (по умолчанию 200 мс)
	AllowSample float64       // доля allow-решений, попадающих в журнал (0 — только review/block)
	Timeout     time.Duration // таймаут записи пачки (по умолчанию 5 с)
}

// Journal — асинхронный писатель.
type Journal struct {
	cfg     Config
	sink    Sink
	log     *slog.Logger
	ch      chan store.Record
	wg      sync.WaitGroup
	Dropped atomic.Uint64
	Written atomic.Uint64
	Failed  atomic.Uint64
}

// New создаёт и запускает журнал. Останавливается Close.
func New(sink Sink, cfg Config, log *slog.Logger) *Journal {
	if cfg.Buffer <= 0 {
		cfg.Buffer = 8192
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 200 * time.Millisecond
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	j := &Journal{cfg: cfg, sink: sink, log: log, ch: make(chan store.Record, cfg.Buffer)}
	j.wg.Add(1)
	go j.loop()
	return j
}

// Wants решает, нужно ли писать решение: review/block всегда, allow — по выборке
// (детерминированно по call_id, чтобы повторная доставка вела себя одинаково).
func (j *Journal) Wants(decision, callID string) bool {
	if decision != "allow" {
		return true
	}
	if j.cfg.AllowSample <= 0 {
		return false
	}
	if j.cfg.AllowSample >= 1 {
		return true
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(callID))
	return float64(h.Sum32())/float64(1<<32) < j.cfg.AllowSample
}

// Add кладёт запись в очередь без блокировки.
func (j *Journal) Add(r store.Record) {
	select {
	case j.ch <- r:
	default:
		j.Dropped.Add(1)
	}
}

func (j *Journal) loop() {
	defer j.wg.Done()
	t := time.NewTicker(j.cfg.FlushEvery)
	defer t.Stop()
	batch := make([]store.Record, 0, j.cfg.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), j.cfg.Timeout)
		err := j.sink.SaveBatch(ctx, batch)
		cancel()
		if err != nil {
			j.Failed.Add(uint64(len(batch)))
			j.log.Error("journal_save_failed", "err", err.Error(), "records", len(batch))
		} else {
			j.Written.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}
	for {
		select {
		case r, ok := <-j.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, r)
			if len(batch) >= j.cfg.BatchSize {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// Close дописывает очередь и останавливает писателя.
func (j *Journal) Close() {
	close(j.ch)
	j.wg.Wait()
}
