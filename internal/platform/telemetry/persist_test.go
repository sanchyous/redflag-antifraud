package telemetry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memStore struct {
	mu   sync.Mutex
	rows map[int64]MinuteRow
	fail bool
}

func (m *memStore) SaveMinutes(_ context.Context, rows []MinuteRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("db down")
	}
	if m.rows == nil {
		m.rows = map[int64]MinuteRow{}
	}
	for _, r := range rows {
		m.rows[r.TS] = r
	}
	return nil
}

func (m *memStore) LoadMinutes(_ context.Context, since int64) ([]MinuteRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []MinuteRow
	for _, r := range m.rows {
		if r.TS >= since {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestPersistRestoreRoundTrip(t *testing.T) {
	clock := time.Date(2026, 9, 29, 12, 0, 30, 0, time.UTC)
	now := func() time.Time { return clock }

	a := New(now)
	for i := 0; i < 5; i++ {
		a.Observe(Sample{Decision: Allow, Stage: StageLinear, LatencyUS: 40})
	}
	a.Observe(Sample{Decision: Block, Stage: StageML, LatencyUS: 4000})
	clock = clock.Add(2 * time.Minute)

	rows := a.Dirty()
	if len(rows) != 1 {
		t.Fatalf("ожидалась одна изменённая минута, получено %d", len(rows))
	}
	if got := a.Dirty(); len(got) != 0 {
		t.Fatalf("после сохранения пометки должны сниматься, осталось %d", len(got))
	}

	b := New(now) // «перезапуск»
	if n := b.Restore(rows); n != 1 {
		t.Fatalf("восстановлено минут: %d, ожидалась 1", n)
	}
	tot := b.Totals()
	if tot.Allow != 5 || tot.Block != 1 || tot.ML != 1 {
		t.Errorf("счётчики после восстановления: %+v", tot)
	}
	w := b.Window(time.Hour)
	if w.Total != 6 || w.Block != 1 {
		t.Errorf("окно часа после восстановления: %+v", w)
	}
	if w.P99US <= 0 {
		t.Errorf("гистограмма задержки потеряна: %+v", w)
	}
}

func TestRestoreSkipsStaleAndFuture(t *testing.T) {
	clock := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	r := New(func() time.Time { return clock })
	now := clock.Unix()
	n := r.Restore([]MinuteRow{
		{TS: now - 2*86400 - now%60 + 0, Allow: 1}, // старше суток
		{TS: now + 600, Allow: 1},                  // из будущего
		{TS: now - 61, Allow: 1},                   // не выровнена по минуте
	})
	if n != 0 {
		t.Fatalf("устаревшие и некорректные строки должны игнорироваться, загружено %d", n)
	}
}

func TestPersistRetriesAfterError(t *testing.T) {
	clock := time.Date(2026, 9, 29, 12, 0, 30, 0, time.UTC)
	r := New(func() time.Time { return clock })
	r.Observe(Sample{Decision: Review, LatencyUS: 100})
	clock = clock.Add(2 * time.Minute)

	st := &memStore{fail: true}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Persist(ctx, st, 10*time.Millisecond, func(error) {})
	}()
	time.Sleep(60 * time.Millisecond) // несколько неудачных попыток
	st.mu.Lock()
	st.fail = false
	st.mu.Unlock()
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done

	got, _ := st.LoadMinutes(context.Background(), 0)
	if len(got) != 1 || got[0].Review != 1 {
		t.Fatalf("после сбоя данные должны быть досохранены, в хранилище: %+v", got)
	}
}
