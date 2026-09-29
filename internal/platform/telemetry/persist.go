package telemetry

import (
	"context"
	"sort"
	"time"
)

// MinuteRow — минутный агрегат в виде, пригодном для хранения (Postgres). Все счётчики — за одну минуту.
type MinuteRow struct {
	TS         int64 // начало минуты, unix-секунды
	Allow      uint64
	Review     uint64
	Block      uint64
	Linear     uint64
	ML         uint64
	Emergency  uint64
	Duplicates uint64
	Floors     uint64
	Suppressed uint64
	LatSumUS   uint64
	Lat        [nLat]uint64 // гистограмма задержки, границы latBoundsUS
}

// LatBuckets — число корзин гистограммы задержки (нужно хранилищу для схемы).
const LatBuckets = nLat

// Store — то, что нужно для сохранения телеметрии между перезапусками (реализует *store.Store).
type Store interface {
	SaveMinutes(ctx context.Context, rows []MinuteRow) error
	LoadMinutes(ctx context.Context, since int64) ([]MinuteRow, error)
}

func (b *bucket) row() MinuteRow {
	m := MinuteRow{
		TS: b.ts.Load(), Allow: b.decisions[Allow].Load(), Review: b.decisions[Review].Load(), Block: b.decisions[Block].Load(),
		Linear: b.stages[StageLinear].Load(), ML: b.stages[StageML].Load(), Emergency: b.emergency.Load(),
		Duplicates: b.duplicates.Load(), Floors: b.floors.Load(), Suppressed: b.suppressed.Load(), LatSumUS: b.latSumUS.Load(),
	}
	for i := range m.Lat {
		m.Lat[i] = b.lat[i].Load()
	}
	return m
}

// Dirty возвращает минутные агрегаты, изменённые с прошлого вызова, и сбрасывает пометку. Перед чтением сворачивает
// завершённые секунды. Если сохранить не удалось, вызывающий возвращает строки через MarkDirty.
func (r *Recorder) Dirty() []MinuteRow {
	r.Roll()
	r.rollMu.Lock()
	defer r.rollMu.Unlock()
	if len(r.dirty) == 0 {
		return nil
	}
	rows := make([]MinuteRow, 0, len(r.dirty))
	for minute := range r.dirty {
		if b := &r.mins[(minute/60)%minSlots]; b.ts.Load() == minute {
			rows = append(rows, b.row())
		}
	}
	r.dirty = map[int64]struct{}{}
	sort.Slice(rows, func(i, j int) bool { return rows[i].TS < rows[j].TS })
	return rows
}

// MarkDirty снова помечает минуты неотправленными (сохранение не удалось).
func (r *Recorder) MarkDirty(rows []MinuteRow) {
	r.rollMu.Lock()
	defer r.rollMu.Unlock()
	for _, m := range rows {
		r.dirty[m.TS] = struct{}{}
	}
}

// Restore загружает сохранённые минутные агрегаты (при старте). Строки старше суток и из будущего игнорируются.
// Итоговые счётчики (Totals) становятся суммой за восстановленный период. Возвращает число загруженных минут.
func (r *Recorder) Restore(rows []MinuteRow) int {
	r.rollMu.Lock()
	defer r.rollMu.Unlock()
	now := r.now().Unix()
	n := 0
	for _, m := range rows {
		if m.TS%60 != 0 || m.TS > now || now-m.TS >= int64(minSlots)*60 {
			continue
		}
		b := &r.mins[(m.TS/60)%minSlots]
		b.reset(m.TS)
		b.decisions[Allow].Store(m.Allow)
		b.decisions[Review].Store(m.Review)
		b.decisions[Block].Store(m.Block)
		b.stages[StageLinear].Store(m.Linear)
		b.stages[StageML].Store(m.ML)
		b.emergency.Store(m.Emergency)
		b.duplicates.Store(m.Duplicates)
		b.floors.Store(m.Floors)
		b.suppressed.Store(m.Suppressed)
		b.latSumUS.Store(m.LatSumUS)
		for i, c := range m.Lat {
			b.lat[i].Store(c)
		}
		r.total.decisions[Allow].Add(m.Allow)
		r.total.decisions[Review].Add(m.Review)
		r.total.decisions[Block].Add(m.Block)
		r.total.stages[StageLinear].Add(m.Linear)
		r.total.stages[StageML].Add(m.ML)
		r.total.emergency.Add(m.Emergency)
		n++
	}
	return n
}

// RestoreEvents заполняет список событий и счётчики причин (при старте). events — от старых к новым.
func (r *Recorder) RestoreEvents(events []Event) {
	for _, ev := range events {
		r.RecordEvent(ev)
	}
}

// Persist раз в every сохраняет изменённые минутные агрегаты, а при остановке (ctx отменён) делает последнее сохранение.
// Ошибка записи не теряет данные: минуты помечаются снова и уходят при следующей попытке.
func (r *Recorder) Persist(ctx context.Context, st Store, every time.Duration, onError func(error)) {
	if every <= 0 {
		every = 15 * time.Second
	}
	flush := func(c context.Context) {
		rows := r.Dirty()
		if len(rows) == 0 {
			return
		}
		if err := st.SaveMinutes(c, rows); err != nil {
			r.MarkDirty(rows)
			if onError != nil {
				onError(err)
			}
		}
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// последнее сохранение: контекст уже отменён, берём новый с коротким сроком
			fc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			flush(fc)
			cancel()
			return
		case <-t.C:
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			flush(c)
			cancel()
		}
	}
}
