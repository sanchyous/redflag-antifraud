package graph

import (
	"sort"
	"sync/atomic"

	"github.com/sanchyous/redflag-antifraud/internal/detection/window"
)

// SimBoxConfig — параметры детектора «SIM-box»: несколько SIM работают только на исходящие,
// каждый получатель новый, вызовы обычной (не короткой — иначе это веер/wangiri) длительности,
// входящих на номер нет вовсе. Нормальная длительность — то, что отличает SIM-box от «веера»
// (graph.Analyze): там шаблон аномален именно короткими/неотвеченными вызовами, здесь трафик
// выглядит как обычные разговоры и отличается только отсутствием входящих и полной новизной
// адресатов.
type SimBoxConfig struct {
	MinCalls   int     // минимум исходящих за период (по умолчанию 50)
	MinNovelty float32 // peers/calls, ниже — обычный повторный собеседник (по умолчанию 0.95)
	MinMeanDur float32 // средняя длительность принятых, с (по умолчанию 30)
}

// MinCallsOrDefault возвращает MinCalls с учётом значения по умолчанию.
func (c SimBoxConfig) MinCallsOrDefault() int {
	c.defaults()
	return c.MinCalls
}

func (c *SimBoxConfig) defaults() {
	if c.MinCalls <= 0 {
		c.MinCalls = 50
	}
	if c.MinNovelty <= 0 {
		c.MinNovelty = 0.95
	}
	if c.MinMeanDur <= 0 {
		c.MinMeanDur = 30
	}
}

// SimBoxInfo — показатели номера, отмеченного как участник SIM-box.
type SimBoxInfo struct {
	Calls uint32
	Peers int
}

// SimBoxIndex — результат анализа. Неизменяем после создания.
type SimBoxIndex struct{ m map[uint64]SimBoxInfo }

// Lookup ищет номер в индексе.
func (ix *SimBoxIndex) Lookup(key uint64) (SimBoxInfo, bool) {
	if ix == nil {
		return SimBoxInfo{}, false
	}
	si, ok := ix.m[key]
	return si, ok
}

// SimBoxEntry — отмеченный номер с его показателями (для панели).
type SimBoxEntry struct {
	Key uint64
	SimBoxInfo
}

// List возвращает отмеченные номера, самые активные первыми. Аллоцирует на каждый вызов —
// не горячий путь (панель мониторинга).
func (ix *SimBoxIndex) List() []SimBoxEntry {
	if ix == nil {
		return nil
	}
	out := make([]SimBoxEntry, 0, len(ix.m))
	for k, v := range ix.m {
		out = append(out, SimBoxEntry{Key: k, SimBoxInfo: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Calls > out[j].Calls })
	return out
}

// Members — число отмеченных номеров.
func (ix *SimBoxIndex) Members() int {
	if ix == nil {
		return 0
	}
	return len(ix.m)
}

// AnalyzeSimBox ищет номера с паттерном SIM-box: только исходящие (win.Peek на вход даёт 0 за
// сутки), почти все вызовы — новому собеседнику, обычная длительность, заметный объём.
// win нужен для проверки входящих — Profiles() строит профили только по исходящим.
func AnalyzeSimBox(win *window.Store, profiles []window.Profile, now int64, cfg SimBoxConfig) *SimBoxIndex {
	cfg.defaults()
	ix := &SimBoxIndex{m: make(map[uint64]SimBoxInfo)}
	for i := range profiles {
		p := &profiles[i]
		if int(p.Calls) < cfg.MinCalls || len(p.Peers) == 0 {
			continue
		}
		novelty := float32(len(p.Peers)) / float32(p.Calls)
		if novelty < cfg.MinNovelty || p.MeanDurSec < cfg.MinMeanDur {
			continue
		}
		if win.Peek(p.Key, false, now).Calls24h > 0 {
			continue // есть входящие — не SIM-box (возможен колл-центр, D1)
		}
		ix.m[p.Key] = SimBoxInfo{Calls: p.Calls, Peers: len(p.Peers)}
	}
	return ix
}

// SimBoxHolder — атомарный держатель актуального индекса SIM-box.
type SimBoxHolder struct{ p atomic.Pointer[SimBoxIndex] }

// Store публикует новый индекс.
func (h *SimBoxHolder) Store(ix *SimBoxIndex) { h.p.Store(ix) }

// Lookup ищет номер в текущем индексе.
func (h *SimBoxHolder) Lookup(key uint64) (SimBoxInfo, bool) { return h.p.Load().Lookup(key) }

// Index возвращает текущий индекс (может быть nil).
func (h *SimBoxHolder) Index() *SimBoxIndex { return h.p.Load() }
