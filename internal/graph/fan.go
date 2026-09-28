// Package graph — графовые признаки: «веер» (группа номеров, обзванивающая непересекающиеся
// списки получателей по одному шаблону) и число номеров на одного абонента.
//
// Поиск веера идёт асинхронно по снимку профилей, результат — неизменяемый Index,
// который подменяется атомарно; на горячем пути — один поиск в map.
package graph

import (
	"math"
	"sync/atomic"

	"github.com/sanchyous/redflag-antifraud/internal/window"
)

// Config — параметры детектора.
//
// Одних «похожего шаблона» и «непересекающихся списков» мало: обычные люди тоже звонят
// разным адресатам и в большой популяции случайно совпадают по шаблону. Поэтому в веере
// участвуют только номера с аномальным шаблоном — высокая активность и короткие или
// неотвеченные вызовы.
type Config struct {
	MinCalls    int     // минимум исходящих у номера за период (по умолчанию 30)
	MinGroup    int     // минимальный размер группы (по умолчанию 4)
	MinDisjoint float32 // порог непересечения списков: |union| / Σ|список| (по умолчанию 0.85)
	MinUnanswer float32 // доля неотвеченных, с которой шаблон считается аномальным (по умолчанию 0.5)
	MaxMeanDur  float32 // средняя длительность принятых, до которой шаблон аномален, с (по умолчанию 15)
}

func (c *Config) defaults() {
	if c.MinCalls <= 0 {
		c.MinCalls = 30
	}
	if c.MinUnanswer <= 0 {
		c.MinUnanswer = 0.5
	}
	if c.MaxMeanDur <= 0 {
		c.MaxMeanDur = 15
	}
	if c.MinGroup <= 0 {
		c.MinGroup = 4
	}
	if c.MinDisjoint <= 0 {
		c.MinDisjoint = 0.85
	}
}

// FanInfo — принадлежность номера к вееру.
type FanInfo struct {
	GroupID  uint64  // наименьший ключ участника
	Size     uint16  // число номеров в группе
	Disjoint float32 // 1.0 — списки получателей не пересекаются вовсе
	Calls    uint32  // суммарно вызовов группы за период
}

// Index — результат анализа: номер → веер. Неизменяем после создания.
type Index struct {
	m map[uint64]FanInfo
}

// Lookup ищет номер в индексе.
func (ix *Index) Lookup(key uint64) (FanInfo, bool) {
	if ix == nil {
		return FanInfo{}, false
	}
	fi, ok := ix.m[key]
	return fi, ok
}

// Groups — число найденных вееров.
func (ix *Index) Groups() int {
	if ix == nil {
		return 0
	}
	seen := map[uint64]struct{}{}
	for _, fi := range ix.m {
		seen[fi.GroupID] = struct{}{}
	}
	return len(seen)
}

// Members — число номеров во всех веерах.
func (ix *Index) Members() int {
	if ix == nil {
		return 0
	}
	return len(ix.m)
}

type cohortKey struct {
	dur, gap, unans int8
	foreign         bool
}

func bucketLog2(v float32) int8 {
	if v <= 0 {
		return 0
	}
	return int8(math.Round(math.Log2(float64(v) + 1)))
}

func cohortOf(p *window.Profile) cohortKey {
	return cohortKey{
		dur:     bucketLog2(p.MeanDurSec),
		gap:     bucketLog2(p.GapMeanSec),
		unans:   int8(p.UnansweredShr * 4), // 0..4, шаг 0.25
		foreign: p.ForeignShare > 0.5,
	}
}

// Analyze ищет веера. Номера группируются по шаблону поведения (порядок длительности,
// ритм, доля неотвеченных, вход из-за рубежа); группа — веер, если в ней не меньше
// MinGroup номеров и списки получателей практически не пересекаются.
// Колл-центр с общим пулом клиентов даёт похожий шаблон, но пересекающиеся списки — веером не считается.
func Analyze(profiles []window.Profile, cfg Config) *Index {
	cfg.defaults()
	cohorts := make(map[cohortKey][]*window.Profile)
	for i := range profiles {
		p := &profiles[i]
		if int(p.Calls) < cfg.MinCalls || len(p.Peers) == 0 {
			continue
		}
		if p.UnansweredShr < cfg.MinUnanswer && p.MeanDurSec > cfg.MaxMeanDur {
			continue // нормальный шаблон: разговоры, а не «прозвон»
		}
		k := cohortOf(p)
		cohorts[k] = append(cohorts[k], p)
	}
	ix := &Index{m: make(map[uint64]FanInfo)}
	for _, members := range cohorts {
		if len(members) < cfg.MinGroup {
			continue
		}
		total := 0
		union := make(map[uint64]struct{}, 256)
		var calls uint32
		gid := members[0].Key
		for _, p := range members {
			total += len(p.Peers)
			for _, peer := range p.Peers {
				union[peer] = struct{}{}
			}
			calls += p.Calls
			if p.Key < gid {
				gid = p.Key
			}
		}
		disjoint := float32(len(union)) / float32(total)
		if disjoint < cfg.MinDisjoint {
			continue
		}
		fi := FanInfo{GroupID: gid, Size: uint16(min(len(members), math.MaxUint16)), Disjoint: disjoint, Calls: calls}
		for _, p := range members {
			ix.m[p.Key] = fi
		}
	}
	return ix
}

// Holder — атомарный держатель актуального индекса.
type Holder struct {
	p atomic.Pointer[Index]
}

// Store публикует новый индекс.
func (h *Holder) Store(ix *Index) { h.p.Store(ix) }

// Lookup ищет номер в текущем индексе (пустой индекс — не найден).
func (h *Holder) Lookup(key uint64) (FanInfo, bool) { return h.p.Load().Lookup(key) }

// Index возвращает текущий индекс (может быть nil).
func (h *Holder) Index() *Index { return h.p.Load() }
