package graph

import (
	"sort"
	"sync/atomic"

	"github.com/sanchyous/redflag-antifraud/internal/detection/window"
)

// CarouselConfig — параметры детектора «карусели»: закрытая группа номеров звонит только друг
// другу. Это зеркало graph.Analyze (веер): там группа ищется по непересекающимся спискам
// получателей (fan-out), здесь — наоборот, по почти полному пересечению в крошечный общий
// пул (clique). Обычный абонент тоже кому-то перезванивает регулярно — отличает карусель
// заметный объём при единицах уникальных собеседников и отсутствие контактов за пределами
// группы.
type CarouselConfig struct {
	MinCalls int // минимум вызовов за период на номер (по умолчанию 100)
	MaxPeers int // максимум уникальных собеседников за весь период (по умолчанию 9)
	MinGroup int // минимальный размер группы (по умолчанию 3)
	MaxGroup int // максимальный размер группы (по умолчанию 12)
	// MaxLeak — сколько уникальных собеседников за пределами группы ещё терпимо (по умолчанию 4).
	// Раньше кандидаты строились только по исходящим, и участник, который в основном ПРИНИМАЕТ
	// звонки внутри группы и сам звонит редко, не набирал MinCalls по одним исходящим и не попадал
	// в кандидаты вовсе — у активных соседей он тогда считался «утечкой», хотя был частью той же
	// группы. Это исправлено на уровне вызывающего кода: RefreshCarousel строит профили по обеим
	// сторонам (window.Store.ProfilesAllDirections), и молчун виден наравне с активными. Запас в
	// MaxLeak остаётся — он больше не компенсирует пропущенных молчунов, а терпит редкие реальные
	// контакты вне группы (ошиблись номером, разовый легитимный звонок).
	MaxLeak int
}

// MinCallsOrDefault возвращает MinCalls с учётом значения по умолчанию.
func (c CarouselConfig) MinCallsOrDefault() int {
	c.defaults()
	return c.MinCalls
}

func (c *CarouselConfig) defaults() {
	if c.MinCalls <= 0 {
		c.MinCalls = 100
	}
	if c.MaxPeers <= 0 {
		c.MaxPeers = 9
	}
	if c.MinGroup <= 0 {
		c.MinGroup = 3
	}
	if c.MaxGroup <= 0 {
		c.MaxGroup = 12
	}
	if c.MaxLeak <= 0 {
		c.MaxLeak = 4
	}
}

// CarouselInfo — принадлежность номера к карусели.
type CarouselInfo struct {
	GroupID uint64
	Size    int
}

// CarouselIndex — результат анализа. Неизменяем после создания.
type CarouselIndex struct{ m map[uint64]CarouselInfo }

// Lookup ищет номер в индексе.
func (ix *CarouselIndex) Lookup(key uint64) (CarouselInfo, bool) {
	if ix == nil {
		return CarouselInfo{}, false
	}
	ci, ok := ix.m[key]
	return ci, ok
}

// CarouselGroup — закрытая группа номеров для панели.
type CarouselGroup struct {
	ID      uint64
	Members []uint64
}

// List возвращает найденные группы, крупные первыми. Аллоцирует на каждый вызов — не горячий
// путь (панель мониторинга).
func (ix *CarouselIndex) List() []CarouselGroup {
	if ix == nil {
		return nil
	}
	byGroup := make(map[uint64][]uint64)
	for k, v := range ix.m {
		byGroup[v.GroupID] = append(byGroup[v.GroupID], k)
	}
	out := make([]CarouselGroup, 0, len(byGroup))
	for gid, members := range byGroup {
		sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
		out = append(out, CarouselGroup{ID: gid, Members: members})
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].Members) > len(out[j].Members) })
	return out
}

// Members — число номеров во всех каруселях.
func (ix *CarouselIndex) Members() int {
	if ix == nil {
		return 0
	}
	return len(ix.m)
}

// AnalyzeCarousel ищет закрытые группы номеров, звонящих только друг другу: кандидаты —
// номера с малым числом уникальных собеседников за весь период при заметном объёме вызовов;
// кандидаты объединяются в группу, если входят в списки собеседников друг друга (union-find);
// группа принимается, если её размер в границах и утечка вовне (уникальные собеседники не
// из группы) не превышает MaxLeak.
func AnalyzeCarousel(profiles []window.Profile, cfg CarouselConfig) *CarouselIndex {
	cfg.defaults()
	cand := make(map[uint64]*window.Profile, 64)
	for i := range profiles {
		p := &profiles[i]
		if int(p.Calls) < cfg.MinCalls || len(p.Peers) == 0 || len(p.Peers) > cfg.MaxPeers {
			continue
		}
		cand[p.Key] = p
	}

	parent := make(map[uint64]uint64, len(cand))
	for k := range cand {
		parent[k] = k
	}
	find := func(x uint64) uint64 {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b uint64) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}
	for k, p := range cand {
		for _, peer := range p.Peers {
			if _, ok := cand[peer]; ok {
				union(k, peer)
			}
		}
	}

	groups := make(map[uint64][]uint64, 16)
	for k := range cand {
		r := find(k)
		groups[r] = append(groups[r], k)
	}

	ix := &CarouselIndex{m: make(map[uint64]CarouselInfo)}
	for gid, members := range groups {
		if len(members) < cfg.MinGroup || len(members) > cfg.MaxGroup {
			continue
		}
		memberSet := make(map[uint64]struct{}, len(members))
		for _, m := range members {
			memberSet[m] = struct{}{}
		}
		leak := make(map[uint64]struct{})
		for _, m := range members {
			for _, peer := range cand[m].Peers {
				if _, in := memberSet[peer]; !in {
					leak[peer] = struct{}{}
				}
			}
		}
		if len(leak) > cfg.MaxLeak {
			continue
		}
		info := CarouselInfo{GroupID: gid, Size: len(members)}
		for _, m := range members {
			ix.m[m] = info
		}
	}
	return ix
}

// CarouselHolder — атомарный держатель актуального индекса карусели.
type CarouselHolder struct{ p atomic.Pointer[CarouselIndex] }

// Store публикует новый индекс.
func (h *CarouselHolder) Store(ix *CarouselIndex) { h.p.Store(ix) }

// Lookup ищет номер в текущем индексе.
func (h *CarouselHolder) Lookup(key uint64) (CarouselInfo, bool) { return h.p.Load().Lookup(key) }

// Index возвращает текущий индекс (может быть nil).
func (h *CarouselHolder) Index() *CarouselIndex { return h.p.Load() }
