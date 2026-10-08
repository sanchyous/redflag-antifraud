package graph

import (
	"sync"
	"sync/atomic"
)

const (
	chainEdgeShards = 64
	maxChainEdges   = 2_000_000
)

// ChainEdges копит переадресации Callee→ForwardTo (из записей с Direction == DirForwarded).
// Переадресация на номере обычно статична (одна и та же цель раз за разом — «на работе
// переводи на мобильный»), поэтому держим только последнюю цель на номер: O(номеров) памяти,
// не O(вызовов).
type ChainEdges struct {
	shards [chainEdgeShards]struct {
		mu sync.Mutex
		m  map[uint64]uint64
	}
	maxPerShard int
}

// NewChainEdges создаёt хранилище; maxEdges — общий предел (0 → 2 млн).
func NewChainEdges(maxEdges int) *ChainEdges {
	if maxEdges <= 0 {
		maxEdges = maxChainEdges
	}
	e := &ChainEdges{maxPerShard: maxEdges/chainEdgeShards + 1}
	for i := range e.shards {
		e.shards[i].m = make(map[uint64]uint64)
	}
	return e
}

// Observe регистрирует «from переадресует на to» (from — Callee, to — ForwardTo).
func (e *ChainEdges) Observe(from, to uint64) {
	if from == 0 || to == 0 {
		return
	}
	sh := &e.shards[(from*0x9E3779B97F4A7C15)>>58]
	sh.mu.Lock()
	if _, ok := sh.m[from]; !ok && len(sh.m) >= e.maxPerShard {
		for k := range sh.m {
			delete(sh.m, k)
			break
		}
	}
	sh.m[from] = to
	sh.mu.Unlock()
}

// Snapshot копирует текущую карту рёбер (для периодического анализа).
func (e *ChainEdges) Snapshot() map[uint64]uint64 {
	out := make(map[uint64]uint64, 1024)
	for i := range e.shards {
		sh := &e.shards[i]
		sh.mu.Lock()
		for k, v := range sh.m {
			out[k] = v
		}
		sh.mu.Unlock()
	}
	return out
}

// ChainInfo — положение номера в цепочке переадресаций.
type ChainInfo struct {
	Depth int  // длина цепочки, в которую входит номер (число узлов)
	Ring  bool // цепочка замыкается сама на себя (кольцо)
}

// ChainIndex — результат анализа графа переадресаций. Неизменяем после создания.
type ChainIndex struct{ m map[uint64]ChainInfo }

// Lookup ищет номер в индексе цепочек.
func (ix *ChainIndex) Lookup(key uint64) (ChainInfo, bool) {
	if ix == nil {
		return ChainInfo{}, false
	}
	ci, ok := ix.m[key]
	return ci, ok
}

// Members — число номеров, входящих хоть в одну цепочку.
func (ix *ChainIndex) Members() int {
	if ix == nil {
		return 0
	}
	return len(ix.m)
}

// HubFanIn — с какого числа различных источников цель переадресации считается легальным узлом
// сбора (единая горячая линия на несколько номеров компании), а не звеном мошеннической цепочки.
const HubFanIn = 10

// AnalyzeChains строит индекс участников многошаговых цепочек переадресации: обходит
// статический граф Callee→ForwardTo и помечает узлы цепочек длиной от 2 переходов (3 узла).
// Переадресации на «узел сбора» (fan-in ≥ hubFanIn — легальная горячая линия на несколько
// номеров компании, D4 в материалах кейса) обрывают цепочку и сам узел сбора в индекс не
// попадает: это не мошенничество, это точка приёма.
func AnalyzeChains(edges map[uint64]uint64, hubFanIn int) *ChainIndex {
	if hubFanIn <= 0 {
		hubFanIn = HubFanIn
	}
	indeg := make(map[uint64]int, len(edges))
	for _, to := range edges {
		indeg[to]++
	}
	hubs := make(map[uint64]struct{})
	for to, n := range indeg {
		if n >= hubFanIn {
			hubs[to] = struct{}{}
		}
	}

	ix := &ChainIndex{m: make(map[uint64]ChainInfo)}
	visited := make(map[uint64]struct{}, len(edges))
	for start := range edges {
		if _, done := visited[start]; done {
			continue
		}
		path := []uint64{start}
		seen := map[uint64]struct{}{start: {}}
		ring := false
		cur := start
		for {
			next, ok := edges[cur]
			if !ok {
				break
			}
			if _, isHub := hubs[next]; isHub {
				break // легальный узел сбора: в путь не включаем, цепочку обрываем
			}
			if _, loop := seen[next]; loop {
				ring = true
				break // кольцо: дальше идти некуда, но путь уже содержит next
			}
			path = append(path, next)
			seen[next] = struct{}{}
			cur = next
		}
		for _, n := range path {
			visited[n] = struct{}{}
		}
		if len(path) >= 3 {
			for _, n := range path {
				ix.m[n] = ChainInfo{Depth: len(path), Ring: ring}
			}
		}
	}
	return ix
}

// ChainHolder — атомарный держатель актуального индекса цепочек переадресации.
type ChainHolder struct {
	p atomic.Pointer[ChainIndex]
}

// Store публикует новый индекс.
func (c *ChainHolder) Store(ix *ChainIndex) { c.p.Store(ix) }

// Lookup ищет номер в текущем индексе.
func (c *ChainHolder) Lookup(key uint64) (ChainInfo, bool) { return c.p.Load().Lookup(key) }

// Index возвращает текущий индекс (может быть nil).
func (c *ChainHolder) Index() *ChainIndex { return c.p.Load() }
