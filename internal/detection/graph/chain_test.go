package graph

import (
	"fmt"
	"testing"
)

func TestChainEdgesObserveAndSnapshot(t *testing.T) {
	e := NewChainEdges(0)
	e.Observe(0, 5) // from=0 должен игнорироваться
	e.Observe(1, 0) // to=0 должен игнорироваться
	e.Observe(1, 2)
	e.Observe(1, 3) // статичная цель: перезаписывает предыдущую
	snap := e.Snapshot()
	if len(snap) != 1 || snap[1] != 3 {
		t.Fatalf("snapshot = %v", snap)
	}

	small := NewChainEdges(64)
	for i := uint64(1); i < 5000; i++ {
		small.Observe(i, i+1)
	}
	total := 0
	for i := range small.shards {
		total += len(small.shards[i].m)
	}
	if total > 64*3 {
		t.Fatalf("eviction: %d", total)
	}
}

func TestAnalyzeChainsMultiHop(t *testing.T) {
	// B(1) → C(2) → D(3) → E(4): цепочка из 4 узлов.
	edges := map[uint64]uint64{1: 2, 2: 3, 3: 4}
	ix := AnalyzeChains(edges, 10)
	for _, n := range []uint64{1, 2, 3, 4} {
		ci, ok := ix.Lookup(n)
		if !ok || ci.Depth != 4 || ci.Ring {
			t.Fatalf("node %d: %+v ok=%v", n, ci, ok)
		}
	}
	if ix.Members() != 4 {
		t.Fatalf("members = %d", ix.Members())
	}
}

func TestAnalyzeChainsSingleHopIsNotFlagged(t *testing.T) {
	// Один обычный переадресующий номер (например, личная переадресация) — не цепочка.
	edges := map[uint64]uint64{1: 2}
	ix := AnalyzeChains(edges, 10)
	if ix.Members() != 0 {
		t.Fatalf("single hop must not be flagged: %d members", ix.Members())
	}
}

func TestAnalyzeChainsRingClosure(t *testing.T) {
	// 1 → 2 → 3 → 1: кольцо.
	edges := map[uint64]uint64{1: 2, 2: 3, 3: 1}
	ix := AnalyzeChains(edges, 10)
	ci, ok := ix.Lookup(1)
	if !ok || !ci.Ring {
		t.Fatalf("ring not detected: %+v ok=%v", ci, ok)
	}
}

func TestAnalyzeChainsHubIsLegitHotline(t *testing.T) {
	// 20 разных номеров переадресуют на один и тот же C(999) — горячая линия (D4), не цепочка.
	edges := make(map[uint64]uint64, 20)
	for i := uint64(1); i <= 20; i++ {
		edges[i] = 999
	}
	ix := AnalyzeChains(edges, 10)
	if ix.Members() != 0 {
		t.Fatalf("hub fan-in must not be flagged as a chain: %d members", ix.Members())
	}

	// Длинный путь, упирающийся в хаб: 22 → 21 → 1 → hub(999). Путь из трёх узлов (22,21,1)
	// должен попасть в индекс как цепочка, а сам хаб — нет (это узел сбора, не звено).
	edges[21] = 1
	edges[22] = 21
	ix = AnalyzeChains(edges, 10)
	if _, ok := ix.Lookup(999); ok {
		t.Fatal("hub itself must never be a chain member")
	}
	ci, ok := ix.Lookup(22)
	if !ok || ci.Depth != 3 {
		t.Fatalf("path truncated at hub must still flag its own members: %+v ok=%v", ci, ok)
	}
}

func TestChainHolderNilIsSafe(t *testing.T) {
	var h ChainHolder
	if _, ok := h.Lookup(1); ok {
		t.Fatal("empty holder must report not-found")
	}
	if h.Index() != nil {
		t.Fatal("empty holder index must be nil")
	}
}

func TestAnalyzeChainsListReturnsPathsLongestFirst(t *testing.T) {
	edges := map[uint64]uint64{
		1: 2, 2: 3, // путь из 3
		10: 11, 11: 12, 12: 13, 13: 14, // путь из 5
	}
	ix := AnalyzeChains(edges, 10)
	list := ix.List()
	if len(list) != 2 {
		t.Fatalf("chains = %d, want 2", len(list))
	}
	if len(list[0].Path) != 5 || len(list[1].Path) != 3 {
		t.Fatalf("not sorted longest-first: %v / %v", list[0].Path, list[1].Path)
	}
	if list[0].Ring || list[1].Ring {
		t.Fatalf("neither chain is a ring: %+v", list)
	}
}

func TestAnalyzeChainsListMarksRing(t *testing.T) {
	edges := map[uint64]uint64{1: 2, 2: 3, 3: 1}
	ix := AnalyzeChains(edges, 10)
	list := ix.List()
	if len(list) != 1 || !list[0].Ring {
		t.Fatalf("ring not reflected in List(): %+v", list)
	}
}

func TestAnalyzeChainsNoDuplicateFragmentsBelowHubThreshold(t *testing.T) {
	// Регрессия: несколько независимых источников (1..5) переадресуют на один и тот же C(100),
	// ниже порога хаба (5 < 10) — C не хаб, обход продолжается через него дальше (100 → 200 → 300).
	// Карта в Go перебирается в неопределённом порядке: раньше любой из 1..5 мог случайно стать
	// стартом ПОСЛЕ того, как через C уже прошёл другой источник, и путь C→200→300 задваивался.
	edges := map[uint64]uint64{
		1: 100, 2: 100, 3: 100, 4: 100, 5: 100,
		100: 200, 200: 300,
	}
	ix := AnalyzeChains(edges, 10)
	list := ix.List()
	seen := map[uint64]int{}
	for _, c := range list {
		for _, n := range c.Path {
			seen[n]++
		}
	}
	for n, c := range seen {
		if c > 1 {
			t.Fatalf("node %d appears in %d chains, want at most 1: %+v", n, c, list)
		}
	}
	if seen[300] != 1 {
		t.Fatalf("tail node 300 must be reachable through exactly one chain: %+v", list)
	}
}

// Регрессия: AnalyzeChains решает, какой из нескольких равнозначных стартов (1..5 выше) «застолбит»
// общий хвост, по порядку starts — а он без сортировки наследовал неопределённый порядок обхода
// карты edges. Официальный ответ кейса (cmd/cdrflag) гонится один раз, но должен быть
// воспроизводим: повторный прогон на тех же данных обязан дать тот же список номеров, не просто
// тот же по размеру. Строим одинаковые по содержимому, но физически разные map (разные литералы —
// у Go нет гарантии, что обход двух независимых map с одинаковыми ключами в одном процессе даст
// одинаковый порядок), прогоняем много раз и сравниваем сериализованный результат.
func TestAnalyzeChainsDeterministicAcrossRuns(t *testing.T) {
	edgesOf := func() map[uint64]uint64 {
		return map[uint64]uint64{
			1: 100, 2: 100, 3: 100, 4: 100, 5: 100,
			100: 200, 200: 300,
			10: 20, 20: 30, 30: 10, // чистое кольцо — второй проход
		}
	}
	serialize := func(ix *ChainIndex) string {
		s := ""
		for _, c := range ix.List() {
			s += fmt.Sprintf("%v|", c.Path)
		}
		return s
	}
	want := serialize(AnalyzeChains(edgesOf(), 10))
	for i := 0; i < 20; i++ {
		got := serialize(AnalyzeChains(edgesOf(), 10))
		if got != want {
			t.Fatalf("run %d: non-deterministic chain list\n want=%s\n got =%s", i, want, got)
		}
	}
}
