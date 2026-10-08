package graph

import "testing"

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
