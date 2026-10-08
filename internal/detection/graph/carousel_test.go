package graph

import (
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/detection/window"
)

// carouselMember строит профиль номера, который звонит только внутри заданного набора peers.
func carouselMember(key uint64, calls uint32, peers []uint64) window.Profile {
	return window.Profile{Key: key, Calls: calls, Peers: peers}
}

func TestAnalyzeCarouselDetectsClosedGroup(t *testing.T) {
	// 5 номеров, каждый звонит только четырём остальным, по 150 вызовов.
	keys := []uint64{10, 11, 12, 13, 14}
	var ps []window.Profile
	for _, k := range keys {
		var peers []uint64
		for _, o := range keys {
			if o != k {
				peers = append(peers, o)
			}
		}
		ps = append(ps, carouselMember(k, 150, peers))
	}
	ix := AnalyzeCarousel(ps, CarouselConfig{})
	if ix.Members() != 5 {
		t.Fatalf("members = %d, want 5", ix.Members())
	}
	info, ok := ix.Lookup(10)
	if !ok || info.Size != 5 {
		t.Fatalf("info = %+v ok=%v", info, ok)
	}
}

func TestAnalyzeCarouselToleratesPassiveMembers(t *testing.T) {
	// Регрессия по находке на официальном датасете кейса: в реальных группах часть участников в
	// основном ПРИНИМАЕТ звонки и сама звонит редко — у них мало или вовсе нет исходящих, поэтому
	// они не проходят MinCalls и не попадают в cand/memberSet. У активных участников такие
	// «молчуны» в списке собеседников считаются утечкой — с MaxLeak=0/1 вся группа отсеивалась
	// (живой прогон находил 5 карусельных номеров вместо ожидаемых по независимому анализу
	// нескольких десятков).
	active := []uint64{10, 11, 12, 13, 14} // пять активных: звонят всем, включая молчунов
	passive := []uint64{20, 21, 22}        // три молчуна: в Profiles вообще не попадают (Calls=0)
	all := append(append([]uint64{}, active...), passive...)
	var ps []window.Profile
	for _, k := range active {
		var peers []uint64
		for _, o := range all {
			if o != k {
				peers = append(peers, o)
			}
		}
		ps = append(ps, carouselMember(k, 150, peers))
	}
	// молчуны в ps не представлены вовсе — Profiles() их бы не вернул (Calls=0 < MinCalls)
	ix := AnalyzeCarousel(ps, CarouselConfig{})
	if ix.Members() != 5 {
		t.Fatalf("active members must still form a carousel despite passive peers: %d members (index=%+v)",
			ix.Members(), ix.m)
	}
	for _, k := range active {
		if _, ok := ix.Lookup(k); !ok {
			t.Fatalf("active member %d must be flagged", k)
		}
	}
}

func TestAnalyzeCarouselRejectsExternalLeakage(t *testing.T) {
	keys := []uint64{20, 21, 22, 23, 24}
	var ps []window.Profile
	for _, k := range keys {
		var peers []uint64
		for _, o := range keys {
			if o != k {
				peers = append(peers, o)
			}
		}
		peers = append(peers, 9000+k, 9001+k, 9002+k) // заметная утечка вовне
		ps = append(ps, carouselMember(k, 150, peers))
	}
	ix := AnalyzeCarousel(ps, CarouselConfig{})
	if ix.Members() != 0 {
		t.Fatalf("leaky group must not be a carousel: %d members", ix.Members())
	}
}

func TestAnalyzeCarouselRejectsTooFewCalls(t *testing.T) {
	keys := []uint64{30, 31, 32, 33, 34}
	var ps []window.Profile
	for _, k := range keys {
		var peers []uint64
		for _, o := range keys {
			if o != k {
				peers = append(peers, o)
			}
		}
		ps = append(ps, carouselMember(k, 5, peers)) // мало вызовов — обычная переписка, не карусель
	}
	ix := AnalyzeCarousel(ps, CarouselConfig{})
	if ix.Members() != 0 {
		t.Fatalf("low-volume group must not be a carousel: %d members", ix.Members())
	}
}

func TestAnalyzeCarouselRejectsGroupTooLarge(t *testing.T) {
	// Полносвязная группа из 20: у каждого участника 19 собеседников — выше MaxPeers по умолчанию,
	// кандидат отсеивается ещё до объединения в группы (обычная большая рабочая группа — не карусель).
	var keys []uint64
	for i := uint64(0); i < 20; i++ {
		keys = append(keys, 100+i)
	}
	var ps []window.Profile
	for _, k := range keys {
		var peers []uint64
		for _, o := range keys {
			if o != k {
				peers = append(peers, o)
			}
		}
		ps = append(ps, carouselMember(k, 150, peers))
	}
	ix := AnalyzeCarousel(ps, CarouselConfig{})
	if ix.Members() != 0 {
		t.Fatalf("oversized group must not be a carousel: %d members", ix.Members())
	}

	// Цепочка перекрывающихся пар: у каждого участника всего 2 собеседника (в пределах MaxPeers),
	// но union-find сольёт всю цепочку в одну группу из 13 узлов — выше MaxGroup.
	var chain []window.Profile
	n := 13
	for i := 0; i < n; i++ {
		var peers []uint64
		if i > 0 {
			peers = append(peers, uint64(200+i-1))
		}
		if i < n-1 {
			peers = append(peers, uint64(200+i+1))
		}
		chain = append(chain, carouselMember(uint64(200+i), 150, peers))
	}
	ix = AnalyzeCarousel(chain, CarouselConfig{})
	if ix.Members() != 0 {
		t.Fatalf("merged group above MaxGroup must not be a carousel: %d members", ix.Members())
	}
}

func TestCarouselHolderNilIsSafe(t *testing.T) {
	var h CarouselHolder
	if _, ok := h.Lookup(1); ok {
		t.Fatal("empty holder must report not-found")
	}
}
