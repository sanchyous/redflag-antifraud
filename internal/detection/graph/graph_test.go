package graph

import (
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/detection/window"
)

// profile строит профиль звонящего с n получателями из непересекающегося диапазона base+.
func fanMember(key uint64, base uint64, n int, dur, gap float32) window.Profile {
	peers := make([]uint64, n)
	for i := range peers {
		peers[i] = base + uint64(i)
	}
	return window.Profile{Key: key, Calls: uint32(n), Peers: peers, UnansweredShr: 0.6, MeanDurSec: dur, GapMeanSec: gap}
}

func TestFanDetected(t *testing.T) {
	var ps []window.Profile
	for i := 0; i < 8; i++ { // 8 номеров, шаблон: 3 с, каждые 20 с, непересекающиеся списки по 30
		ps = append(ps, fanMember(uint64(1000+i), uint64(i)*10_000, 30, 3, 20))
	}
	ix := Analyze(ps, Config{})
	if ix.Groups() != 1 || ix.Members() != 8 {
		t.Fatalf("groups=%d members=%d", ix.Groups(), ix.Members())
	}
	fi, ok := ix.Lookup(1003)
	if !ok || fi.Size != 8 || fi.GroupID != 1000 || fi.Disjoint != 1 || fi.Calls != 240 {
		t.Fatalf("info = %+v ok=%v", fi, ok)
	}
	if _, ok := ix.Lookup(42); ok {
		t.Fatal("unrelated number must not be in the fan")
	}
}

func TestCallCenterSharedPoolIsNotFan(t *testing.T) {
	var ps []window.Profile
	for i := 0; i < 8; i++ { // тот же шаблон, но все обзванивают один и тот же пул из 40 клиентов
		ps = append(ps, fanMember(uint64(2000+i), 500_000, 40, 3, 20))
	}
	if ix := Analyze(ps, Config{}); ix.Groups() != 0 {
		t.Fatalf("call center with shared pool flagged as fan: %d groups", ix.Groups())
	}
}

func TestSmallGroupAndLowActivityIgnored(t *testing.T) {
	var ps []window.Profile
	for i := 0; i < 3; i++ { // группа меньше MinGroup
		ps = append(ps, fanMember(uint64(3000+i), uint64(i)*10_000, 30, 3, 20))
	}
	for i := 0; i < 10; i++ { // мало вызовов
		ps = append(ps, fanMember(uint64(4000+i), uint64(100_000+i*100), 5, 3, 20))
	}
	if ix := Analyze(ps, Config{}); ix.Groups() != 0 {
		t.Fatalf("groups = %d", ix.Groups())
	}
}

func TestDifferentTemplatesSeparateGroups(t *testing.T) {
	var ps []window.Profile
	for i := 0; i < 5; i++ {
		ps = append(ps, fanMember(uint64(5000+i), uint64(i)*10_000, 30, 3, 20))
	}
	for i := 0; i < 5; i++ { // другой ритм и длительность → другая когорта
		ps = append(ps, fanMember(uint64(6000+i), 1_000_000+uint64(i)*10_000, 30, 90, 600))
	}
	ix := Analyze(ps, Config{})
	if ix.Groups() != 2 || ix.Members() != 10 {
		t.Fatalf("groups=%d members=%d", ix.Groups(), ix.Members())
	}
	a, _ := ix.Lookup(5000)
	b, _ := ix.Lookup(6000)
	if a.GroupID == b.GroupID {
		t.Fatal("different templates must give different groups")
	}
}

func TestHeavyButNormalCallersNoFan(t *testing.T) {
	// Активные люди/менеджеры: много вызовов, разные адресаты, но длинные принятые разговоры.
	var ps []window.Profile
	for i := 0; i < 50; i++ {
		p := fanMember(uint64(9500+i), uint64(i)*10_000, 40, 120, 30)
		p.UnansweredShr = 0.1
		ps = append(ps, p)
	}
	if ix := Analyze(ps, Config{}); ix.Groups() != 0 {
		t.Fatalf("normal heavy callers flagged: %d groups", ix.Groups())
	}
}

func TestShortCallsPatternQualifiesEvenIfAnswered(t *testing.T) {
	var ps []window.Profile
	for i := 0; i < 6; i++ {
		p := fanMember(uint64(9700+i), uint64(i)*10_000, 40, 4, 15)
		p.UnansweredShr = 0.1 // все берут трубку, но разговор 4 с
		ps = append(ps, p)
	}
	if ix := Analyze(ps, Config{}); ix.Groups() != 1 {
		t.Fatalf("groups = %d", ix.Groups())
	}
}

func TestRandomHumansNoFan(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	var ps []window.Profile
	for i := 0; i < 200; i++ {
		ps = append(ps, fanMember(uint64(7000+i), uint64(i)*1000, 10+r.IntN(20), float32(20+r.IntN(300)), float32(60+r.IntN(3000))))
		ps[i].UnansweredShr = float32(r.Float64() * 0.4)
	}
	// люди звонят частично одним и тем же (семья/коллеги): пересечения
	for i := range ps {
		ps[i].Peers = append(ps[i].Peers, 9_000_000, 9_000_001, 9_000_002)
	}
	if ix := Analyze(ps, Config{}); ix.Groups() != 0 {
		t.Fatalf("humans flagged: %d groups, %d members", ix.Groups(), ix.Members())
	}
}

func TestEmptyIndexAndHolder(t *testing.T) {
	var ix *Index
	if _, ok := ix.Lookup(1); ok || ix.Groups() != 0 || ix.Members() != 0 {
		t.Fatal("nil index must be empty")
	}
	var h Holder
	if _, ok := h.Lookup(1); ok {
		t.Fatal("empty holder must not find")
	}
	var ps []window.Profile
	for i := 0; i < 5; i++ {
		ps = append(ps, fanMember(uint64(8000+i), uint64(i)*10_000, 30, 3, 20))
	}
	h.Store(Analyze(ps, Config{}))
	if _, ok := h.Lookup(8002); !ok || h.Index().Groups() != 1 {
		t.Fatal("holder must serve stored index")
	}
}

func TestHolderConcurrent(t *testing.T) {
	var h Holder
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				var ps []window.Profile
				for j := 0; j < 5; j++ {
					ps = append(ps, fanMember(uint64(j), uint64(j)*10_000, 20, 3, 20))
				}
				h.Store(Analyze(ps, Config{}))
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				h.Lookup(uint64(i % 5))
			}
		}()
	}
	wg.Wait()
}

func TestSubscribers(t *testing.T) {
	s := NewSubscribers(0)
	if s.Observe(0, 1) != 0 || s.Count(0) != 0 {
		t.Fatal("unknown subscriber must give 0")
	}
	for n := uint64(1); n <= 5; n++ {
		if got := s.Observe(42, n); got != int(n) {
			t.Fatalf("after %d numbers got %d", n, got)
		}
	}
	if s.Observe(42, 3) != 5 || s.Count(42) != 5 { // повтор не увеличивает
		t.Fatal("repeat must not grow")
	}
	for n := uint64(100); n < 300; n++ {
		s.Observe(42, n)
	}
	if s.Count(42) != maxNumsPerSub {
		t.Fatalf("cap: %d", s.Count(42))
	}
	small := NewSubscribers(64) // 2 на шард
	for i := uint64(1); i < 5000; i++ {
		small.Observe(i, i)
	}
	total := 0
	for i := range small.shards {
		total += len(small.shards[i].m)
	}
	if total > 64*3 {
		t.Fatalf("eviction: %d", total)
	}
}

func TestBucketLog2(t *testing.T) {
	if bucketLog2(0) != 0 || bucketLog2(-1) != 0 || bucketLog2(3) != 2 || bucketLog2(90) != 7 {
		t.Fatalf("buckets: %d %d %d", bucketLog2(3), bucketLog2(90), bucketLog2(0))
	}
}
