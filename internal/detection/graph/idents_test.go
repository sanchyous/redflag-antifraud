package graph

import "testing"

func TestIdents(t *testing.T) {
	s := NewIdents(0)
	if s.Observe(42, 0) != 0 || s.Count(42) != 0 {
		t.Fatal("unknown IMSI must give 0 and not count")
	}
	for n := uint64(1); n <= 5; n++ {
		if got := s.Observe(42, n); got != int(n) {
			t.Fatalf("after %d IMSI got %d", n, got)
		}
	}
	if s.Observe(42, 3) != 5 || s.Count(42) != 5 { // повтор не увеличивает
		t.Fatal("repeat IMSI must not grow")
	}
	if s.Count(43) != 0 {
		t.Fatal("unrelated number must be 0")
	}
	for n := uint64(100); n < 300; n++ {
		s.Observe(42, n)
	}
	if s.Count(42) != maxImsiPerNum {
		t.Fatalf("cap: %d", s.Count(42))
	}

	small := NewIdents(64) // 2 на шард
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
