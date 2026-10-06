package api

import "testing"

func TestRateLimiterDisabledByDefault(t *testing.T) {
	l := NewRateLimiter(0)
	if l.Enabled() {
		t.Fatal("perSecond=0 must be disabled")
	}
	for i := 0; i < 1000; i++ {
		if !l.AllowN("k", 1) {
			t.Fatal("disabled limiter must always allow")
		}
	}
}

func TestRateLimiterAllowsUpToLimitPerSecond(t *testing.T) {
	sec := int64(1000)
	l := NewRateLimiter(3)
	l.now = func() int64 { return sec }
	for i := 0; i < 3; i++ {
		if !l.AllowN("k", 1) {
			t.Fatalf("call %d should be allowed within limit", i)
		}
	}
	if l.AllowN("k", 1) {
		t.Fatal("4th call in the same second must be rejected")
	}
	sec++ // новая секунда — счётчик сбрасывается
	if !l.AllowN("k", 1) {
		t.Fatal("must be allowed again in the next second")
	}
}

func TestRateLimiterKeysAreIndependent(t *testing.T) {
	l := NewRateLimiter(1)
	l.now = func() int64 { return 42 }
	if !l.AllowN("a", 1) || !l.AllowN("b", 1) {
		t.Fatal("different keys must not share a budget")
	}
	if l.AllowN("a", 1) {
		t.Fatal("key a already used its budget")
	}
}

func TestRateLimiterAllowNCost(t *testing.T) {
	l := NewRateLimiter(10)
	l.now = func() int64 { return 1 }
	if !l.AllowN("k", 7) {
		t.Fatal("7 of 10 should fit")
	}
	if l.AllowN("k", 7) {
		t.Fatal("7+7=14 > 10 must be rejected")
	}
}
