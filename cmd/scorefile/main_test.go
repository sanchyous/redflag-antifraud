package main

import "testing"

// TestConfTally — ошибка здесь означала бы неверную долю ложных срабатываний на защите перед жюри
// (именно тот показатель, на который в ТЗ явный акцент), поэтому разобрано по каждой клетке матрицы.
func TestConfTally(t *testing.T) {
	var c conf
	c.tally(true, true)   // tp: мошеннический, отмечен
	c.tally(true, false)  // fn: мошеннический, пропущен
	c.tally(false, true)  // fp: легитимный, ошибочно отмечен
	c.tally(false, false) // tn: легитимный, не отмечен
	c.tally(false, false)
	want := conf{tp: 1, fn: 1, fp: 1, tn: 2}
	if c != want {
		t.Fatalf("got %+v, want %+v", c, want)
	}
}

func TestConfRecallAndFPR(t *testing.T) {
	c := conf{tp: 97, fn: 3, fp: 8, tn: 992}
	if got := c.recall(); got < 0.969 || got > 0.971 {
		t.Fatalf("recall = %v, want ~0.97", got)
	}
	if got := c.fpr(); got < 0.0079 || got > 0.0081 {
		t.Fatalf("fpr = %v, want ~0.008", got)
	}
}

func TestConfEmptyIsZeroNotNaN(t *testing.T) {
	var c conf
	if c.recall() != 0 {
		t.Fatalf("recall of empty conf = %v, want 0 (not NaN from 0/0)", c.recall())
	}
	if c.fpr() != 0 {
		t.Fatalf("fpr of empty conf = %v, want 0 (not NaN from 0/0)", c.fpr())
	}
}

func TestConfAllFraudNoLegit(t *testing.T) {
	c := conf{tp: 5, fn: 0}
	if c.recall() != 1 {
		t.Fatalf("recall = %v, want 1", c.recall())
	}
	if c.fpr() != 0 { // 0/0: не должно давать ложное впечатление ненулевого FPR
		t.Fatalf("fpr = %v, want 0", c.fpr())
	}
}
