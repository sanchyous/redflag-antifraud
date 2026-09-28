package journal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/store"
)

type fakeSink struct {
	mu      sync.Mutex
	batches [][]store.Record
	err     error
	block   chan struct{}
}

func (f *fakeSink) SaveBatch(ctx context.Context, recs []store.Record) error {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.batches = append(f.batches, append([]store.Record(nil), recs...))
	return nil
}

func (f *fakeSink) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func TestBatchesAndFlushOnClose(t *testing.T) {
	s := &fakeSink{}
	j := New(s, Config{BatchSize: 10, FlushEvery: time.Hour}, nil)
	for i := 0; i < 25; i++ {
		j.Add(store.Record{CallID: fmt.Sprint(i)})
	}
	j.Close() // остаток дописывается при закрытии
	if s.total() != 25 || j.Written.Load() != 25 {
		t.Fatalf("written %d / metric %d", s.total(), j.Written.Load())
	}
	for _, b := range s.batches {
		if len(b) > 10 {
			t.Fatalf("batch of %d exceeds BatchSize", len(b))
		}
	}
}

func TestPeriodicFlush(t *testing.T) {
	s := &fakeSink{}
	j := New(s, Config{FlushEvery: 10 * time.Millisecond}, nil)
	defer j.Close()
	j.Add(store.Record{CallID: "x"})
	deadline := time.Now().Add(2 * time.Second)
	for s.total() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.total() != 1 {
		t.Fatal("periodic flush did not write the record")
	}
}

func TestOverflowDropsWithoutBlocking(t *testing.T) {
	s := &fakeSink{block: make(chan struct{})}
	j := New(s, Config{Buffer: 4, BatchSize: 1, FlushEvery: time.Hour}, nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			j.Add(store.Record{CallID: fmt.Sprint(i)})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Add blocked on a stalled sink")
	}
	if j.Dropped.Load() == 0 {
		t.Fatal("overflow must be counted")
	}
	close(s.block)
	j.Close()
}

func TestSinkErrorCounted(t *testing.T) {
	s := &fakeSink{err: errors.New("db down")}
	j := New(s, Config{BatchSize: 2, FlushEvery: time.Hour}, nil)
	j.Add(store.Record{CallID: "1"})
	j.Add(store.Record{CallID: "2"})
	j.Close()
	if j.Failed.Load() != 2 || j.Written.Load() != 0 {
		t.Fatalf("failed=%d written=%d", j.Failed.Load(), j.Written.Load())
	}
}

func TestWants(t *testing.T) {
	none := &Journal{cfg: Config{}}
	if !none.Wants("review", "a") || !none.Wants("block", "a") || none.Wants("allow", "a") {
		t.Fatal("default: only flagged decisions")
	}
	all := &Journal{cfg: Config{AllowSample: 1}}
	if !all.Wants("allow", "a") {
		t.Fatal("sample=1 must keep every allow")
	}
	half := &Journal{cfg: Config{AllowSample: 0.5}}
	kept := 0
	for i := 0; i < 10000; i++ {
		id := fmt.Sprint("call-", i)
		w := half.Wants("allow", id)
		if w != half.Wants("allow", id) {
			t.Fatal("sampling must be deterministic per call_id")
		}
		if w {
			kept++
		}
	}
	if kept < 4500 || kept > 5500 {
		t.Fatalf("sample 0.5 kept %d of 10000", kept)
	}
}
