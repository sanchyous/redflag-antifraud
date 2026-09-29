package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// Интеграционный тест: включается через TEST_DATABASE_URL (в CI поднимается Postgres).
func TestSaveBatchAndRecent(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.pool.Exec(ctx, "TRUNCATE call_decisions"); err != nil {
		t.Fatal(err)
	}

	recs := []Record{
		{CallID: "a", CallerMasked: "+7 495 ***-**-12", CalleeMasked: "+7 916 ***-**-83", Decision: "review", Score: 0.31,
			Reasons: json.RawMessage(`[{"factor":"spoof"}]`), Signals: []string{"spoof"}, ModelVersion: "m1"},
		{CallID: "b", CallerMasked: "+7 916 ***-**-01", CalleeMasked: "+7 495 ***-**-02", Decision: "allow", Score: 0.001},
		{CallID: "a", CallerMasked: "dup", CalleeMasked: "dup", Decision: "block", Score: 1}, // дубль call_id
	}
	if err := s.SaveBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBatch(ctx, nil); err != nil {
		t.Fatal(err)
	}
	all, err := s.Recent(ctx, 10, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("Recent = %d rows, err=%v (дубль call_id не должен писаться)", len(all), err)
	}
	if all[1].CallID != "a" || all[1].Decision != "review" || all[1].Signals[0] != "spoof" {
		t.Fatalf("first record must survive the duplicate: %+v", all[1])
	}
	only, err := s.Recent(ctx, 10, "review")
	if err != nil || len(only) != 1 || only[0].CallID != "a" {
		t.Fatalf("filter by decision: %+v err=%v", only, err)
	}
	if all[0].Signals == nil || string(all[0].Reasons) != "[]" {
		t.Fatalf("defaults for empty signals/reasons: %+v", all[0])
	}
}

// Регрессия: сервис перезапускается при каждом деплое, схема должна применяться повторно без ошибки.
// (Раньше второй запуск падал: relation "call_decisions_call_id_unique" already exists.)
func TestOpenIsRepeatable(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		s, err := Open(ctx, url)
		if err != nil {
			t.Fatalf("Open #%d: %v", i+1, err)
		}
		s.Close()
	}
}

func TestItoa(t *testing.T) {
	for in, want := range map[int]string{0: "0", -5: "0", 7: "7", 100: "100", 1234567: "1234567"} {
		if got := itoa(in); got != want {
			t.Fatalf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}
