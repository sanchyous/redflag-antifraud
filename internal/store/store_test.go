package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// Интеграционный тест: требует реальный Postgres. Локально пропускается,
// в CI поднимается service-контейнер и TEST_DATABASE_URL задаётся в env.
func TestSaveAndRecent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rec := Record{
		RequestID:     "req-test-1",
		TransactionID: "txn-test-1",
		UserID:        "u-test",
		Amount:        1500.50,
		Currency:      "RUB",
		IP:            "10.1.2.3",
		Decision:      "review",
		Reasons:       []string{"velocity_user_limit"},
		LatencyMS:     7,
	}
	if err := s.Save(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}

	entries, err := s.Recent(ctx, 10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("want at least one entry")
	}
	got := entries[0]
	if got.TransactionID != rec.TransactionID || got.Decision != rec.Decision {
		t.Fatalf("latest entry mismatch: %+v", got)
	}
	if len(got.Reasons) != 1 || got.Reasons[0] != "velocity_user_limit" {
		t.Fatalf("reasons mismatch: %v", got.Reasons)
	}
}
