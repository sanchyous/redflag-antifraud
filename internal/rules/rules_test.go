package rules

import (
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/decision"
)

func baseTxn() decision.Txn {
	return decision.Txn{
		TransactionID: "t-1",
		UserID:        "u-1",
		Amount:        1000,
		Currency:      "RUB",
		IP:            "10.0.0.1",
	}
}

func TestCheck(t *testing.T) {
	cfg := Config{
		MaxAmount:         10000,
		AllowedCurrencies: []string{"RUB", "USD"},
		BlockedUsers:      []string{"bad-user"},
		BlockedIPs:        []string{"6.6.6.6"},
	}

	cases := []struct {
		name        string
		mutate      func(t *decision.Txn)
		wantReasons []string
	}{
		{"clean pass", func(t *decision.Txn) {}, nil},
		{"user blacklisted", func(t *decision.Txn) { t.UserID = "bad-user" }, []string{"user_blacklisted"}},
		{"ip blacklisted", func(t *decision.Txn) { t.IP = "6.6.6.6" }, []string{"ip_blacklisted"}},
		{"amount over limit", func(t *decision.Txn) { t.Amount = 10001 }, []string{"amount_over_limit"}},
		{"currency not allowed", func(t *decision.Txn) { t.Currency = "GBP" }, []string{"currency_not_allowed"}},
		{"multiple hits", func(t *decision.Txn) {
			t.UserID = "bad-user"
			t.Amount = 999999
		}, []string{"user_blacklisted", "amount_over_limit"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			txn := baseTxn()
			tc.mutate(&txn)
			got := cfg.Check(txn)
			if len(got) != len(tc.wantReasons) {
				t.Fatalf("reasons = %v, want %v", got, tc.wantReasons)
			}
			for i := range got {
				if got[i] != tc.wantReasons[i] {
					t.Fatalf("reasons = %v, want %v", got, tc.wantReasons)
				}
			}
		})
	}
}

func TestCheckEmptyConfigPasses(t *testing.T) {
	var cfg Config // ничего не сконфигурировано — L1 не должна отсекать
	if got := cfg.Check(baseTxn()); len(got) != 0 {
		t.Fatalf("empty config must pass, got %v", got)
	}
}
