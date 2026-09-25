// Package rules — L1: мгновенные детерминированные проверки (blacklist, лимиты).
package rules

import (
	"github.com/sanchyous/redflag-antifraud/internal/decision"
)

// Config собирается из env на старте (см. cmd/decision-api).
type Config struct {
	MaxAmount         float64
	AllowedCurrencies []string
	BlockedUsers      []string
	BlockedIPs        []string
}

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, it := range items {
		set[it] = struct{}{}
	}
	return set
}

// Check возвращает причины срабатывания L1. Пустой список — L1 пройдена.
func (c Config) Check(t decision.Txn) []string {
	var reasons []string

	users := toSet(c.BlockedUsers)
	if _, bad := users[t.UserID]; bad {
		reasons = append(reasons, "user_blacklisted")
	}
	ips := toSet(c.BlockedIPs)
	if _, bad := ips[t.IP]; bad {
		reasons = append(reasons, "ip_blacklisted")
	}
	if c.MaxAmount > 0 && t.Amount > c.MaxAmount {
		reasons = append(reasons, "amount_over_limit")
	}
	if len(c.AllowedCurrencies) > 0 {
		currencies := toSet(c.AllowedCurrencies)
		if _, ok := currencies[t.Currency]; !ok {
			reasons = append(reasons, "currency_not_allowed")
		}
	}
	return reasons
}
