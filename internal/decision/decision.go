// Package decision содержит общую модель транзакции и вердикта.
package decision

import "time"

// Geo — приблизительная геолокация транзакции (для impossible travel, фаза 2).
type Geo struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// Txn — входящая транзакция на проверку.
type Txn struct {
	TransactionID string    `json:"transaction_id"`
	UserID        string    `json:"user_id"`
	Amount        float64   `json:"amount"`
	Currency      string    `json:"currency"`
	IP            string    `json:"ip"`
	Geo           Geo       `json:"geo"`
	TS            time.Time `json:"ts"`
}

// Решения.
const (
	Allow  = "allow"
	Review = "review"
	Deny   = "deny"
)

// Verdict — итог pipeline по одной транзакции.
type Verdict struct {
	RequestID     string   `json:"request_id"`
	TransactionID string   `json:"transaction_id"`
	UserID        string   `json:"user_id"`
	Decision      string   `json:"decision"`
	Reasons       []string `json:"reasons"`
	LatencyMS     int64    `json:"latency_ms"`
}

// Validate — структурная целостность входа (не антифрод, а контракта).
func (t Txn) Validate() []string {
	var errs []string
	if t.TransactionID == "" {
		errs = append(errs, "transaction_id_required")
	}
	if t.UserID == "" {
		errs = append(errs, "user_id_required")
	}
	if t.Amount < 0 {
		errs = append(errs, "amount_negative")
	}
	if t.IP == "" {
		errs = append(errs, "ip_required")
	}
	return errs
}
