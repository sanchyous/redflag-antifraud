// Package decider — оркестратор pipeline: L1 rules → L2 velocity → внешний scorer.
package decider

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision"
	"github.com/sanchyous/redflag-antifraud/internal/rules"
	"github.com/sanchyous/redflag-antifraud/internal/velocity"
)

// HTTPTimeout — таймаут вызова внешнего scorer (клиент собирается в main).
const HTTPTimeout = 2 * time.Second

// decisionRank — порядок строгости: внешний вердикт может только усилить решение.
var decisionRank = map[string]int{decision.Allow: 0, decision.Review: 1, decision.Deny: 2}

type Scorer struct {
	Rules     rules.Config
	Vel       *velocity.Limiter
	ScorerURL string       // пусто — внешний scorer не используется
	HTTP      *http.Client // задаётся при сборке в main; nil — http.DefaultClient
	FailOpen  bool         // true: деградация Redis/scorer не эскалирует вердикт (доступность > детекции)
	Log       *slog.Logger
}

// Evaluate прогоняет транзакцию через уровни и логирует решение.
// Инфраструктурная деградация (Redis/scorer недоступны) не блокирует трафик — уходит reason'ом в вердикт.
// При FAIL_MODE=closed (FailOpen=false) деградация эскалирует вердикт до review.
func (s *Scorer) Evaluate(ctx context.Context, t decision.Txn, requestID string) decision.Verdict {
	start := time.Now()

	var reasons []string
	verdict := decision.Allow
	levels := ""

	// L1: hard rules — любое срабатывание = deny
	if l1 := s.Rules.Check(t); len(l1) > 0 {
		reasons = append(reasons, l1...)
		verdict = decision.Deny
		levels = "l1"
	}

	// Дедуп: повторная транзакция не должна второй раз кормить velocity и scorer.
	duplicate := false
	if s.Vel != nil {
		if seen, _ := s.Vel.MarkSeen(ctx, t.TransactionID); seen {
			reasons = append(reasons, "duplicate_transaction")
			duplicate = true
		}
	}

	// L2: velocity — срабатывание = review
	if !duplicate && verdict != decision.Deny && s.Vel != nil {
		l2, degraded := s.Vel.Check(ctx, t)
		if degraded {
			reasons = append(reasons, "velocity_degraded")
			if !s.FailOpen {
				verdict = decision.Review
			}
		}
		if len(l2) > 0 {
			reasons = append(reasons, l2...)
			verdict = decision.Review
		}
		if levels == "" && (len(l2) > 0 || degraded) {
			levels = "l2"
		}
	}

	// Внешний scorer (сервис на любом стеке): score>=0.8 → review, явный decision уважается
	if !duplicate && verdict != decision.Deny && s.ScorerURL != "" {
		extReason, extDecision, err := s.callExternal(ctx, t)
		if err != nil {
			s.Log.WarnContext(ctx, "external_scorer_error", "request_id", requestID, "err", err.Error())
			reasons = append(reasons, "external_scorer_error")
			if !s.FailOpen {
				verdict = decision.Review
			}
		} else {
			if extReason != "" {
				reasons = append(reasons, extReason)
			}
			// Эскалация по строгости: честный allow от scorer не понижает вердикт,
			// review/deny — усиливают. extDecision нормализован в callExternal.
			if r, ok := decisionRank[extDecision]; ok && r > decisionRank[verdict] {
				verdict = extDecision
			}
		}
	}

	if reasons == nil {
		reasons = []string{} // JSON: [] вместо null
	}

	v := decision.Verdict{
		RequestID:     requestID,
		TransactionID: t.TransactionID,
		UserID:        t.UserID,
		Decision:      verdict,
		Reasons:       reasons,
		LatencyMS:     time.Since(start).Milliseconds(),
	}

	s.logDecision(ctx, t, v)
	return v
}

func (s *Scorer) logDecision(ctx context.Context, t decision.Txn, v decision.Verdict) {
	lvl := slog.LevelInfo
	switch v.Decision {
	case decision.Review:
		lvl = slog.LevelWarn
	case decision.Deny:
		lvl = slog.LevelError
	}
	s.Log.Log(ctx, lvl, "decision",
		"request_id", v.RequestID,
		"transaction_id", v.TransactionID,
		"user_id", v.UserID,
		"amount", t.Amount,
		"currency", t.Currency,
		"ip", t.IP,
		"decision", v.Decision,
		"reasons", v.Reasons,
		"latency_ms", v.LatencyMS,
	)
}

type externalResponse struct {
	Score    float64 `json:"score"`
	Decision string  `json:"decision"`
	Reason   string  `json:"reason"`
}

func (s *Scorer) callExternal(ctx context.Context, t decision.Txn) (reason, extDecision string, err error) {
	// Клиент инициализируется в main; nil допустим только в тестах — http.DefaultClient без таймаута.
	client := s.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	body, err := json.Marshal(t)
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.ScorerURL, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", &scorerStatusError{Code: resp.StatusCode}
	}
	var out externalResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	reason = out.Reason
	if reason == "" && out.Score >= 0.8 {
		reason = "external_scorer_hit"
	}
	switch {
	case out.Decision != "":
		extDecision = strings.ToLower(strings.TrimSpace(out.Decision))
	case out.Score >= 0.8:
		extDecision = decision.Review
	}
	return reason, extDecision, nil
}

type scorerStatusError struct{ Code int }

func (e *scorerStatusError) Error() string {
	return http.StatusText(e.Code)
}
