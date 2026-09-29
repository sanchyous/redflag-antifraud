// Package mlclient — клиент ML-сервиса (Python: CatBoost + SHAP). Ядро вызывает его только для
// вызовов «серой зоны», поэтому клиент обязан быть быстрым и безопасным при сбоях:
// короткий таймаут и circuit breaker — недоступный ML не тормозит и не роняет скоринг,
// ядро откатывается на стадию 1.
package mlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/features"
)

// Ошибки клиента.
var (
	ErrBreakerOpen = errors.New("mlclient: circuit breaker open")
	ErrNoModel     = errors.New("mlclient: service has no model loaded")
)

// Config — параметры клиента.
type Config struct {
	BaseURL         string
	APIKey          string
	Timeout         time.Duration // на один запрос (по умолчанию 50 мс; SHAP занимает ~8 мс)
	BreakerFailures int           // подряд идущих сбоев до открытия (по умолчанию 5)
	BreakerCooldown time.Duration // сколько breaker остаётся открытым (по умолчанию 10 с)
	HTTP            *http.Client  // nil — собственный клиент с пулом соединений
	Now             func() time.Time
}

// Contribution — вклад признака (SHAP) в лог-шансы.
type Contribution struct {
	Feature      string  `json:"feature"`
	Value        float64 `json:"value"`
	Contribution float64 `json:"contribution"`
}

// Result — ответ ML на один вызов.
type Result struct {
	Score         float64        `json:"score"`
	Logit         float64        `json:"logit"`
	BaseLogit     float64        `json:"base_logit"`
	Contributions []Contribution `json:"contributions"`
	ModelVersion  string         `json:"model_version"`
}

// ErrBadResponse — ответ ML не похож на оценку (нет версии модели или score вне [0, 1]).
var ErrBadResponse = errors.New("mlclient: malformed score response")

// validate защищает от ответа 200 с не тем телом: без проверки он превратился бы в score = 0,
// то есть в тихий allow.
func (r *Result) validate() error {
	if r.ModelVersion == "" || math.IsNaN(r.Score) || r.Score < 0 || r.Score > 1 {
		return ErrBadResponse
	}
	return nil
}

// Info — описание текущей модели: версия и пороги, подобранные при обучении.
type Info struct {
	Version    string             `json:"version"`
	Features   []string           `json:"features"`
	Thresholds map[string]float64 `json:"thresholds"`
}

// Client безопасен для конкурентного использования.
type Client struct {
	cfg  Config
	http *http.Client
	base string

	mu       sync.Mutex
	failures int
	openedAt time.Time
	probing  bool
}

// New создаёт клиент.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("mlclient: BaseURL is empty")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 50 * time.Millisecond
	}
	if cfg.BreakerFailures <= 0 {
		cfg.BreakerFailures = 5
	}
	if cfg.BreakerCooldown <= 0 {
		cfg.BreakerCooldown = 10 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	h := cfg.HTTP
	if h == nil {
		h = &http.Client{Transport: &http.Transport{
			MaxIdleConns: 128, MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second,
		}}
	}
	return &Client{cfg: cfg, http: h, base: strings.TrimRight(cfg.BaseURL, "/")}, nil
}

// allow решает, можно ли сейчас отправлять запрос (состояния breaker: закрыт / открыт / проба).
func (c *Client) allow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures < c.cfg.BreakerFailures {
		return true
	}
	if c.cfg.Now().Sub(c.openedAt) < c.cfg.BreakerCooldown {
		return false
	}
	if c.probing {
		return false // одну пробу уже отправили, остальные ждут её результата
	}
	c.probing = true
	return true
}

func (c *Client) record(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probing = false
	if err == nil {
		c.failures = 0
		return
	}
	c.failures++
	if c.failures >= c.cfg.BreakerFailures {
		c.openedAt = c.cfg.Now()
	}
}

// Open сообщает, открыт ли breaker (для метрик).
func (c *Client) Open() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failures >= c.cfg.BreakerFailures
}

type scoreRequest struct {
	Features map[string]float32 `json:"features"`
	Explain  bool               `json:"explain"`
}

// Score отправляет вектор признаков (исходные значения) и возвращает оценку ML.
// Ошибки и таймаут учитываются breaker'ом; ошибка контракта (4xx) — тоже сбой, потому что
// повторять неверный запрос бессмысленно, а молчать об этом нельзя.
func (c *Client) Score(ctx context.Context, v *features.Vector, explain bool) (Result, error) {
	if !c.allow() {
		return Result{}, ErrBreakerOpen
	}
	req := scoreRequest{Features: make(map[string]float32, features.N), Explain: explain}
	for i, n := range features.Names {
		req.Features[n] = v.Raw[i]
	}
	var res Result
	err := c.do(ctx, http.MethodPost, "/v1/score", &req, &res)
	if err == nil {
		err = res.validate()
	}
	c.record(err)
	return res, err
}

// Info запрашивает описание модели. Не подчиняется breaker'у: это редкий служебный запрос.
func (c *Client) Info(ctx context.Context) (Info, error) {
	var inf Info
	if err := c.do(ctx, http.MethodGet, "/v1/model", nil, &inf); err != nil {
		return Info{}, err
	}
	return inf, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", c.cfg.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		return ErrNoModel
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("mlclient: %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
