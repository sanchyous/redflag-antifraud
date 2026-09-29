// scorefile — оффлайн-прогон файла вызовов (.csv/.jsonl) через боевой движок: те же признаки, окна,
// граф, защитный слой и (по желанию) ML-стадия, что и в сервисе. Часы движка идут по времени вызовов,
// поэтому результат детерминирован и не зависит от скорости прогона. Если в файле есть метка, печатается
// сводка: ложные срабатывания, полнота, скорая.
//
//	go run ./cmd/scorefile -numplan /path/to/numplan -in calls.csv -out decisions.csv [-ml-url http://ml:8100]
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
	"github.com/sanchyous/redflag-antifraud/internal/decision/mlclient"
	"github.com/sanchyous/redflag-antifraud/internal/decision/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/detection/protect"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/ingest"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/numplan"
)

func main() {
	var (
		numplanDir = flag.String("numplan", os.Getenv("NUMPLAN_DIR"), "каталог с CSV реестра Россвязи")
		in         = flag.String("in", "", "файл вызовов (.csv, .jsonl)")
		out        = flag.String("out", "decisions.csv", "куда записать решения (CSV)")
		modelFile  = flag.String("model", "", "линейная модель стадии 1 (JSON); пусто — экспертная")
		allowFile  = flag.String("allowlist", "", "файл allowlist проверенных номеров")
		mlURL      = flag.String("ml-url", "", "адрес ML-сервиса; пусто — только линейная стадия")
		mlKey      = flag.String("ml-key", os.Getenv("ML_API_KEY"), "ключ ML-сервиса")
		fanEvery   = flag.Duration("fan-every", 10*time.Minute, "как часто в модельном времени пересчитывать веера")
	)
	flag.Parse()
	if *in == "" {
		log.Fatal("укажите -in")
	}
	var plan *numplan.Plan
	if *numplanDir != "" {
		var err error
		if plan, err = numplan.LoadDir(*numplanDir); err != nil {
			log.Fatalf("numplan: %v", err)
		}
	} else {
		log.Print("справочник не задан: региональные признаки и сигнал нераспределённого номера отключены")
	}
	res, err := ingest.ReadFile(*in)
	if err != nil {
		log.Fatalf("input: %v", err)
	}
	for i, e := range res.Errors {
		if i >= 5 {
			log.Printf("… и ещё %d ошибок разбора", len(res.Errors)-5)
			break
		}
		log.Printf("пропущена %v", e)
	}
	recs := res.Records
	for i := range recs {
		if recs[i].Call.StartedAt.IsZero() {
			log.Fatalf("строка %d: нет времени начала вызова", recs[i].Line)
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Call.StartedAt.Before(recs[j].Call.StartedAt) })

	var clock atomic.Int64
	cfg := engine.Config{Plan: plan, Now: func() time.Time { return time.Unix(clock.Load(), 0) }}
	if *allowFile != "" {
		f, err := os.Open(*allowFile)
		if err != nil {
			log.Fatal(err)
		}
		cfg.Classifier = protect.New()
		cfg.Classifier.LoadAllowlist(f)
		_ = f.Close()
	}
	if *modelFile != "" {
		f, err := os.Open(*modelFile)
		if err != nil {
			log.Fatal(err)
		}
		if cfg.Model, err = scoring.Load(f); err != nil {
			log.Fatalf("model: %v", err)
		}
		_ = f.Close()
	}
	if *mlURL != "" {
		if cfg.ML, err = mlclient.New(mlclient.Config{BaseURL: *mlURL, APIKey: *mlKey, Timeout: 2 * time.Second, BreakerFailures: 1000}); err != nil {
			log.Fatal(err)
		}
	}
	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.ML != nil {
		if err := eng.RefreshML(context.Background()); err != nil {
			log.Fatalf("ML недоступен или несовместим: %v", err)
		}
		_ = eng.WarmupML(context.Background())
		log.Printf("ML-стадия активна: %s", eng.MLVersion())
	}

	of, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	w := csv.NewWriter(of)
	_ = w.Write([]string{"call_id", "caller", "callee", "started_at", "decision", "score", "stage", "signals", "safe_class", "rule_floor", "top_reasons", "label"})

	type conf struct{ tp, fp, fn, tn int }
	var review, block conf
	emerg, emergBlocked, errCount := 0, 0, 0
	hasLabel := false
	start := time.Now()
	var lastFan int64
	for i := range recs {
		rc := &recs[i]
		ts := rc.Call.StartedAt.Unix()
		clock.Store(ts)
		if *fanEvery > 0 && ts-lastFan >= int64(fanEvery.Seconds()) {
			eng.RefreshFan()
			lastFan = ts
		}
		resp, err := eng.Score(&rc.Call)
		if err != nil {
			errCount++
			continue
		}
		var reasons []string
		for j, r := range resp.Reasons {
			if j == 3 {
				break
			}
			reasons = append(reasons, r.Text)
		}
		label := ""
		if rc.Label != nil {
			hasLabel = true
			label = strconv.FormatBool(*rc.Label)
		}
		_ = w.Write([]string{resp.CallID, resp.Caller.Masked, resp.Callee.Masked, rc.Call.StartedAt.Format(time.RFC3339),
			resp.Decision, strconv.FormatFloat(resp.Score, 'f', 4, 64), resp.Stage, strings.Join(resp.Signals, "|"),
			resp.SafeClass, strconv.FormatBool(resp.RuleFloor), strings.Join(reasons, "; "), label})
		if resp.SafeClass == "emergency" {
			emerg++
			if resp.Decision == "block" {
				emergBlocked++
			}
			continue
		}
		if rc.Label != nil {
			tally := func(c *conf, flagged bool) {
				switch {
				case *rc.Label && flagged:
					c.tp++
				case *rc.Label:
					c.fn++
				case flagged:
					c.fp++
				default:
					c.tn++
				}
			}
			tally(&review, resp.Decision != "allow")
			tally(&block, resp.Decision == "block")
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
	_ = of.Close()
	took := time.Since(start)
	log.Printf("обработано %d вызовов за %s (%.0f вызовов/с), ошибок валидации %d, результат: %s",
		len(recs)-errCount, took.Round(time.Millisecond), float64(len(recs))/took.Seconds(), errCount, *out)
	if hasLabel {
		pct := func(a, b int) float64 {
			if b == 0 {
				return 0
			}
			return 100 * float64(a) / float64(b)
		}
		fmt.Printf("\nСводка по размеченным вызовам (без экстренных):\n")
		fmt.Printf("  review или выше: полнота %.1f%%, ложных срабатываний %.3f%% (%d из %d легитимных)\n",
			pct(review.tp, review.tp+review.fn), pct(review.fp, review.fp+review.tn), review.fp, review.fp+review.tn)
		fmt.Printf("  block:           полнота %.1f%%, ложных блокировок %.4f%% (%d из %d легитимных)\n",
			pct(block.tp, block.tp+block.fn), pct(block.fp, block.fp+block.tn), block.fp, block.fp+block.tn)
		fmt.Printf("  экстренные: %d, заблокировано %d\n", emerg, emergBlocked)
	}
}
