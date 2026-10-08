// cdrflag — прогон официального датасета кейса (каталог CDR_*.cdr, позиционный формат без
// заголовка) через боевой движок и выгрузка итогового списка подозрительных номеров в формате
// сдачи ответа кейса («один номер на строку, 10 цифр, тип схемы — через ;»). В отличие от
// cmd/scorefile (один файл, решение на каждый вызов), здесь вход — каталог из многих файлов,
// выход — не решения, а агрегированный список номеров, когда-либо получивших review/block, и
// проход двойной: первый прогревает окна/граф, второй считает решения уже по полной истории
// закрытого набора (см. комментарий у первого прохода в main).
//
//	go run ./cmd/cdrflag -numplan /path/to/numplan -indir cdr_out -out submission.txt
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
	"github.com/sanchyous/redflag-antifraud/internal/decision/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/detection/protect"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/ingest"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/phone"
)

// splitChainSignal отделяет "forward_chain" от остальных сигналов решения: own — был ли он
// среди сигналов, rest — всё остальное как есть.
func splitChainSignal(signals []string) (own bool, rest []string) {
	for _, s := range signals {
		if s == "forward_chain" {
			own = true
			continue
		}
		rest = append(rest, s)
	}
	return own, rest
}

func main() {
	var (
		numplanDir = flag.String("numplan", os.Getenv("NUMPLAN_DIR"), "каталог с CSV реестра Россвязи")
		indir      = flag.String("indir", "", "каталог с файлами CDR_*.cdr")
		out        = flag.String("out", "submission.txt", "куда записать итоговый список номеров")
		modelFile  = flag.String("model", "", "линейная модель стадии 1 (JSON); пусто — экспертная")
		allowFile  = flag.String("allowlist", "", "файл allowlist проверенных номеров")
		fanEvery   = flag.Duration("fan-every", 10*time.Minute, "как часто в модельном времени пересчитывать графовые индексы на первом проходе (прогрев)")
		anySignal  = flag.Bool("any-signal", false, "отмечать и решения без объяснимого сигнала (чистая модель без графовых/жёстких улик) — по умолчанию выключено: без ретрейна модели на этом датасете такие решения не обоснованы объяснимой уликой")
	)
	flag.Parse()
	if *indir == "" {
		log.Fatal("укажите -indir")
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

	files, err := filepath.Glob(filepath.Join(*indir, "CDR_*.cdr"))
	if err != nil || len(files) == 0 {
		log.Fatalf("нет файлов CDR_*.cdr в %s: %v", *indir, err)
	}
	sort.Strings(files)

	var recs []ingest.Record
	errCount := 0
	for fi, path := range files {
		res, err := ingest.ReadCDRFile(path)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		errCount += len(res.Errors)
		// call_id из ingest уникален только внутри одного файла (построен по номеру строки) —
		// при склейке 471 файлов он массово повторяется, и Dedupe (24ч TTL, ключ — call_id) принял
		// бы почти весь датасет за повторную доставку одного и того же вызова, не пополняя окна.
		for i := range res.Records {
			res.Records[i].Call.CallID = fmt.Sprintf("f%d-%s", fi, res.Records[i].Call.CallID)
		}
		recs = append(recs, res.Records...)
	}
	log.Printf("прочитано %d файлов, %d вызовов, %d строк пропущено как мусорные", len(files), len(recs), errCount)
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Call.StartedAt.Before(recs[j].Call.StartedAt) })

	var clock atomic.Int64
	cfg := engine.Config{Plan: plan, Now: func() time.Time { return time.Unix(clock.Load(), 0) },
		// SIM-box и карусель — устойчивый паттерн на днях, не на часе (по умолчанию движка — 24ч):
		// закрытый набор кейса конечен (471 файл, 5 суток), окно шире всей истории ничего не стоит
		// (ring-буфер окна и так ограничен по числу событий на номер, не по времени).
		SimBoxSpan: 10 * 24 * 3600, CarouselSpan: 10 * 24 * 3600}
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
	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	flagged := make(map[string]map[string]struct{})
	markFlagged := func(number string, signals []string) {
		if number == "" {
			return
		}
		sigs, ok := flagged[number]
		if !ok {
			sigs = make(map[string]struct{})
			flagged[number] = sigs
		}
		for _, s := range signals {
			sigs[s] = struct{}{}
		}
	}

	start := time.Now()

	// Первый проход: только прогрев состояния (окна, рёбра переадресации, IMSI-счётчики) с
	// периодическим RefreshGraph — как это происходило бы в проде. Графовые индексы (веер,
	// цепочки, SIM-box, карусель) на этом проходе неполны: ранние вызовы видят только то, что
	// накопилось к моменту последнего пересчёта, поэтому, например, легальная горячая линия
	// (D4) ещё не набрала порог fan-in и её источники временно выглядят как звенья цепочки.
	// Решения первого прохода не считаются — только состояние.
	var lastFan int64
	for i := range recs {
		rc := &recs[i]
		ts := rc.Call.StartedAt.Unix()
		clock.Store(ts)
		if *fanEvery > 0 && ts-lastFan >= int64(fanEvery.Seconds()) {
			eng.RefreshGraph()
			lastFan = ts
		}
		if _, err := eng.Score(&rc.Call); err != nil {
			continue
		}
	}
	eng.RefreshGraph() // окончательный пересчёт по полной истории закрытого набора

	// Второй проход: тот же порядок вызовов, та же модельная «сейчас» — но графовые индексы уже
	// не меняются (не обновляем их внутри цикла), поэтому решение по каждому вызову видит полную
	// картину связей, а не срез на момент своего появления в потоке. Dedupe отмечает все call_id
	// как повтор (это и есть повтор), окна читаются, а не пополняются заново — вторые счётчики
	// вызовов не задваиваются.
	scoreErrs, noSignal := 0, 0
	for i := range recs {
		rc := &recs[i]
		clock.Store(rc.Call.StartedAt.Unix())
		resp, err := eng.Score(&rc.Call)
		if err != nil {
			scoreErrs++
			continue
		}
		if resp.SafeClass == "emergency" || resp.Decision == "allow" {
			continue
		}
		if len(resp.Signals) == 0 {
			noSignal++
			if !*anySignal {
				continue
			}
		}
		// forward_chain — единственный сигнал, который engine.Analyze проверяет по ОБЕИМ сторонам
		// вызова (цепочка могла опознаться и по звонящему, и по тому, кому звонят): остальные
		// детекторы (клон SIM, SIM-box, карусель, веер, всплеск) всегда смотрят только на
		// звонящего, поэтому им безопасно приписывать решение целиком. Для forward_chain так
		// делать нельзя — иначе случайный человек, просто набравший номер из цепочки, попадёт в
		// список вместо самого звена цепочки. Проверяем обе стороны по индексу напрямую.
		own, rest := splitChainSignal(resp.Signals)
		if len(rest) > 0 {
			markFlagged(ingest.CDRBareNumber(rc.Call.Caller), rest)
		}
		if own {
			if n, err := phone.Parse(rc.Call.Caller); err == nil {
				if _, ok := eng.Chains().Lookup(n.Key()); ok {
					markFlagged(ingest.CDRBareNumber(rc.Call.Caller), []string{"forward_chain"})
				}
			}
			if n, err := phone.Parse(rc.Call.Callee); err == nil {
				if _, ok := eng.Chains().Lookup(n.Key()); ok {
					markFlagged(ingest.CDRBareNumber(rc.Call.Callee), []string{"forward_chain"})
				}
			}
		}
	}
	took := time.Since(start)
	log.Printf("оценено %d вызовов (2 прохода) за %s (%.0f вызовов/с на проход), ошибок скоринга %d, "+
		"решений без объяснимого сигнала %d (%s), отмечено номеров: %d",
		len(recs), took.Round(time.Second), float64(len(recs))/took.Seconds()*2, scoreErrs, noSignal,
		map[bool]string{true: "учтены", false: "пропущены, см. -any-signal"}[*anySignal], len(flagged))

	numbers := make([]string, 0, len(flagged))
	for n := range flagged {
		numbers = append(numbers, n)
	}
	sort.Strings(numbers)

	of, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer of.Close()
	for _, n := range numbers {
		sigs := make([]string, 0, len(flagged[n]))
		for s := range flagged[n] {
			sigs = append(sigs, s)
		}
		sort.Strings(sigs)
		if _, err := of.WriteString(n + ";" + strings.Join(sigs, ",") + "\n"); err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("записан %s: %d номеров", *out, len(numbers))
}
