// export — выгрузка датасета признаков для обучения в ML-сервисе (Python).
//
// Синтетический поток проигрывается через боевой движок, поэтому признаки считаются тем же
// кодом, что и онлайн. Три независимых набора (разные seed): train, calib, test.
//
//	go run ./cmd/export -numplan /path/to/numplan -out ./dataset
package main

import (
	"encoding/json"
	"flag"
	"hash/fnv"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/ingest"
	"github.com/sanchyous/redflag-antifraud/internal/mltrain"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
	"github.com/sanchyous/redflag-antifraud/internal/synth"
)

func main() {
	var (
		numplanDir = flag.String("numplan", os.Getenv("NUMPLAN_DIR"), "каталог с CSV реестра Россвязи")
		out        = flag.String("out", "dataset", "каталог для train.csv, calib.csv, test.csv и meta.json")
		seed       = flag.Uint64("seed", 1, "seed генератора (наборы: 3*seed+1..3)")
		scale      = flag.Float64("scale", 1, "множитель числа абонентов")
		days       = flag.Int("days", 3, "длина периода, суток")
		input      = flag.String("input", "", "размеченная выгрузка вызовов (.csv/.jsonl) вместо синтетики; нужна колонка label")
		allowFile  = flag.String("allowlist", "", "файл allowlist проверенных номеров (для -input)")
	)
	flag.Parse()
	if *numplanDir == "" {
		log.Fatal("укажите -numplan (или NUMPLAN_DIR)")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	plan, err := numplan.LoadDir(*numplanDir)
	if err != nil {
		log.Fatalf("numplan: %v", err)
	}
	counts := map[string]int{}
	if *input != "" {
		exportExternal(plan, *input, *allowFile, *out, counts)
		writeMeta(*out, plan, *seed, *scale, *days, counts, *input)
		return
	}
	for i, name := range []string{"train", "calib", "test"} {
		s := 3**seed + uint64(i) + 1
		ds := synth.Generate(synth.Config{Seed: s, Plan: plan, Scale: *scale, Days: *days})
		cls := protect.New()
		for _, a := range ds.Allowlist {
			cls.Add(a)
		}
		rows, err := mltrain.Replay(plan, cls, ds.Samples, 10*time.Minute)
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		f, err := os.Create(filepath.Join(*out, name+".csv"))
		if err != nil {
			log.Fatal(err)
		}
		if err := mltrain.ExportCSV(f, rows); err != nil {
			log.Fatal(err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
		counts[name] = len(rows)
		log.Printf("%s: %d вызовов (seed %d)", name, len(rows), s)
	}
	writeMeta(*out, plan, *seed, *scale, *days, counts, "")
}

func writeMeta(out string, plan *numplan.Plan, seed uint64, scale float64, days int, counts map[string]int, input string) {
	meta := map[string]any{
		"features": features.Names, "numplan_version": plan.Version, "seed": seed, "scale": scale,
		"days": days, "rows": counts, "generated_at": time.Now().UTC().Format(time.RFC3339), "input": input,
	}
	mf, err := os.Create(filepath.Join(out, "meta.json"))
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(mf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		log.Fatal(err)
	}
	_ = mf.Close()
}

// exportExternal выгружает размеченные вызовы из файла организаторов. Разбиение — по номеру звонящего
// (хэш), чтобы вызовы одного номера не попадали в разные наборы (иначе оценка завышена утечкой); каждый
// набор проигрывается независимо, в порядке времени.
func exportExternal(plan *numplan.Plan, input, allowFile, out string, counts map[string]int) {
	res, err := ingest.ReadFile(input)
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
	splits := map[string][]synth.Sample{}
	unlabeled := 0
	for _, r := range res.Records {
		if r.Label == nil {
			unlabeled++
			continue
		}
		if r.Call.StartedAt.IsZero() {
			log.Fatalf("строка %d: нет времени начала вызова — окна по номерам без времени не считаются", r.Line)
		}
		h := fnv.New32a()
		_, _ = h.Write([]byte(r.Call.Caller))
		name := "test"
		switch b := h.Sum32() % 100; {
		case b < 60:
			name = "train"
		case b < 80:
			name = "calib"
		}
		splits[name] = append(splits[name], synth.Sample{Call: r.Call, Fraud: *r.Label, Kind: "external"})
	}
	if unlabeled > 0 {
		log.Printf("вызовов без метки пропущено: %d", unlabeled)
	}
	cls := protect.New()
	if allowFile != "" {
		f, err := os.Open(allowFile)
		if err != nil {
			log.Fatal(err)
		}
		n, bad := cls.LoadAllowlist(f)
		_ = f.Close()
		log.Printf("allowlist: %d записей, некорректных %d", n, len(bad))
	}
	for _, name := range []string{"train", "calib", "test"} {
		samples := splits[name]
		if len(samples) == 0 {
			log.Fatalf("набор %s пуст: в файле слишком мало разных номеров или вызовов", name)
		}
		sort.SliceStable(samples, func(i, j int) bool { return samples[i].Call.StartedAt.Before(samples[j].Call.StartedAt) })
		rows, err := mltrain.Replay(plan, cls, samples, 10*time.Minute)
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		f, err := os.Create(filepath.Join(out, name+".csv"))
		if err != nil {
			log.Fatal(err)
		}
		if err := mltrain.ExportCSV(f, rows); err != nil {
			log.Fatal(err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
		fraud := 0
		for _, r := range rows {
			if r.Label {
				fraud++
			}
		}
		counts[name] = len(rows)
		log.Printf("%s: %d вызовов, мошеннических %d", name, len(rows), fraud)
	}
}
