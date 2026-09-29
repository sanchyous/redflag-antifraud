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
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/features"
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
	meta := map[string]any{
		"features": features.Names, "numplan_version": plan.Version, "seed": *seed, "scale": *scale,
		"days": *days, "rows": counts, "generated_at": time.Now().UTC().Format(time.RFC3339),
	}
	mf, err := os.Create(filepath.Join(*out, "meta.json"))
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
