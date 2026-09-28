// train — обучение и оценка модели скоринга на синтетическом потоке вызовов.
//
// Три независимых набора (разные seed): обучение, калибровка порогов по целевому FPR и
// итоговая проверка. Признаки считаются боевым движком, поэтому рассинхрона между обучением
// и продом нет.
//
//	go run ./cmd/train -numplan /path/to/numplan -out model.json -report report.md
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/mltrain"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
	"github.com/sanchyous/redflag-antifraud/internal/synth"
)

func main() {
	var (
		numplanDir  = flag.String("numplan", os.Getenv("NUMPLAN_DIR"), "каталог с CSV реестра Россвязи")
		out         = flag.String("out", "model.json", "куда записать модель")
		reportPath  = flag.String("report", "", "куда записать отчёт (Markdown); пусто — не писать")
		seed        = flag.Uint64("seed", 1, "seed генератора (три набора: 3*seed+1..3)")
		scale       = flag.Float64("scale", 1, "множитель числа абонентов")
		days        = flag.Int("days", 3, "длина периода, суток")
		legitWeight = flag.Float64("legit-weight", 3, "вес легитимных вызовов при обучении")
		prevalence  = flag.Float64("prevalence", 0.01, "ожидаемая доля мошеннических вызовов в боевом потоке")
		reviewFPR   = flag.Float64("review-fpr", 0.01, "целевая доля легитимных вызовов в review")
		blockFPR    = flag.Float64("block-fpr", 0.0001, "целевая доля легитимных вызовов под block")
		minSignals  = flag.Int("min-signals", 2, "сильных сигналов для block")
		l2          = flag.Float64("l2", 5, "L2-регуляризация")
	)
	flag.Parse()
	if *numplanDir == "" {
		log.Fatal("укажите -numplan (или NUMPLAN_DIR)")
	}

	t0 := time.Now()
	plan, err := numplan.LoadDir(*numplanDir)
	if err != nil {
		log.Fatalf("numplan: %v", err)
	}
	log.Printf("справочник: %d диапазонов, версия %s", plan.Size(), plan.Version)

	gen := func(name string, s uint64) []mltrain.Row {
		ds := synth.Generate(synth.Config{Seed: s, Plan: plan, Scale: *scale, Days: *days})
		cls := protect.New()
		for _, a := range ds.Allowlist {
			cls.Add(a)
		}
		rows, err := mltrain.Replay(plan, cls, ds.Samples, 10*time.Minute)
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		fraud := 0
		for _, r := range rows {
			if r.Label {
				fraud++
			}
		}
		log.Printf("%s: %d вызовов, мошеннических %d (%.1f%%), %s", name, len(rows), fraud, 100*float64(fraud)/float64(len(rows)), time.Since(t0).Round(time.Millisecond))
		return rows
	}
	train := gen("обучение", 3**seed+1)
	calib := gen("калибровка", 3**seed+2)
	test := gen("проверка", 3**seed+3)

	fit, err := mltrain.Fit(train, mltrain.FitOptions{L2: *l2, LegitWeight: *legitWeight, NonNegative: mltrain.DefaultNonNegative()})
	if err != nil {
		log.Fatalf("fit: %v", err)
	}
	log.Printf("обучение: %d итераций, потеря %.1f, обнулены признаки %v", fit.Iterations, fit.Loss, fit.Zeroed)

	model := mltrain.BuildModel(fit, train, mltrain.BuildOptions{Prevalence: *prevalence, LegitWeight: *legitWeight, Version: mltrain.Stamp(time.Now())})
	targets := mltrain.Targets{ReviewFPR: *reviewFPR, BlockFPR: *blockFPR}
	model.Review, model.Block = mltrain.FitThresholds(model, calib, *minSignals, targets)
	if err := model.Validate(); err != nil {
		log.Fatalf("модель невалидна: %v", err)
	}

	pol := mltrain.Policy(model, *minSignals)
	mt := mltrain.Evaluate(test, model, pol)
	log.Printf("проверка: AUC %.4f, review recall %.1f%% FPR %.3f%%, block recall %.1f%% FPR %.4f%% (ложных блокировок %d из %d), скорая: заблокировано %d из %d",
		mt.AUC, mt.Review.Recall()*100, mt.Review.FPR()*100, mt.Block.Recall()*100, mt.Block.FPR()*100, mt.Block.FP, mt.Legit, mt.Emergency.Blocked, mt.Emergency.N)

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	metrics := map[string]float64{
		"auc": mt.AUC, "pr_auc": mt.PRAUC,
		"review_recall": mt.Review.Recall(), "review_fpr": mt.Review.FPR(),
		"block_recall": mt.Block.Recall(), "block_fpr": mt.Block.FPR(),
	}
	if err := model.Write(f, metrics); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	log.Printf("модель записана: %s (версия %s, review=%.4f, block=%.4f)", *out, model.Version, model.Review, model.Block)

	if *reportPath != "" {
		rf, err := os.Create(*reportPath)
		if err != nil {
			log.Fatal(err)
		}
		mltrain.WriteReport(rf, &mltrain.ReportInfo{
			Title: "Отчёт об обучении и оценке модели", Date: time.Now().Format("2006-01-02"),
			Model: model, Fit: fit, Targets: targets, Prevalence: *prevalence, LegitWeight: *legitWeight, MinStrong: *minSignals,
			TrainRows: len(train), CalibRows: len(calib), Test: mt,
			Notes: []string{
				fmt.Sprintf("данные синтетические (генератор internal/synth, seed %d), справочник нумерации %s; на реальных данных цифры будут другими", *seed, plan.Version),
				"порог review подобран по целевому FPR на калибровочном наборе, метрики посчитаны на третьем, не участвовавшем ни в обучении, ни в подборе порогов",
			},
		})
		if err := rf.Close(); err != nil {
			log.Fatal(err)
		}
		log.Printf("отчёт записан: %s", *reportPath)
	}
	log.Printf("готово за %s", time.Since(t0).Round(time.Millisecond))
}
