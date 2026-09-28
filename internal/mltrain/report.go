package mltrain

import (
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/synth"
)

// ReportInfo — всё, что попадает в отчёт.
type ReportInfo struct {
	Title       string
	Date        string
	Model       *scoring.Model
	Fit         *FitResult
	Targets     Targets
	Prevalence  float64
	LegitWeight float64
	MinStrong   int
	TrainRows   int
	CalibRows   int
	Test        *Metrics
	Notes       []string
}

// WriteReport пишет отчёт в Markdown.
func WriteReport(w io.Writer, ri *ReportInfo) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f+"\n", a...) }
	m := ri.Test
	p("# %s", ri.Title)
	p("")
	p("Дата: %s. Модель: `%s`. Пороги: review = %.4f, block = %.4f.", ri.Date, ri.Model.Version, ri.Model.Review, ri.Model.Block)
	p("")
	p("## Постановка")
	p("- обучение: %d вызовов, калибровка порогов: %d, независимая проверка: %d (три разных seed генератора)", ri.TrainRows, ri.CalibRows, m.N+m.Emergency.N)
	p("- целевая доля ложных срабатываний: review ≤ %.2f%%, block ≤ %.3f%% легитимных вызовов", ri.Targets.ReviewFPR*100, ri.Targets.BlockFPR*100)
	p("- вес легитимных при обучении: %.1f (ложное срабатывание дороже пропуска); ожидаемая доля мошенничества в потоке: %.2f%%", ri.LegitWeight, ri.Prevalence*100)
	p("- block требует score ≥ порога и не менее %d независимых сильных сигналов; защищённые классы не блокируются", ri.MinStrong)
	p("")
	p("## Итог на независимой проверке")
	p("")
	p("| Метрика | Значение |")
	p("|---|---|")
	p("| Вызовов (без экстренных) | %d (легитимных %d, мошеннических %d) |", m.N, m.Legit, m.Fraud)
	p("| ROC-AUC | %.4f |", m.AUC)
	p("| PR-AUC | %.4f |", m.PRAUC)
	p("| review: recall / FPR | %.1f%% / %.3f%% |", m.Review.Recall()*100, m.Review.FPR()*100)
	p("| block: recall / FPR | %.1f%% / %.4f%% |", m.Block.Recall()*100, m.Block.FPR()*100)
	p("| block: ложных блокировок легитимных | %d из %d |", m.Block.FP, m.Legit)
	p("| review: ложных отметок легитимных | %d из %d |", m.Review.FP, m.Legit)
	p("")
	p("Точность (precision) зависит от доли мошенничества в потоке; при тех же recall и FPR:")
	p("")
	p("| Доля мошеннических вызовов | precision(review) | precision(block) |")
	p("|---|---|---|")
	for _, pr := range []float64{0.001, 0.01, 0.05, 0.15} {
		p("| %.1f%% | %.1f%% | %.1f%% |", pr*100, m.Review.PrecisionAt(pr)*100, m.Block.PrecisionAt(pr)*100)
	}
	p("")
	p("## Экстренные службы")
	p("")
	p("Вызовов на 112/101/102/103/104 в проверке: **%d**; получили allow: **%d**; заблокировано: **%d**.", m.Emergency.N, m.Emergency.Allowed, m.Emergency.Blocked)
	p("Защитный слой стоит выше модели, поэтому блокировка скорой невозможна архитектурно (см. `decide.Decide` и тест `TestEmergencyNeverBlocked`).")
	p("")
	p("## Ложные срабатывания по типам легитимных абонентов")
	p("")
	p("| Тип | Вызовов | review+ | block | Блок отменён защитой |")
	p("|---|---|---|---|---|")
	for _, k := range synth.LegitKinds {
		if ks := m.ByKind[k]; ks != nil {
			p("| %s | %d | %d (%.2f%%) | %d | %d |", k, ks.N, ks.Review, pct(ks.Review, ks.N), ks.Block, ks.Suppressed)
		}
	}
	p("")
	p("## Обнаружение по типам мошенничества")
	p("")
	p("| Тип | Вызовов | review+ (доля) | block (доля) |")
	p("|---|---|---|---|")
	for _, k := range synth.FraudKinds {
		if ks := m.ByKind[k]; ks != nil {
			p("| %s | %d | %.1f%% | %.1f%% |", k, ks.N, pct(ks.Review, ks.N), pct(ks.Block, ks.N))
		}
	}
	p("")
	p("## Скорость реакции на номер-нарушитель")
	p("")
	p("- мошеннических номеров: %d; получили review: %d (%.1f%%); получили block: %d (%.1f%%)", m.FraudCallers,
		m.CallersReviewed, pct(m.CallersReviewed, m.FraudCallers), m.CallersBlocked, pct(m.CallersBlocked, m.FraudCallers))
	p("- медиана вызовов до первой отметки review: %s; до первого block: %s (прошедшие до реакции вызовы — цена холодного старта)",
		num(m.MedianCallsToReview), num(m.MedianCallsToBlock))
	p("")
	p("## Веса модели")
	p("")
	p("Вклад признака в лог-шансы = вес × (значение − значение эталонного абонента). Вес > 0 повышает риск.")
	p("")
	p("| Признак | Вес | Эталон |")
	p("|---|---|---|")
	idx := make([]int, features.N)
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool {
		return math.Abs(float64(ri.Model.W[idx[a]])) > math.Abs(float64(ri.Model.W[idx[b]]))
	})
	for _, i := range idx {
		p("| %s | %+.3f | %.3f |", features.Names[i], ri.Model.W[i], ri.Model.Base[i])
	}
	if ri.Fit != nil && len(ri.Fit.Zeroed) > 0 {
		p("")
		p("Признаки, обнулённые ограничением знака (рост не может снижать риск): %v.", ri.Fit.Zeroed)
	}
	if len(ri.Notes) > 0 {
		p("")
		p("## Замечания")
		for _, n := range ri.Notes {
			p("- %s", n)
		}
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

func num(x float64) string {
	if math.IsNaN(x) {
		return "нет"
	}
	return fmt.Sprintf("%.0f", x)
}
