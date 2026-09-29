package engine

import (
	"strconv"
	"strings"

	"github.com/sanchyous/redflag-antifraud/internal/decision/decide"
)

// Резюме решения — одна строка для оператора, отчёта и журнала: кто кому звонил, что решено и почему.
// ТЗ требует не «0,87», а факторы с вкладом; резюме собирает главные из них в связную фразу
// (подробные вклады остаются в reasons). Для allow строка статична — на потоке обычных вызовов лишних аллокаций нет.
const (
	summaryAllow     = "Пропуск: признаков риска не найдено."
	summaryEmergency = "Пропуск: вызов экстренной службы — защитный класс, скоринг не применялся."
)

func verdictWord(decision string) string {
	switch decision {
	case decide.Block.String():
		return "Блок"
	case decide.Review.String():
		return "Проверка"
	}
	return "Пропуск"
}

// summarize строит резюме по готовому ответу.
func summarize(r *Response) string {
	if r.SafeClass == "emergency" {
		return summaryEmergency
	}
	if r.Decision == "allow" {
		return summaryAllow
	}
	var b strings.Builder
	b.WriteString("Вызов ")
	b.WriteString(orDash(r.Caller.Masked))
	b.WriteString(" → ")
	b.WriteString(orDash(r.Callee.Masked))
	b.WriteString(": ")
	b.WriteString(verdictWord(r.Decision))
	b.WriteString(" (риск ")
	b.WriteString(strings.Replace(strconv.FormatFloat(r.Score, 'f', 4, 64), ".", ",", 1))
	b.WriteString(", ")
	if r.Stage == "ml" {
		b.WriteString("ML-модель")
	} else {
		b.WriteString("линейная модель")
	}
	b.WriteString("). ")
	n := 0
	for _, x := range r.Reasons {
		if x.Effect != "raises" {
			continue
		}
		if n == 0 {
			b.WriteString("Причины: ")
		} else {
			b.WriteString("; ")
		}
		b.WriteString(x.Text)
		if n++; n == 3 {
			break
		}
	}
	if n == 0 {
		b.WriteString("Причины: суммарный вклад признаков превысил порог.")
	} else {
		b.WriteByte('.')
	}
	if r.BlockSuppressed {
		b.WriteString(" Блок отменён защитным классом («")
		b.WriteString(r.SafeClass)
		b.WriteString("») — оставлена проверка.")
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "(номер скрыт)"
	}
	return s
}
