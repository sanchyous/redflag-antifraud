package engine

import (
	"strings"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/decision/explain"
)

func TestSummaryForTheCaseFromTheSpec(t *testing.T) {
	// Пример из ТЗ: вызов с российским номером при иностранном входе на 6 секунд.
	e, _ := newEngine(t, nil)
	r, err := e.Score(spoofCall("sum-1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Вызов +7 495 ***-**-67 → +7 916 ***-**-67", "Проверка", "риск 0,1511", "линейная модель", "Причины:", "подмена номера"} {
		if !strings.Contains(r.Summary, want) {
			t.Fatalf("summary lacks %q: %s", want, r.Summary)
		}
	}
	if !strings.HasSuffix(r.Summary, ".") {
		t.Fatalf("a full sentence is expected: %s", r.Summary)
	}
	if strings.Contains(r.Summary, "123-45-67") {
		t.Fatal("no raw digits in the summary")
	}
}

func TestSummaryAllowAndEmergency(t *testing.T) {
	e, _ := newEngine(t, nil)
	ok, _ := e.Score(ordinaryCall("sum-ok"))
	if ok.Summary != summaryAllow {
		t.Fatalf("allow: %q", ok.Summary)
	}
	for _, callee := range []string{"103", "*112#"} {
		r, _ := e.Score(call("sum-em-"+callee, "+7 495 123-45-67", callee, t0, 2))
		if r.Summary != summaryEmergency {
			t.Fatalf("%s: %q", callee, r.Summary)
		}
	}
}

func TestSummaryMentionsMLAndFloor(t *testing.T) {
	f := newFakeML(t)
	f.score.Store(0.0002)
	e, _ := newCascade(t, f, nil)
	r, _ := e.Score(spoofCall("sum-ml"))
	if !strings.Contains(r.Summary, "ML-модель") || !strings.Contains(r.Summary, "правило") || !strings.Contains(r.Summary, "0,0002") {
		t.Fatalf("summary of a floored ML decision: %s", r.Summary)
	}
}

func TestSummaryBlockSuppressedByProtection(t *testing.T) {
	r := &Response{Decision: "review", Score: 0.99, Stage: "ml", SafeClass: "allowlisted", BlockSuppressed: true,
		Caller: Party{Masked: "+7 495 ***-**-01"}, Callee: Party{Masked: "+7 916 ***-**-02"},
		Reasons: []explain.Reason{{Effect: "raises", Text: "первое"}, {Effect: "lowers", Text: "смягчающее"}, {Effect: "raises", Text: "второе"}}}
	s := summarize(r)
	if !strings.Contains(s, "Блок отменён защитным классом («allowlisted»)") || !strings.Contains(s, "первое; второе") || strings.Contains(s, "смягчающее") {
		t.Fatalf("summary: %s", s)
	}
}

func TestSummaryLimitsReasonsAndHandlesEmptyOnes(t *testing.T) {
	many := make([]explain.Reason, 6)
	for i := range many {
		many[i] = explain.Reason{Effect: "raises", Text: string(rune('a' + i))}
	}
	s := summarize(&Response{Decision: "block", Score: 1, Reasons: many})
	if !strings.Contains(s, "a; b; c.") || strings.Contains(s, "d") || !strings.Contains(s, "(номер скрыт)") {
		t.Fatalf("summary: %s", s)
	}
	if e := summarize(&Response{Decision: "review", Score: 0.3}); !strings.Contains(e, "суммарный вклад признаков превысил порог") {
		t.Fatalf("no reasons: %s", e)
	}
	if verdictWord("allow") != "Пропуск" || verdictWord("block") != "Блок" || verdictWord("review") != "Проверка" {
		t.Fatal("verdict words")
	}
}

func TestSummaryOfAllowDoesNotAllocate(t *testing.T) {
	r := &Response{Decision: "allow"}
	if a := testing.AllocsPerRun(100, func() { _ = summarize(r) }); a != 0 {
		t.Fatalf("the allow path must not allocate, got %v", a)
	}
}
