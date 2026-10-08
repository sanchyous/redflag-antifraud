package graph

import (
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/detection/window"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/callrec"
)

func simboxEvent(caller, callee uint64, ts int64, dur uint32) *callrec.Event {
	return &callrec.Event{TS: ts, Caller: caller, Callee: callee, DurSec: dur, Flags: callrec.FlagAnswered}
}

const simT0 = int64(1_800_000_000)

func TestAnalyzeSimBoxDetectsOutboundOnlyNovelPattern(t *testing.T) {
	win := window.New(window.Config{})
	for i := 0; i < 60; i++ { // номер 1: 60 исходящих, все новым собеседникам, 90 с
		win.Observe(simboxEvent(1, uint64(1000+i), simT0+int64(i*60), 90))
	}
	profiles := win.Profiles(simT0+4000, 3600*24, 1)
	ix := AnalyzeSimBox(win, profiles, simT0+4000, SimBoxConfig{})
	if ix.Members() != 1 {
		t.Fatalf("members = %d, want 1", ix.Members())
	}
	if _, ok := ix.Lookup(1); !ok {
		t.Fatal("number 1 must be flagged as sim-box")
	}
}

func TestAnalyzeSimBoxExcludesNumbersWithInbound(t *testing.T) {
	win := window.New(window.Config{})
	for i := 0; i < 60; i++ {
		win.Observe(simboxEvent(2, uint64(2000+i), simT0+int64(i*60), 90))
	}
	win.Observe(simboxEvent(9999, 2, simT0, 30)) // хоть один входящий — не SIM-box (D1)
	profiles := win.Profiles(simT0+4000, 3600*24, 1)
	ix := AnalyzeSimBox(win, profiles, simT0+4000, SimBoxConfig{})
	if ix.Members() != 0 {
		t.Fatalf("number with inbound must not be flagged: %d members", ix.Members())
	}
}

func TestAnalyzeSimBoxExcludesShortDuration(t *testing.T) {
	win := window.New(window.Config{})
	for i := 0; i < 60; i++ { // похоже на wangiri/рассылку: короткие вызовы
		win.Observe(simboxEvent(3, uint64(3000+i), simT0+int64(i*60), 2))
	}
	profiles := win.Profiles(simT0+4000, 3600*24, 1)
	ix := AnalyzeSimBox(win, profiles, simT0+4000, SimBoxConfig{})
	if ix.Members() != 0 {
		t.Fatalf("short-duration burst must not be flagged as sim-box: %d members", ix.Members())
	}
}

func TestAnalyzeSimBoxExcludesRepeatedPeers(t *testing.T) {
	win := window.New(window.Config{})
	for i := 0; i < 60; i++ { // те же 5 собеседников — обычный частый пользователь, не SIM-box
		win.Observe(simboxEvent(4, uint64(4000+i%5), simT0+int64(i*60), 90))
	}
	profiles := win.Profiles(simT0+4000, 3600*24, 1)
	ix := AnalyzeSimBox(win, profiles, simT0+4000, SimBoxConfig{})
	if ix.Members() != 0 {
		t.Fatalf("repeated peers must not be flagged as sim-box: %d members", ix.Members())
	}
}

func TestSimBoxHolderNilIsSafe(t *testing.T) {
	var h SimBoxHolder
	if _, ok := h.Lookup(1); ok {
		t.Fatal("empty holder must report not-found")
	}
}
