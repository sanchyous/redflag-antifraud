package numplan

import (
	"os"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/telecom/phone"
)

// Прогон на реальном реестре Россвязи. Включается через NUMPLAN_DIR (в CI без данных пропускается).
func TestRealRegistry(t *testing.T) {
	dir := os.Getenv("NUMPLAN_DIR")
	if dir == "" {
		t.Skip("NUMPLAN_DIR not set")
	}
	start := time.Now()
	p, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded %d ranges in %s, stats=%+v version=%s", p.Size(), time.Since(start), p.Stats, p.Version)
	if p.Size() < 400_000 {
		t.Fatalf("suspiciously few ranges: %d", p.Size())
	}
	if p.Stats.Skipped > p.Stats.Rows/1000 {
		t.Fatalf("too many skipped rows: %+v", p.Stats)
	}
	for _, s := range []string{"+7 495 123-45-67", "+7 916 123-45-67", "+7 812 200-00-00", "+7 913 123-45-67", "8 800 555-35-35"} {
		n, _ := phone.Parse(s)
		info, ok := p.Lookup(n)
		t.Logf("%s → %+v ok=%v", s, info, ok)
		if !ok {
			t.Errorf("%s not found", s)
		}
	}
	regions := map[string]bool{}
	for _, r := range p.regs {
		regions[r.name] = true
	}
	t.Logf("distinct regions: %d", len(regions))
	if len(regions) < 70 || len(regions) > 130 {
		t.Errorf("unexpected number of regions: %d", len(regions))
	}
	n, _ := phone.Parse("+7 495 ***-**-12")
	info, ok := p.Lookup(n)
	t.Logf("masked 495 → %+v", info)
	if !ok || info.Region != "Москва и Московская область" {
		t.Errorf("masked 495: %+v %v", info, ok)
	}
}
