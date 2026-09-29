// loadtest — нагрузочный тест HTTP-API скоринга вызовов.
//
// Два режима:
//
//   - закрытая модель (по умолчанию): c воркеров шлют запросы подряд, измеряется максимальная пропускная способность;
//
//   - открытая модель (-rps N): запросы уходят по расписанию N в секунду независимо от скорости ответов, задержка
//     считается от запланированного момента отправки. Так не теряются хвосты, которые скрывает «согласованный пропуск»
//     (coordinated omission): если сервер притормозил, запросы, которые должны были уйти за это время, всё равно
//     учитываются с накопившейся задержкой.
//
//     go run ./cmd/loadtest -url http://127.0.0.1:8000 -c 64 -d 20s
//     go run ./cmd/loadtest -url http://127.0.0.1:8000 -rps 20000 -c 256 -d 30s
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var defCodes = []string{"900", "903", "905", "906", "909", "910", "911", "912", "913", "915", "916", "917", "918", "919", "920",
	"921", "922", "923", "924", "925", "926", "927", "928", "929", "930", "931", "932", "933", "934", "936", "937", "938", "950",
	"951", "952", "953", "960", "961", "962", "963", "964", "965", "966", "967", "968", "969", "977", "978", "980", "981", "982",
	"983", "984", "985", "987", "988", "989", "991", "992", "993", "994", "995", "996", "997", "999"}

// callGen строит тела запросов без лишних аллокаций: реалистичная смесь обычных абонентов и подозрительных вызовов.
type callGen struct {
	rng      *rand.Rand
	callers  []string // пул звонящих: повторяющиеся номера дают окнам реальную работу
	suspects float64  // доля вызовов «подозрительного» профиля
}

func newGen(seed uint64, pool int, suspects float64) *callGen {
	g := &callGen{rng: rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15)), suspects: suspects}
	for i := 0; i < pool; i++ {
		g.callers = append(g.callers, g.number())
	}
	return g
}

func (g *callGen) number() string {
	return "+7" + defCodes[g.rng.IntN(len(defCodes))] + fmt.Sprintf("%07d", g.rng.IntN(10_000_000))
}

// body формирует JSON вызова; id уникален (идемпотентность по call_id не должна превращать нагрузку в дубли).
func (g *callGen) body(buf []byte, id uint64) []byte {
	caller := g.callers[g.rng.IntN(len(g.callers))]
	callee := g.callers[g.rng.IntN(len(g.callers))]
	dur := 20 + g.rng.IntN(300)
	extra := ""
	if g.rng.Float64() < g.suspects {
		dur = g.rng.IntN(6)
		extra = `,"src_country":"DE","conn_type":"international"`
	}
	buf = buf[:0]
	buf = append(buf, `{"call_id":"lt-`...)
	buf = strconv.AppendUint(buf, id, 36)
	buf = append(buf, `","caller":"`...)
	buf = append(buf, caller...)
	buf = append(buf, `","callee":"`...)
	buf = append(buf, callee...)
	buf = append(buf, `","duration_sec":`...)
	buf = strconv.AppendInt(buf, int64(dur), 10)
	buf = append(buf, extra...)
	buf = append(buf, '}')
	return buf
}

type sample struct {
	lat    time.Duration
	status int16
}

func main() {
	var (
		url      = flag.String("url", "http://127.0.0.1:8000", "адрес сервиса")
		conc     = flag.Int("c", 64, "число параллельных соединений")
		dur      = flag.Duration("d", 15*time.Second, "длительность")
		rps      = flag.Int("rps", 0, "целевая скорость, запросов/с (0 — закрытая модель: максимум)")
		warm     = flag.Duration("warmup", 2*time.Second, "прогрев, не входит в результат")
		apiKey   = flag.String("api-key", os.Getenv("API_KEY"), "ключ API")
		pool     = flag.Int("pool", 5000, "размер пула звонящих номеров")
		suspects = flag.Float64("suspects", 0.05, "доля подозрительных вызовов")
		seed     = flag.Uint64("seed", 1, "seed генератора")
	)
	flag.Parse()

	tr := &http.Transport{
		MaxIdleConns: *conc * 2, MaxIdleConnsPerHost: *conc * 2, MaxConnsPerHost: *conc * 2, IdleConnTimeout: 60 * time.Second,
		DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, DisableCompression: true,
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	endpoint := *url + "/v1/calls/score"

	// Проверка доступности до начала замеров.
	if resp, err := client.Get(*url + "/health"); err != nil || resp.StatusCode != 200 {
		log.Fatalf("сервис недоступен: %v", err)
	} else {
		_ = resp.Body.Close()
	}

	var counter atomic.Uint64
	var stop atomic.Bool
	total := *warm + *dur
	start := time.Now()
	measureFrom := start.Add(*warm)
	interval := time.Duration(0)
	if *rps > 0 {
		interval = time.Second / time.Duration(*rps)
	}

	results := make([][]sample, *conc)
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			gen := newGen(*seed+uint64(w)*7919, *pool, *suspects)
			buf := make([]byte, 0, 512)
			local := make([]sample, 0, 1<<16)
			defer func() { results[w] = local }() // и при досрочном выходе в открытой модели
			for !stop.Load() {
				n := counter.Add(1) - 1
				sched := time.Now()
				if interval > 0 { // открытая модель: запрос n должен уйти в start + n*interval
					sched = start.Add(time.Duration(n) * interval)
					if sched.After(start.Add(total)) {
						return
					}
					// time.Sleep не годится для интервалов в десятки микросекунд (гранулярность таймера):
					// крупные паузы отсыпаем, последние сотни микросекунд ждём, уступая процессор.
					for {
						d := time.Until(sched)
						if d <= 0 {
							break
						}
						if d > 500*time.Microsecond {
							time.Sleep(d - 300*time.Microsecond)
						} else {
							runtime.Gosched()
						}
					}
				}
				buf = gen.body(buf, n)
				req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(buf))
				req.Header.Set("Content-Type", "application/json")
				if *apiKey != "" {
					req.Header.Set("X-API-Key", *apiKey)
				}
				status := int16(0)
				if resp, err := client.Do(req); err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					status = int16(resp.StatusCode)
				}
				if !sched.Before(measureFrom) {
					local = append(local, sample{lat: time.Since(sched), status: status})
				}
			}
		}(w)
	}
	time.Sleep(total)
	stop.Store(true)
	wg.Wait()

	var all []sample
	for _, r := range results {
		all = append(all, r...)
	}
	report(all, *dur, *conc, *rps)
}

func report(all []sample, dur time.Duration, conc, rps int) {
	if len(all) == 0 {
		fmt.Println("нет результатов")
		return
	}
	statuses := map[int16]int{}
	lats := make([]time.Duration, 0, len(all))
	var sum time.Duration
	for _, s := range all {
		statuses[s.status]++
		if s.status == 200 {
			lats = append(lats, s.lat)
			sum += s.lat
		}
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	q := func(p float64) time.Duration {
		if len(lats) == 0 {
			return 0
		}
		return lats[min(len(lats)-1, int(float64(len(lats))*p))]
	}
	mode := "закрытая модель (максимум)"
	if rps > 0 {
		mode = fmt.Sprintf("открытая модель, цель %d запросов/с", rps)
	}
	fmt.Printf("\nНагрузочный тест: %s, %d соединений, %s\n", mode, conc, dur)
	fmt.Printf("  запросов:       %d (успешных %d)\n", len(all), statuses[200])
	fmt.Printf("  пропускная:     %.0f запросов/с\n", float64(len(all))/dur.Seconds())
	if len(lats) > 0 {
		fmt.Printf("  задержка:       среднее %s | p50 %s | p90 %s | p99 %s | p99.9 %s | max %s\n", round(sum/time.Duration(len(lats))),
			round(q(0.5)), round(q(0.9)), round(q(0.99)), round(q(0.999)), round(lats[len(lats)-1]))
	}
	if len(statuses) > 1 || statuses[200] != len(all) {
		fmt.Printf("  статусы:        %v (0 — сетевая ошибка или таймаут)\n", statuses)
	}
}

func round(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return d.Round(time.Microsecond).String()
	case d < time.Second:
		return d.Round(10 * time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}
