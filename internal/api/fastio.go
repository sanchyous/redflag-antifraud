package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
)

// Горячий путь скоринга: буферы переиспользуются через sync.Pool (нет аллокации на запрос), ответ строится
// специализированным кодировщиком без рефлексии и уходит с Content-Length (без chunked-передачи).

const maxPooledBuf = 64 << 10 // большие буферы (крупные пакеты) в пул не возвращаются

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 4096); return &b }}

func getBuf() *[]byte { return bufPool.Get().(*[]byte) }

func putBuf(b *[]byte) {
	if cap(*b) > maxPooledBuf {
		return
	}
	*b = (*b)[:0]
	bufPool.Put(b)
}

// readBody читает тело целиком в буфер из пула. Ограничение размера задаёт http.MaxBytesReader выше по стеку.
func readBody(r io.Reader, bp *[]byte) error {
	b := (*bp)[:0]
	for {
		if len(b) == cap(b) {
			b = append(b, 0)[:len(b)]
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			*bp = b
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// decodeJSON разбирает тело запроса в v. Возвращает false, если тело не читается или не JSON нужной формы.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	bp := getBuf()
	defer putBuf(bp)
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := readBody(r.Body, bp); err != nil {
		return false
	}
	return json.Unmarshal(*bp, v) == nil
}

var contentTypeJSON = []string{"application/json"}

// setJSONHeaders задаёт тип содержимого без аллокаций (готовый срез, канонический ключ). Content-Length для одиночного
// ответа net/http выставляет сам, если тело небольшое; для пакетов задаётся явно (n > 0).
func setJSONHeaders(w http.ResponseWriter, n int) {
	h := w.Header()
	h["Content-Type"] = contentTypeJSON
	if n > 0 {
		h["Content-Length"] = []string{strconv.Itoa(n)}
	}
}

// writeScore пишет ответ скоринга быстрым кодировщиком.
func writeScore(w http.ResponseWriter, status int, resp *engine.Response) {
	bp := getBuf()
	b := resp.AppendJSON((*bp)[:0])
	b = append(b, '\n') // как у json.Encoder: удобно для curl и построчного чтения
	*bp = b
	setJSONHeaders(w, 0)
	w.WriteHeader(status)
	_, _ = w.Write(b)
	putBuf(bp)
}

// writeBatch пишет ответ пакетной обработки: {"results":[{"call_id":…,"result":{…}} | {"call_id":…,"error":"…"}]}.
func writeBatch(w http.ResponseWriter, items []batchItem) {
	bp := getBuf()
	b := append((*bp)[:0], `{"results":[`...)
	for i := range items {
		if i > 0 {
			b = append(b, ',')
		}
		it := &items[i]
		b = append(b, `{"call_id":`...)
		b = engine.AppendString(b, it.CallID)
		if it.Result != nil {
			b = append(b, `,"result":`...)
			b = it.Result.AppendJSON(b)
		}
		if it.Error != "" {
			b = append(b, `,"error":`...)
			b = engine.AppendString(b, it.Error)
		}
		b = append(b, '}')
	}
	b = append(b, ']', '}', '\n')
	*bp = b
	setJSONHeaders(w, len(b))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	putBuf(bp)
}
