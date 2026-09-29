package ingest

import "os"

func osWrite(p, body string) error { return os.WriteFile(p, []byte(body), 0o644) }
