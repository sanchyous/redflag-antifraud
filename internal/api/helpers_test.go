package api

import (
	"github.com/sanchyous/redflag-antifraud/internal/telecom/callrec"
)

func callFor(caller, callee string) *callrec.Call {
	return &callrec.Call{CallID: "x", Caller: caller, Callee: callee}
}
