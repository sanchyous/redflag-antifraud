package engine

import "github.com/sanchyous/redflag-antifraud/internal/telecom/phone"

func phoneKey(s string) (uint64, error) {
	n, err := phone.Parse(s)
	if err != nil {
		return 0, err
	}
	return n.Key(), nil
}
