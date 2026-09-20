package findings

import (
	"crypto/rand"
	"fmt"
)

func NewScanID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("scan-%x", b)
}
