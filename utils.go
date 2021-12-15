package merkletree

import (
	"fmt"
)

// Hex returns a hex string
func Hex(b []byte) string {
	return fmt.Sprintf("%x", b)
}
