package merkletree

import (
	"bytes"
)

func (obj *Leaves) Len() int {
	if obj == nil {
		return 0
	}
	return len(*obj)
}

func (obj *Leaves) Less(i, j int) bool {
	if obj == nil {
		return false
	}
	return bytes.Compare((*obj)[i].Hash, (*obj)[j].Hash) == -1
}

func (obj *Leaves) Swap(i, j int) {
	if obj == nil {
		return
	}
	(*obj)[i], (*obj)[j] = (*obj)[j], (*obj)[i]
}
