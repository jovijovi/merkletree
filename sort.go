package merkletree

import (
	"bytes"
)

func (obj *Leaves) Len() int           { return len(*obj) }
func (obj *Leaves) Less(i, j int) bool { return bytes.Compare((*obj)[i].Hash, (*obj)[j].Hash) == -1 }
func (obj *Leaves) Swap(i, j int)      { (*obj)[i], (*obj)[j] = (*obj)[j], (*obj)[i] }
