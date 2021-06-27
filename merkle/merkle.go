package merkle

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/sha3"
)

type HashProvider func() hash.Hash

type IHashFunc interface {
	Hash(msg []byte) ([]byte, error)
}

type ITree interface {
	BuildTree(opt ...OptionFunc) error
}

type HashFunc struct {
	Provider HashProvider
}

func (h *HashFunc) Hash(msg []byte) ([]byte, error) {
	provider := h.Provider()
	if _, err := provider.Write(msg); err != nil {
		return nil, err
	}

	return provider.Sum(nil), nil
}

func DefaultHashFunc() IHashFunc {
	hashFunc := new(HashFunc)
	hashFunc.Provider = sha3.NewLegacyKeccak256
	return hashFunc
}

type Node struct {
	Degree  int
	Hash    []byte
	Left    *Node
	Right   *Node
	Payload []byte
}

type Leaf = Node

type Root = Node

func NewLeaf() Leaf {
	return Leaf{
		Degree: 1,
	}
}

type Leaves []Leaf

func (obj *Leaves) Length() int {
	if obj == nil {
		return 0
	}

	return len(*obj)
}

func (obj *Leaves) LastLeaf() *Leaf {
	if obj == nil {
		return nil
	}

	return &(*obj)[obj.Length()-1]
}

func (obj *Leaves) Clone(leaf *Leaf) *Leaf {
	clone := NewLeaf()
	clone.Degree = leaf.Degree
	clone.Hash = leaf.Hash
	clone.Payload = leaf.Payload
	return &clone
}

func (obj *Leaves) BuildTree(opt ...OptionFunc) (*Root, error) {
	if obj == nil {
		return nil, errors.New("not found leaf")
	}
	opts := NewOptions(opt...)

	h := opts.HashFunc

	if !opts.SkipHash {
		for i := 0; i < obj.Length(); i++ {
			digest, err := h.Hash((*obj)[i].Payload)
			if err != nil {
				return nil, err
			}

			(*obj)[i].Hash = digest

			// TODO:
			fmt.Println(fmt.Sprintf("Payload=%s, Digest=%v", (*obj)[i].Payload, (*obj)[i].Hash))
		}
	}

	if obj.Length()%2 == 1 {
		clone := obj.Clone(obj.LastLeaf())
		*obj = append(*obj, *clone)
	}

	root, err := obj.buildBranch(*obj, h)
	if err != nil {
		return nil, err
	}

	return root, nil
}

func (obj *Leaves) buildBranch(nodes []Node, h IHashFunc) (*Root, error) {
	var branches []Node

	length := len(nodes)

	for i := 0; i < length; i += 2 {
		left, right := i, i+1
		if length == i+1 {
			right = i
		}

		digest, err := h.Hash(append(nodes[left].Hash, nodes[right].Hash...))
		if err != nil {
			return nil, err
		}

		branch := Node{
			Degree: nodes[left].Degree + 1,
			Hash:   digest,
			Left:   &nodes[left],
			Right:  &nodes[right],
		}

		branches = append(branches, branch)

		if length == 2 {
			return &branch, nil
		}
	}

	return obj.buildBranch(branches, h)
}

func (root *Root) Marshal() ([]byte, error) {
	return json.Marshal(root)
}
