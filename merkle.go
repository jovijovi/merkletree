package merkletree

import (
	"bytes"
	"encoding/json"
	"errors"
	"hash"
	"sort"

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

type Hash = []byte

type Tree [][]Hash

type Node struct {
	Height  int
	Hash    []byte
	Left    *Node
	Right   *Node
	Payload []byte
}

type Leaf = Node

type Root = Node

func NewLeaf() Leaf {
	return Leaf{
		Height: 0,
	}
}

// Clone returns a clone of the leaf
func (node *Leaf) Clone() *Leaf {
	if node == nil {
		return nil
	}

	clone := NewLeaf()
	clone.Height = node.Height
	clone.Hash = node.Hash
	clone.Left = node.Left
	clone.Right = node.Right
	clone.Payload = node.Payload

	return &clone
}

// Marshal returns bytes of tree
func (node *Root) Marshal() ([]byte, error) {
	return json.Marshal(node)
}

type Leaves []Leaf

// Length returns length of leaves
func (obj *Leaves) Length() int {
	if obj == nil {
		return 0
	}

	return len(*obj)
}

// IsEmpty returns if leaves if empty
func (obj *Leaves) IsEmpty() bool {
	return obj.Length() == 0
}

// LastLeaf returns the last leaf
func (obj *Leaves) LastLeaf() *Leaf {
	if obj == nil {
		return nil
	}

	return &(*obj)[obj.Length()-1]
}

// BuildTree build tree by options, returns tree & root
func (obj *Leaves) BuildTree(opt ...OptionFunc) (*Tree, *Root, error) {
	if obj == nil || obj.IsEmpty() {
		return nil, nil, errors.New("not found leaf")
	}
	opts := NewOptions(opt...)

	h := opts.HashFunc

	if !opts.SkipHash {
		if err := obj.Hash(h); err != nil {
			return nil, nil, err
		}
	}

	if obj.Length()%2 == 1 {
		clone := obj.LastLeaf().Clone()
		*obj = append(*obj, *clone)
	}

	tree, err := obj.initTree()
	if err != nil {
		return nil, nil, err
	}

	root, err := obj.buildBranch(*obj, tree, h)
	if err != nil {
		return nil, nil, err
	}

	return tree, root, nil
}

// Hash calc hash of leaves
func (obj *Leaves) Hash(h IHashFunc) error {
	for i := 0; i < obj.Length(); i++ {
		digest, err := h.Hash((*obj)[i].Payload)
		if err != nil {
			return err
		}

		(*obj)[i].Hash = digest
	}

	return nil
}

// Sort leaves by hash
func (obj *Leaves) Sort() {
	sort.Sort(obj)
}

// Add leaf to leaves
func (obj *Leaves) Add(leaf *Leaf) {
	if obj == nil || leaf == nil {
		return
	}
	*obj = append(*obj, *leaf)
}

// Clone returns a clone of the leaves
func (obj *Leaves) Clone() *Leaves {
	if obj == nil {
		return nil
	}

	leaves := make(Leaves, 0)
	for _, leaf := range *obj {
		if clone := leaf.Clone(); clone != nil {
			leaves = append(leaves, *clone)
		}
	}

	if obj.Length() != leaves.Length() {
		return nil
	}

	return &leaves
}

// initTree init a tree
func (obj *Leaves) initTree() (*Tree, error) {
	if obj.Length() == 0 {
		return nil, errors.New("not found")
	}

	tree := make(Tree, 1)
	hashSet := make([]Hash, obj.Length())

	for i := 0; i < obj.Length(); i++ {
		hashSet[i] = (*obj)[i].Hash
	}

	tree[0] = hashSet

	return &tree, nil
}

// buildBranch build branch, fill the tree & returns root
func (obj *Leaves) buildBranch(nodes []Node, tree *Tree, h IHashFunc) (*Root, error) {
	var branches []Node
	var hashSet []Hash

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
			Height: nodes[left].Height + 1,
			Hash:   digest,
			Left:   &nodes[left],
			Right:  &nodes[right],
		}

		branches = append(branches, branch)
		hashSet = append(hashSet, digest)

		if length == 2 {
			*tree = append(*tree, hashSet)
			return &branch, nil
		}
	}

	*tree = append(*tree, hashSet)

	return obj.buildBranch(branches, tree, h)
}

/***************************
     Y
     ^
     |
     +------------
2    | 0 |   |   |
     +------------
1    | 0 | 1 |   |
     +------------
0    | 0 | 1 | 2 |
   --+-----------------> X
     | 0   1   2
***************************/

// Marshal returns bytes of tree
func (tree *Tree) Marshal() ([]byte, error) {
	if tree == nil {
		return nil, errors.New("tree is empty")
	}
	return json.Marshal(tree)
}

// Height returns height of tree
func (tree *Tree) Height() uint64 {
	if tree == nil {
		return 0
	}
	return uint64(len(*tree))
}

// Width returns width of tree by y
func (tree *Tree) Width(y uint64) uint64 {
	if tree == nil || tree.Height() == 0 {
		return 0
	}

	return uint64(len((*tree)[y]))
}

// Y returns value of 'y'
func (tree *Tree) Y() uint64 {
	if tree == nil || tree.Height() == 0 {
		return 0
	}
	return tree.Height() - 1
}

// X returns value of 'x'
func (tree *Tree) X(y uint64) uint64 {
	if tree == nil || tree.Height() == 0 {
		return 0
	}
	return tree.Width(y) - 1
}

// GetRootHash returns root hash
func (tree *Tree) GetRootHash() ([]byte, error) {
	if tree == nil || tree.Height() == 0 {
		return nil, errors.New("tree is empty")
	}

	return (*tree)[tree.Y()][0], nil
}

// GetHash returns hash by (y,x)
func (tree *Tree) GetHash(y uint64, x uint64) ([]byte, error) {
	if tree == nil || tree.Height() == 0 {
		return nil, errors.New("tree is empty")
	} else if y > tree.Y() {
		return nil, errors.New("invalid y")
	} else if x > tree.X(y) {
		return nil, errors.New("invalid x")
	}

	return (*tree)[y][x], nil
}

// Prove returns merkle proofs result
func (tree *Tree) Prove(merklePath *PoNs, unverifiedHash []byte, h IHashFunc) (bool, error) {
	digest := unverifiedHash

	for _, pon := range *merklePath {
		brother, err := tree.GetHash(pon[0], pon[1])
		if err != nil {
			return false, err
		}

		if pon[1]%2 == 0 {
			digest, err = h.Hash(append(brother, digest...))
		} else {
			digest, err = h.Hash(append(digest, brother...))
		}
		if err != nil {
			return false, err
		}
	}

	rootHash, err := tree.GetRootHash()
	if err != nil {
		return false, err
	}

	return bytes.Compare(rootHash, digest) == 0, nil
}

// PoN is position of node, PoN[0] is y, PoN[1] is x
type PoN [2]uint64

// PoNs is positions of nodes, from leaf to the root
type PoNs []PoN

// GetParent returns parent of node
func (pon PoN) GetParent() PoN {
	return PoN{pon[0] + 1, pon[1] / 2}
}

// GetPath returns merkle path, pons is Positions Of Nodes
func (pons *PoNs) GetPath(height uint64, y uint64, x uint64) {
	pon := PoN{y}
	if x%2 == 0 {
		pon[1] = x + 1
	} else {
		pon[1] = x - 1
	}

	if y == height-1 {
		return
	}

	*pons = append(*pons, pon)

	parent := pon.GetParent()

	pons.GetPath(height, parent[0], parent[1])
}
