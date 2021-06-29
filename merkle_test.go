package merkletree_test

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jovijovi/merkletree"
	"github.com/stretchr/testify/assert"
)

var (
	// Leaves for building merkle tree
	MockLeaves = merkletree.Leaves{
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("Hello"),
		},
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("Привет"),
		},
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("你好"),
		},
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("こんにちは"),
		},
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("안녕하세요"),
		},
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("สวัสดี"),
		},
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("Bonjour"),
		},
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("Hola"),
		},
		merkletree.Leaf{
			Height:  0,
			Payload: []byte("Hallo"),
		},
	}

	// Hash(sha256) of 你好
	goodHash = []byte{103, 13, 151, 67, 84, 44, 174, 62, 167, 235, 227, 106, 245, 107, 213, 54, 72, 176, 161, 18, 97, 98, 231, 141, 129, 163, 41, 52, 167, 17, 48, 46}

	// Bad hash sample
	badHash = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
)

type CustomHashFunc struct {
	merkletree.HashFunc
}

// Custom impl of hash
func (h *CustomHashFunc) Hash(msg []byte) ([]byte, error) {
	provider := h.Provider()
	if _, err := provider.Write(msg); err != nil {
		return nil, err
	}

	return provider.Sum(nil), nil
}

// GetCustomHashFunc returns custom hash func
func GetCustomHashFunc() merkletree.IHashFunc {
	customHashFunc := new(CustomHashFunc)
	customHashFunc.Provider = sha256.New
	return customHashFunc
}

// Build tree with default hash func
func TestLeaves_BuildTree_Simple(t *testing.T) {
	leaves := MockLeaves
	tree, root, err := leaves.BuildTree()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree=", tree)
	t.Log("Root=", root)
}

// Build tree without hash(skip hash)
func TestLeaves_BuildTree_SkipHash(t *testing.T) {
	leaves := MockLeaves
	if err := leaves.Hash(GetCustomHashFunc()); err != nil {
		t.Fatal(err)
	}

	tree, root, err := leaves.BuildTree(merkletree.WithSkipHash(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree=", tree)
	t.Log("Root=", root)

	rootHash, err := tree.GetRootHash()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("TreeRootHash=", rootHash)

	assert.Equal(t, rootHash, root.Hash)
}

// Build tree with specified hash func
func TestLeaves_BuildTree_WithCustomHashFunc(t *testing.T) {
	leaves := MockLeaves

	// Build tree
	tree1, root1, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree1=", *tree1)
	t.Log("Root1=", *root1)

	// Build tree again
	tree2, root2, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree2=", *tree2)
	t.Log("Root2=", *root2)

	assert.Equal(t, *tree1, *tree2)
	assert.Equal(t, *root1, *root2)
}

// Root marshal
func TestRoot_Marshal(t *testing.T) {
	leaves := MockLeaves

	// Build tree, get root1
	_, root1, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Root_1=", *root1)

	// Marshal root1, get bytes1
	bytes1, err := root1.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("RootMarshal_1=", bytes1)
	t.Log("RootMarshalString_1=", string(bytes1))

	// Unmarshal bytes1, get root2
	var root2 merkletree.Root
	if err := json.Unmarshal(bytes1, &root2); err != nil {
		t.Fatal(err)
	}
	t.Log("Root_2=", root2)

	// Marshal root2, get bytes2
	bytes2, err := root2.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("RootMarshal_2=", bytes2)
	t.Log("RootMarshalString_2=", string(bytes2))

	// Check equal
	assert.Equal(t, bytes1, bytes2)
}

// Tree marshal
func TestTree_Marshal(t *testing.T) {
	leaves := MockLeaves

	// Build tree
	tree1, _, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree1=", tree1)

	// Marshal tree1
	bytes1, err := tree1.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("TreeMarshal_1=", bytes1)
	t.Log("TreeMarshalString_1=", string(bytes1))

	var tree2 merkletree.Tree
	if err := json.Unmarshal(bytes1, &tree2); err != nil {
		t.Fatal(err)
	}
	t.Log("Tree2=", tree2)

	bytes2, err := tree2.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("TreeMarshal_2=", bytes2)
	t.Log("TreeMarshalString_2=", string(bytes2))

	assert.Equal(t, bytes1, bytes2)
}

// Get hash from tree by coordinate(y, x)
func TestTree_GetHash(t *testing.T) {
	leaves := MockLeaves
	tree, _, err := leaves.BuildTree()
	if err != nil {
		t.Fatal(err)
	}

	hash1, err := tree.GetHash(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Hash1=", hash1)

	hash2, err := tree.GetHash(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Hash2=", hash2)
}

// Calculate merkle path
func TestPoNs_GetPath(t *testing.T) {
	pons := make(merkletree.PoNs, 0)
	pons.GetPath(5, 0, 1)
	t.Log("MerklePath=", pons)
}

// Merkle proofs
func TestTree_Prove(t *testing.T) {
	leaves := MockLeaves

	// Build tree
	tree, root, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("RootHash=", root.Hash)
	t.Log("RootHash(hex)=", merkletree.Hex(root.Hash))

	// Get merkle path
	merklePath := make(merkletree.PoNs, 0)
	merklePath.GetPath(tree.Height(), 0, 2)
	t.Log("MerklePath=", merklePath)

	// Prove hash is good
	resultGood, err := tree.Prove(&merklePath, goodHash, GetCustomHashFunc())
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Result=", resultGood)
	assert.Equal(t, true, resultGood)

	// Prove hash is bad
	resultBad, err := tree.Prove(&merklePath, badHash, GetCustomHashFunc())
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Result=", resultBad)
	assert.Equal(t, false, resultBad)
}
