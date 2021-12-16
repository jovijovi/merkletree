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

	var invalidLeaves1 *merkletree.Leaves
	_, _, err = invalidLeaves1.BuildTree()
	if err != nil {
		t.Log("leaves1 is nil, build tree failed as expected")
	}
	assert.NotNil(t, err)

	var invalidLeaves2 merkletree.Leaves
	_, _, err = invalidLeaves2.BuildTree()
	if err != nil {
		t.Log("leaves2 is empty, build tree failed as expected")
	}
	assert.NotNil(t, err)
}

// Build tree with sorted leaves
func TestLeaves_BuildTree_WithSort(t *testing.T) {
	// Clone the MockLeaves
	leaves := MockLeaves.Clone()
	if err := leaves.Hash(GetCustomHashFunc()); err != nil {
		t.Fatal(err)
	}
	t.Log("Leaves=\n", leaves)
	// Sort the leaves
	leaves.Sort()
	t.Log("Leaves(Sorted)=\n", leaves)
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

	// Test invalid tree
	var invalidTree1 *merkletree.Tree
	_, err = invalidTree1.Marshal()
	if err != nil {
		t.Log("tree is nil, marshal tree failed as expected")
	}
	assert.NotNil(t, err)
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

// Clone leaf
func TestLeaf_Clone(t *testing.T) {
	clone1 := MockLeaves[0].Clone()
	if clone1 == nil {
		t.Fatal("clone leaf failed")
	}
	assert.Equal(t, *clone1, MockLeaves[0])

	var invalidLeaf *merkletree.Leaf = nil
	clone2 := invalidLeaf.Clone()
	if clone2 == nil {
		t.Log("leaf is nil, clone failed as expected.")
	}
	assert.Nil(t, clone2)
}

// Get length of leaves
func TestLeaves_Length(t *testing.T) {
	len1 := MockLeaves.Length()
	if len1 == 0 {
		t.Fatal("get length of leaves failed")
	}
	assert.NotZero(t, len1)

	var invalidLeaves *merkletree.Leaves
	len2 := invalidLeaves.Length()
	if len2 == 0 {
		t.Log("leaves is nil, get length failed as expected.")
	}
	assert.Zero(t, len2)
}

// Get last leaf
func TestLeaves_LastLeaf(t *testing.T) {
	leaf1 := MockLeaves.LastLeaf()
	if leaf1 == nil {
		t.Fatal("get last leaf failed")
	}
	assert.NotNil(t, leaf1)

	var invalidLeaves *merkletree.Leaves
	leaf2 := invalidLeaves.LastLeaf()
	if leaf2 == nil {
		t.Log("leaves is nil, get last leaf failed as expected")
	}
	assert.Nil(t, leaf2)
}

// Add leaf to leaves
func TestLeaves_Add(t *testing.T) {
	// Test add leaf
	var leaves merkletree.Leaves
	leaves.Add(&merkletree.Leaf{})
	leavesLen := leaves.Length()
	assert.NotZero(t, leaves.Length())

	// Test add nil leaf
	var nilLeaf *merkletree.Leaf = nil
	leaves.Add(nilLeaf)
	assert.Equal(t, leavesLen, leaves.Length())

	var invalidLeaves *merkletree.Leaves
	invalidLeaves.Add(&merkletree.Leaf{})
	assert.Zero(t, invalidLeaves.Length())
}

// Clone leaves
func TestLeaves_Clone(t *testing.T) {
	clone1 := MockLeaves.Clone()
	if clone1 == nil {
		t.Fatal("clone leaves failed")
	}
	assert.Equal(t, *clone1, MockLeaves)

	var invalidLeaves *merkletree.Leaves
	clone2 := invalidLeaves.Clone()
	if clone2 == nil {
		t.Log("leaves is nil, clone failed as expected")
	}
	assert.Nil(t, clone2)
}

// Get tree height
func TestTree_Height(t *testing.T) {
	leaves := MockLeaves

	// Build tree
	tree1, _, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree1=", tree1)

	// Test get tree height
	height1 := tree1.Height()
	if height1 == 0 {
		t.Fatal("invalid tree, get tree height failed")
	}
	assert.NotZero(t, height1)

	// Test invalid tree
	var invalidTree1 *merkletree.Tree
	height2 := invalidTree1.Height()
	if height2 == 0 {
		t.Log("tree is nil, get tree height failed as expected")
	}
	assert.Zero(t, height2)
}

// Get tree width
func TestTree_Width(t *testing.T) {
	leaves := MockLeaves

	// Build tree
	tree1, _, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree1=", tree1)

	// Test get tree width
	width1 := tree1.Width(0)
	if width1 == 0 {
		t.Fatal("invalid tree, get tree width failed")
	}
	assert.NotZero(t, width1)

	// Test invalid tree
	var invalidTree1 *merkletree.Tree
	width2 := invalidTree1.Width(0)
	if width2 == 0 {
		t.Log("tree is nil, get tree width failed as expected")
	}
	assert.Zero(t, width2)

	// Test empty tree
	var invalidTree2 merkletree.Tree
	width3 := invalidTree2.Width(0)
	if width3 == 0 {
		t.Log("tree is empty, get tree width failed as expected")
	}
	assert.Zero(t, width3)
}

// Get tree Y
func TestTree_Y(t *testing.T) {
	leaves := MockLeaves

	// Build tree
	tree1, _, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree1=", tree1)

	// Test get Y
	y1 := tree1.Y()
	if y1 == 0 {
		t.Fatal("invalid tree, get Y failed")
	}
	assert.NotZero(t, y1)

	// Test invalid tree
	var invalidTree1 *merkletree.Tree
	y2 := invalidTree1.Y()
	if y2 == 0 {
		t.Log("tree is nil, get Y failed as expected")
	}
	assert.Zero(t, y2)

	// Test empty tree
	var invalidTree2 merkletree.Tree
	y3 := invalidTree2.Y()
	if y3 == 0 {
		t.Log("tree is empty, get Y failed as expected")
	}
	assert.Zero(t, y3)
}

// Get tree X
func TestTree_X(t *testing.T) {
	leaves := MockLeaves

	// Build tree
	tree1, _, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree1=", tree1)

	// Test get X
	x1 := tree1.X(0)
	if x1 == 0 {
		t.Fatal("invalid tree, get X failed")
	}
	assert.NotZero(t, x1)

	// Test invalid tree
	var invalidTree1 *merkletree.Tree
	x2 := invalidTree1.X(0)
	if x2 == 0 {
		t.Log("tree is nil, get X failed as expected")
	}
	assert.Zero(t, x2)

	// Test empty tree
	var invalidTree2 merkletree.Tree
	x3 := invalidTree2.X(0)
	if x3 == 0 {
		t.Log("tree is empty, get X failed as expected")
	}
	assert.Zero(t, x3)
}
