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
	leaves = merkletree.Leaves{
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

func (h *CustomHashFunc) Hash(msg []byte) ([]byte, error) {
	provider := h.Provider()
	if _, err := provider.Write(msg); err != nil {
		return nil, err
	}

	return provider.Sum(nil), nil
}

func GetCustomHashFunc() merkletree.IHashFunc {
	customHashFunc := new(CustomHashFunc)
	customHashFunc.Provider = sha256.New
	return customHashFunc
}

func TestBuildTree(t *testing.T) {
	// Build tree with default hash func
	if tree, root, err := leaves.BuildTree(); err != nil {
		t.Fatal(err)
	} else {
		t.Log("Tree=", tree)
		rootHash, err := tree.GetRootHash()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("TreeRootHash=", rootHash)
		t.Log("Root=", root)
		assert.Equal(t, rootHash, root.Hash)
	}

	// Build tree with specified hash func
	if tree, root, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc())); err != nil {
		t.Fatal(err)
	} else {
		t.Log("Tree=", tree)
		t.Log("Root=", root)
	}

	// Build tree again
	tree, root, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Tree=", tree)
	t.Log("Root=", root)

	bytesOfTree, err := tree.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Length of TreeMarshal=", len(bytesOfTree))
	t.Log("TreeMarshal=", bytesOfTree)
	t.Log("TreeMarshalString=", string(bytesOfTree))

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

	bytes, err := root.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("RootMarshal=", bytes)

	t.Log("RootMarshalString=", string(bytes))

	var rootClone merkletree.Root
	if err := json.Unmarshal(bytes, &rootClone); err != nil {
		t.Fatal(err)
	}

	t.Log("RootClone=", rootClone)

	bytes2, err := rootClone.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Marshal2", bytes2)

	assert.Equal(t, bytes, bytes2)
}

func TestPoNs_GetPath(t *testing.T) {
	pons := make(merkletree.PoNs, 0)
	pons.GetPath(5, 0, 1)
	t.Log("MerklePath=", pons)
}

func TestTree_Prove(t *testing.T) {
	// Build tree
	tree, root, err := leaves.BuildTree(merkletree.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("RootHash=", root.Hash)

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
