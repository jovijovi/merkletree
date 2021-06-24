package merkletree_test

import (
	"crypto/sha256"
	"testing"

	"github.com/jovijovi/merkletree"
)

// TestContent implements the Content interface provided by merkle tree and represents the content stored in the tree.
type TestContent struct {
	x string
}

// CalculateHash hashes the values of a TestContent
func (t TestContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents
func (t TestContent) Equals(other merkletree.Content) (bool, error) {
	return t.x == other.(TestContent).x, nil
}

func TestMerkleTree(t *testing.T) {
	// Build list of Content to build tree
	var list []merkletree.Content
	list = append(list, TestContent{x: "Hello"})
	list = append(list, TestContent{x: "Hi"})
	list = append(list, TestContent{x: "Hey"})
	list = append(list, TestContent{x: "Hola"})

	// Create a new Merkle Tree from the list of Content
	tree, err := merkletree.NewTree(list, merkletree.WithHashFunc(sha256.New))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("MerkleTree=\n", tree)

	// bytes, err := json.Marshal(tree)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// t.Log("Tree=", bytes)

	// Get the Merkle Root of the tree
	root := tree.MerkleRoot()
	t.Log("MerkleRoot=", root)

	// Verify the entire tree (hashes for each node) is valid
	verifyTreeResult, err := tree.VerifyTree()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("VerifyTree=", verifyTreeResult)

	// Verify a specific content in in the tree
	verifyPayloadResult, err := tree.VerifyContent(list[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Log("VerifyPayload=", verifyPayloadResult)

	// Get merkle path
	mtPath, index, err := tree.GetMerklePath(TestContent{x: "Hello"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Merkle Path=", mtPath)
	t.Log("Merkle Path(index)=", index)
}
