package merkle_test

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jovijovi/merkletree/merkle"
	"github.com/stretchr/testify/assert"
)

type CustomHashFunc struct {
	merkle.HashFunc
}

func (h *CustomHashFunc) Hash(msg []byte) ([]byte, error) {
	provider := h.Provider()
	if _, err := provider.Write(msg); err != nil {
		return nil, err
	}

	return provider.Sum(nil), nil
}

func GetCustomHashFunc() merkle.IHashFunc {
	customHashFunc := new(CustomHashFunc)
	customHashFunc.Provider = sha256.New
	return customHashFunc
}

func TestA(t *testing.T) {
	leaves := merkle.Leaves{
		merkle.Leaf{
			Degree:  1,
			Payload: []byte("Hello"),
		},
		merkle.Leaf{
			Degree:  1,
			Payload: []byte("Hi"),
		},
		merkle.Leaf{
			Degree:  1,
			Payload: []byte("Hey"),
		},
		merkle.Leaf{
			Degree:  1,
			Payload: []byte("Hola"),
		},
		merkle.Leaf{
			Degree:  1,
			Payload: []byte("你好"),
		},
	}

	// Build tree with default hash func
	if root, err := leaves.BuildTree(); err != nil {
		t.Fatal(err)
	} else {
		t.Log("Root=", root)
	}

	// Build tree with specified hash func
	if root, err := leaves.BuildTree(merkle.WithHashFunc(GetCustomHashFunc())); err != nil {
		t.Fatal(err)
	} else {
		t.Log("Root=", root)
	}

	// Build tree again
	root, err := leaves.BuildTree(merkle.WithHashFunc(GetCustomHashFunc()))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Root=", root)

	bytes, err := root.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Marshal=", bytes)

	t.Log("MarshalString=", string(bytes))

	var rootClone merkle.Root
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
