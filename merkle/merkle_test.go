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
		//merkle.Leaf{
		//	Degree:  1,
		//	Payload: []byte("你好"),
		//},
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

func TestB(t *testing.T) {
	leaves := merkle.Leaves{
		merkle.Leaf{
			Degree: 1,
			Hash:   []byte{24, 95, 141, 179, 34, 113, 254, 37, 245, 97, 166, 252, 147, 139, 46, 38, 67, 6, 236, 48, 78, 218, 81, 128, 7, 209, 118, 72, 38, 56, 25, 105},
		},
		merkle.Leaf{
			Degree: 1,
			Hash:   []byte{54, 57, 239, 205, 8, 171, 178, 115, 177, 97, 158, 130, 231, 140, 41, 167, 223, 2, 193, 5, 27, 24, 32, 233, 159, 195, 149, 220, 170, 51, 38, 184},
		},
		merkle.Leaf{
			Degree: 1,
			Hash:   []byte{103, 184, 144, 26, 195, 1, 53, 231, 77, 66, 3, 109, 250, 96, 67, 54, 225, 249, 120, 228, 158, 224, 214, 191, 72, 74, 70, 255, 39, 162, 174, 156},
		},
	}

	// Build tree with specified hash func
	if root, err := leaves.BuildTree(
		merkle.WithHashFunc(GetCustomHashFunc()),
		merkle.WithSkipHash(true),
	); err != nil {
		t.Fatal(err)
	} else {
		t.Log("Root=", root)
	}
}
