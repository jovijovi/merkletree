package merkletree

import (
	"context"

	"golang.org/x/crypto/sha3"
)

// Options for func
type Options struct {
	// Hash function
	HashFunc HashFunc

	// Options for implementations of the interface can be stored in a context
	Context context.Context
}

// OptionFunc used to initialise
type OptionFunc func(opts *Options)

// NewOptions new options
func NewOptions(optionFunc ...OptionFunc) Options {
	opts := Options{
		Context:  context.Background(),
		HashFunc: sha3.NewLegacyKeccak256,
	}

	for _, f := range optionFunc {
		f(&opts)
	}

	return opts
}

// WithHashFunc option to configure hash function
func WithHashFunc(hashFunc HashFunc) OptionFunc {
	return func(o *Options) {
		o.HashFunc = hashFunc
	}
}
