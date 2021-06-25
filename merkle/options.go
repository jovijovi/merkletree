package merkle

import (
	"context"
)

// Options for func
type Options struct {
	// HashFunc interface
	HashFunc IHashFunc

	// Options for implementations of the interface can be stored in a context
	Context context.Context
}

// OptionFunc used to initialise
type OptionFunc func(opts *Options)

// NewOptions new options
func NewOptions(optionFunc ...OptionFunc) Options {
	opts := Options{
		Context:  context.Background(),
		HashFunc: DefaultHashFunc(),
	}

	for _, f := range optionFunc {
		f(&opts)
	}

	return opts
}

// WithHashFunc option to configure hash function
func WithHashFunc(hashFunc IHashFunc) OptionFunc {
	return func(o *Options) {
		o.HashFunc = hashFunc
	}
}
