package cryptutil

import (
	"github.com/mayef/cms"
	"github.com/pkg/errors"
)

func Compress(data []byte) ([]byte, error) {
	return cms.Compress(data)
}

func Decompress(data []byte) ([]byte, error) {
	p7, err := cms.Parse(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return p7.Decompress()
}
