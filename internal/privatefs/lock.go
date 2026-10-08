package privatefs

import (
	"errors"
	"os"
	"path/filepath"
)

func Lock(dir, name string) (func(), error) {
	if err := Dir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name+".lock")
	if err := File(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = File(path); err == nil {
		err = lock(f)
	}
	if err != nil {
		f.Close()
		return nil, errors.New("state_already_in_use")
	}
	return func() { _ = f.Close() }, nil
}
