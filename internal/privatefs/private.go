package privatefs

import (
	"errors"
	"os"
	"path/filepath"
)

// Dir rejects links in every existing component before creating private state.
func Dir(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for p := abs; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e == nil && (st.Mode()&os.ModeSymlink != 0 || !st.IsDir()) {
			return errors.New("unsafe state directory")
		}
		if e != nil && !os.IsNotExist(e) {
			return errors.New("state directory unavailable")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return err
	}
	return protect(abs, true)
}

func File(path string) error {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("unsafe state file")
	}
	return protect(path, false)
}

func Write(path string, data []byte) error {
	if err := Dir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := File(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tokenhub-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = protect(name, false); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
