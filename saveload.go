package main

import (
	"encoding/json"
	"errors"
	"os"
)

func saveJson(fp string, res any) error {
	d, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return os.WriteFile(fp, d, 0644)
}

func loadJson[T any](fp string) (ret T, err error) {
	f, err := os.Open(fp)
	if err != nil {
		return ret, err
	}
	err = json.NewDecoder(f).Decode(&ret)
	f.Close()
	return
}

func loadJsonIfExists[T any](fp string) (ret T, err error) {
	ret, err = loadJson[T](fp)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return
}
