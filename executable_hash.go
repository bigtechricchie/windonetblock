package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

type executableHashCache struct {
	entries map[ExecutableFileState]string
	hash    func(string) (string, error)
}

func newExecutableHashCache() *executableHashCache {
	return &executableHashCache{
		entries: make(map[ExecutableFileState]string),
		hash:    hashFileSHA256,
	}
}

func (cache *executableHashCache) SHA256(path string) (string, error) {
	before, err := executableFileState(path)
	if err != nil {
		return "", fmt.Errorf("inspect file before hashing: %w", err)
	}

	if hash, ok := cache.entries[before]; ok {
		return hash, nil
	}

	hash, err := cache.hash(path)
	if err != nil {
		return "", err
	}

	after, err := executableFileState(path)
	if err != nil {
		return "", fmt.Errorf("inspect file after hashing: %w", err)
	}

	if before != after {
		return "", errors.New("file changed while hashing")
	}

	cache.entries[before] = hash
	return hash, nil
}

func hashFileSHA256(path string) (hash string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}

	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close file: %w", closeErr)
		}
	}()

	hasher := sha256.New()

	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
