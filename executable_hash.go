package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type executableHashCacheKey struct {
	Path             string
	Size             int64
	ModificationTime time.Time
}

type executableHashCache struct {
	entries map[executableHashCacheKey]string
	hash    func(string) (string, error)
}

func newExecutableHashCache() *executableHashCache {
	return &executableHashCache{
		entries: make(map[executableHashCacheKey]string),
		hash:    hashFileSHA256,
	}
}

func (cache *executableHashCache) SHA256(path string) (string, error) {
	before, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat file before hashing: %w", err)
	}

	key := executableHashCacheKey{
		Path:             path,
		Size:             before.Size(),
		ModificationTime: before.ModTime(),
	}

	if hash, ok := cache.entries[key]; ok {
		return hash, nil
	}

	hash, err := cache.hash(path)
	if err != nil {
		return "", err
	}

	after, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat file after hashing: %w", err)
	}

	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", errors.New("file changed while hashing")
	}

	cache.entries[key] = hash
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
