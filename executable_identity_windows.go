package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const fileIDInfoClass = 0x12

var procGetFileInformationByHandleEx = kernel32.NewProc(
	"GetFileInformationByHandleEx",
)

type ExecutableFileIdentity struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type ExecutableFileState struct {
	Identity         ExecutableFileIdentity
	Size             int64
	ModificationTime time.Time
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

func (identity ExecutableFileIdentity) String() string {
	return fmt.Sprintf(
		"volume=%016X file=%s",
		identity.VolumeSerialNumber,
		hex.EncodeToString(identity.FileID[:]),
	)
}

func executableFileIdentity(path string) (identity ExecutableFileIdentity, err error) {
	state, err := executableFileState(path)
	if err != nil {
		return ExecutableFileIdentity{}, err
	}

	return state.Identity, nil
}

func executableFileState(path string) (state ExecutableFileState, err error) {
	file, err := os.Open(path)
	if err != nil {
		return ExecutableFileState{}, fmt.Errorf("open file: %w", err)
	}

	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close file: %w", closeErr)
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return ExecutableFileState{}, fmt.Errorf("stat file: %w", err)
	}

	var fileIdentityInfo fileIDInfo

	result, _, callErr := procGetFileInformationByHandleEx.Call(
		file.Fd(),
		fileIDInfoClass,
		uintptr(unsafe.Pointer(&fileIdentityInfo)),
		unsafe.Sizeof(fileIdentityInfo),
	)
	if result == 0 {
		if callErr == syscall.Errno(0) {
			return ExecutableFileState{}, fmt.Errorf(
				"GetFileInformationByHandleEx failed",
			)
		}

		return ExecutableFileState{}, callErr
	}

	return ExecutableFileState{
		Identity: ExecutableFileIdentity{
			VolumeSerialNumber: fileIdentityInfo.VolumeSerialNumber,
			FileID:             fileIdentityInfo.FileID,
		},
		Size:             info.Size(),
		ModificationTime: info.ModTime(),
	}, nil
}
