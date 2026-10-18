package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
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
	file, err := os.Open(path)
	if err != nil {
		return ExecutableFileIdentity{}, fmt.Errorf("open file: %w", err)
	}

	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close file: %w", closeErr)
		}
	}()

	var info fileIDInfo

	result, _, callErr := procGetFileInformationByHandleEx.Call(
		file.Fd(),
		fileIDInfoClass,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if result == 0 {
		if callErr == syscall.Errno(0) {
			return ExecutableFileIdentity{}, fmt.Errorf(
				"GetFileInformationByHandleEx failed",
			)
		}

		return ExecutableFileIdentity{}, callErr
	}

	return ExecutableFileIdentity{
		VolumeSerialNumber: info.VolumeSerialNumber,
		FileID:             info.FileID,
	}, nil
}
