package main

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetCurrentProcessID       = kernel32.NewProc("GetCurrentProcessId")
	procGetCurrentProcess         = kernel32.NewProc("GetCurrentProcess")
	procQueryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
)

type ProcessInfo struct {
	PID            uint32
	ExecutablePath string
}

func inspectCurrentProcess() (ProcessInfo, error) {
	pid := currentProcessID()

	handle := currentProcessHandle()

	executablePath, err := processExecutablePath(handle)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("query executable path: %w", err)
	}

	return ProcessInfo{
		PID:            pid,
		ExecutablePath: executablePath,
	}, nil
}

func currentProcessID() uint32 {
	result, _, _ := procGetCurrentProcessID.Call()

	return uint32(result)
}

func currentProcessHandle() syscall.Handle {
	result, _, _ := procGetCurrentProcess.Call()

	return syscall.Handle(result)
}

func processExecutablePath(handle syscall.Handle) (string, error) {
	const bufferSize = 32768

	buffer := make([]uint16, bufferSize)
	size := uint32(len(buffer))

	result, _, callErr := procQueryFullProcessImageName.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if result == 0 {
		if callErr == syscall.Errno(0) {
			return "", errors.New("QueryFullProcessImageNameW failed")
		}

		return "", callErr
	}

	return syscall.UTF16ToString(buffer[:size]), nil
}
