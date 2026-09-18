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

type ProcessSnapshotEntry struct {
	PID       uint32
	ParentPID uint32
	Name      string
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

func enumerateProcesses() (processes []ProcessSnapshotEntry, err error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(
		syscall.TH32CS_SNAPPROCESS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("create process snapshot: %w", err)
	}

	defer func() {
		closeErr := syscall.CloseHandle(snapshot)
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close process snapshot: %w", closeErr)
		}
	}()

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := syscall.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
			return processes, nil
		}

		return nil, fmt.Errorf("read first process snapshot entry: %w", err)
	}

	for {
		processes = append(processes, ProcessSnapshotEntry{
			PID:       entry.ProcessID,
			ParentPID: entry.ParentProcessID,
			Name:      syscall.UTF16ToString(entry.ExeFile[:]),
		})

		err := syscall.Process32Next(snapshot, &entry)
		if err == nil {
			continue
		}

		if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
			break
		}

		return nil, fmt.Errorf("read next process snapshot entry: %w", err)
	}

	return processes, nil
}
