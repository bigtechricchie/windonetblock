package main

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

const processQueryLimitedInformation = 0x1000

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetCurrentProcessID       = kernel32.NewProc("GetCurrentProcessId")
	procGetCurrentProcess         = kernel32.NewProc("GetCurrentProcess")
	procOpenProcess               = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
)

type ProcessInfo struct {
	PID              uint32
	CreationTime     time.Time
	ExecutablePath   string
	FileIdentity     ExecutableFileIdentity
	ExecutableSHA256 string
	Signature        ExecutableSignatureEvidence
	Security         ProcessSecurityContext
}

type ProcessSnapshotEntry struct {
	PID              uint32
	ParentPID        uint32
	Name             string
	CreationTime     time.Time
	TimingError      error
	ExecutablePath   string
	PathError        error
	FileIdentity     ExecutableFileIdentity
	IdentityError    error
	ExecutableSHA256 string
	HashError        error
	Signature        ExecutableSignatureEvidence
	SignatureError   error
	Security         ProcessSecurityContext
	SecurityError    error
}

func inspectCurrentProcess() (ProcessInfo, error) {
	pid := currentProcessID()
	handle := currentProcessHandle()

	creationTime, err := processCreationTime(handle)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("query process creation time: %w", err)
	}

	executablePath, err := processExecutablePath(handle)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("query executable path: %w", err)
	}

	fileIdentity, err := executableFileIdentity(executablePath)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("query executable file identity: %w", err)
	}

	executableSHA256, err := hashFileSHA256(executablePath)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("hash executable: %w", err)
	}

	signatureEvidence, err := verifyAuthenticodeOffline(executablePath)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("verify executable signature: %w", err)
	}

	securityContext, err := inspectProcessSecurity(handle)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("inspect security context: %w", err)
	}

	return ProcessInfo{
		PID:              pid,
		CreationTime:     creationTime,
		ExecutablePath:   executablePath,
		FileIdentity:     fileIdentity,
		ExecutableSHA256: executableSHA256,
		Signature:        signatureEvidence,
		Security:         securityContext,
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

	hashCache := newExecutableHashCache()
	signatureCache := newExecutableSignatureCache()

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := syscall.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
			return processes, nil
		}

		return nil, fmt.Errorf("read first process snapshot entry: %w", err)
	}

	for {
		processes = append(
			processes,
			inspectSnapshotEntry(entry, hashCache, signatureCache),
		)

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

func inspectSnapshotEntry(
	entry syscall.ProcessEntry32,
	hashCache *executableHashCache,
	signatureCache *executableSignatureCache,
) ProcessSnapshotEntry {
	process := ProcessSnapshotEntry{
		PID:       entry.ProcessID,
		ParentPID: entry.ParentProcessID,
		Name:      syscall.UTF16ToString(entry.ExeFile[:]),
	}

	creationTime, err := processCreationTimeForPID(entry.ProcessID)
	if err != nil {
		process.TimingError = err
	} else {
		process.CreationTime = creationTime
	}

	executablePath, err := executablePathForPID(entry.ProcessID)
	if err != nil {
		process.PathError = err
	} else {
		process.ExecutablePath = executablePath

		fileIdentity, identityErr := executableFileIdentity(executablePath)
		if identityErr != nil {
			process.IdentityError = identityErr
		} else {
			process.FileIdentity = fileIdentity
		}

		executableSHA256, hashErr := hashCache.SHA256(executablePath)
		if hashErr != nil {
			process.HashError = hashErr
		} else {
			process.ExecutableSHA256 = executableSHA256
		}

		signatureEvidence, signatureErr := signatureCache.Verify(executablePath)
		if signatureErr != nil {
			process.SignatureError = signatureErr
		} else {
			process.Signature = signatureEvidence
		}
	}

	securityContext, err := securityContextForPID(entry.ProcessID)
	if err != nil {
		process.SecurityError = err
	} else {
		process.Security = securityContext
	}

	return process
}

func executablePathForPID(pid uint32) (path string, err error) {
	handle, err := openProcessForQuery(pid)
	if err != nil {
		return "", fmt.Errorf("open process %d: %w", pid, err)
	}

	defer func() {
		closeErr := syscall.CloseHandle(handle)
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close process %d handle: %w", pid, closeErr)
		}
	}()

	path, err = processExecutablePath(handle)
	if err != nil {
		return "", fmt.Errorf("query process %d executable path: %w", pid, err)
	}

	return path, nil
}

func openProcessForQuery(pid uint32) (syscall.Handle, error) {
	result, _, callErr := procOpenProcess.Call(
		processQueryLimitedInformation,
		0,
		uintptr(pid),
	)

	if result == 0 {
		if callErr == syscall.Errno(0) {
			return 0, errors.New("OpenProcess failed")
		}

		return 0, callErr
	}

	return syscall.Handle(result), nil
}
