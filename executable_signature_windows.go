package main

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

type ExecutableSignatureStatus string

const (
	SignatureNotTrusted ExecutableSignatureStatus = "Not trusted"
	SignatureTrusted    ExecutableSignatureStatus = "Trusted"
	SignatureUnsigned   ExecutableSignatureStatus = "Unsigned"
)

const (
	trustENoSignature        uint32 = 0x800B0100
	wtdCacheOnlyURLRetrieval uint32 = 0x00001000
	wtdChoiceFile            uint32 = 1
	wtdDisableMD2MD4         uint32 = 0x00002000
	wtdRevokeNone            uint32 = 0
	wtdStateActionIgnore     uint32 = 0
	wtdUIContextExecute      uint32 = 0
	wtdUINone                uint32 = 2
)

var (
	wintrust = syscall.NewLazyDLL("wintrust.dll")

	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

var winTrustActionGenericVerifyV2 = syscall.GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

type ExecutableSignatureEvidence struct {
	Status     ExecutableSignatureStatus
	StatusCode uint32
}

type executableSignatureCache struct {
	entries map[ExecutableFileState]ExecutableSignatureEvidence
	verify  func(string) (ExecutableSignatureEvidence, error)
}

type winTrustData struct {
	Size                            uint32
	PolicyCallbackData              uintptr
	SIPClientData                   uintptr
	UIChoice                        uint32
	RevocationChecks                uint32
	UnionChoice                     uint32
	FileOrCatalogOrBlobOrSgnrOrCert unsafe.Pointer
	StateAction                     uint32
	StateData                       syscall.Handle
	URLReference                    *uint16
	ProvFlags                       uint32
	UIContext                       uint32
	SignatureSettings               unsafe.Pointer
}

type winTrustFileInfo struct {
	Size         uint32
	FilePath     *uint16
	File         syscall.Handle
	KnownSubject *syscall.GUID
}

func newExecutableSignatureCache() *executableSignatureCache {
	return &executableSignatureCache{
		entries: make(map[ExecutableFileState]ExecutableSignatureEvidence),
		verify:  verifyAuthenticodeOffline,
	}
}

func (cache *executableSignatureCache) Verify(
	path string,
) (ExecutableSignatureEvidence, error) {
	before, err := executableFileState(path)
	if err != nil {
		return ExecutableSignatureEvidence{}, fmt.Errorf(
			"inspect file before signature verification: %w",
			err,
		)
	}

	if evidence, ok := cache.entries[before]; ok {
		return evidence, nil
	}

	evidence, err := cache.verify(path)
	if err != nil {
		return ExecutableSignatureEvidence{}, err
	}

	after, err := executableFileState(path)
	if err != nil {
		return ExecutableSignatureEvidence{}, fmt.Errorf(
			"inspect file after signature verification: %w",
			err,
		)
	}

	if before != after {
		return ExecutableSignatureEvidence{}, errors.New(
			"file changed during signature verification",
		)
	}

	cache.entries[before] = evidence
	return evidence, nil
}

func verifyAuthenticodeOffline(path string) (ExecutableSignatureEvidence, error) {
	filePath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ExecutableSignatureEvidence{}, fmt.Errorf(
			"convert executable path to UTF-16: %w",
			err,
		)
	}

	fileInfo := winTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(winTrustFileInfo{})),
		FilePath: filePath,
	}

	trustData := winTrustData{
		Size:                            uint32(unsafe.Sizeof(winTrustData{})),
		UIChoice:                        wtdUINone,
		RevocationChecks:                wtdRevokeNone,
		UnionChoice:                     wtdChoiceFile,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fileInfo),
		StateAction:                     wtdStateActionIgnore,
		ProvFlags:                       wtdCacheOnlyURLRetrieval | wtdDisableMD2MD4,
		UIContext:                       wtdUIContextExecute,
	}

	result, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&winTrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	statusCode := uint32(result)

	return ExecutableSignatureEvidence{
		Status:     classifyAuthenticodeStatus(statusCode),
		StatusCode: statusCode,
	}, nil
}

func classifyAuthenticodeStatus(statusCode uint32) ExecutableSignatureStatus {
	switch statusCode {
	case 0:
		return SignatureTrusted
	case trustENoSignature:
		return SignatureUnsigned
	default:
		return SignatureNotTrusted
	}
}
