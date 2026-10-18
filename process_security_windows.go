package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type IntegrityLevel string

const (
	IntegrityHigh      IntegrityLevel = "High"
	IntegrityLow       IntegrityLevel = "Low"
	IntegrityMedium    IntegrityLevel = "Medium"
	IntegrityProtected IntegrityLevel = "Protected"
	IntegritySystem    IntegrityLevel = "System"
	IntegrityUnknown   IntegrityLevel = "Unknown"
	IntegrityUntrusted IntegrityLevel = "Untrusted"
)

type ProcessSecurityContext struct {
	UserSID      string
	Account      string
	Integrity    IntegrityLevel
	IntegrityRID uint32
}

type tokenMandatoryLabel struct {
	Label syscall.SIDAndAttributes
}

func inspectProcessSecurity(process syscall.Handle) (context ProcessSecurityContext, err error) {
	var token syscall.Token

	if err := syscall.OpenProcessToken(
		process,
		syscall.TOKEN_QUERY,
		&token,
	); err != nil {
		return ProcessSecurityContext{}, fmt.Errorf("open process token: %w", err)
	}

	defer func() {
		closeErr := token.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close process token: %w", closeErr)
		}
	}()

	user, err := token.GetTokenUser()
	if err != nil {
		return ProcessSecurityContext{}, fmt.Errorf("query token user: %w", err)
	}

	if user.User.Sid == nil {
		return ProcessSecurityContext{}, errors.New("token user SID is nil")
	}

	userSID, err := user.User.Sid.String()
	if err != nil {
		return ProcessSecurityContext{}, fmt.Errorf("format token user SID: %w", err)
	}

	context.UserSID = userSID

	account, domain, _, lookupErr := user.User.Sid.LookupAccount("")
	if lookupErr == nil {
		if domain == "" {
			context.Account = account
		} else {
			context.Account = domain + `\` + account
		}
	}

	integrity, rid, err := tokenIntegrityLevel(token)
	if err != nil {
		return ProcessSecurityContext{}, fmt.Errorf("query token integrity level: %w", err)
	}

	context.Integrity = integrity
	context.IntegrityRID = rid

	return context, nil
}

func securityContextForPID(pid uint32) (context ProcessSecurityContext, err error) {
	handle, err := openProcessForQuery(pid)
	if err != nil {
		return ProcessSecurityContext{}, fmt.Errorf("open process %d: %w", pid, err)
	}

	defer func() {
		closeErr := syscall.CloseHandle(handle)
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close process %d handle: %w", pid, closeErr)
		}
	}()

	context, err = inspectProcessSecurity(handle)
	if err != nil {
		return ProcessSecurityContext{}, fmt.Errorf(
			"inspect process %d security context: %w",
			pid,
			err,
		)
	}

	return context, nil
}

func tokenIntegrityLevel(token syscall.Token) (IntegrityLevel, uint32, error) {
	var required uint32

	err := syscall.GetTokenInformation(
		token,
		syscall.TokenIntegrityLevel,
		nil,
		0,
		&required,
	)
	if err != nil && !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) {
		return IntegrityUnknown, 0, err
	}

	if required == 0 {
		return IntegrityUnknown, 0, errors.New(
			"Windows returned zero token integrity buffer size",
		)
	}

	buffer := make([]byte, required)

	err = syscall.GetTokenInformation(
		token,
		syscall.TokenIntegrityLevel,
		&buffer[0],
		uint32(len(buffer)),
		&required,
	)
	if err != nil {
		return IntegrityUnknown, 0, err
	}

	label := (*tokenMandatoryLabel)(unsafe.Pointer(&buffer[0]))
	if label.Label.Sid == nil {
		return IntegrityUnknown, 0, errors.New("token integrity SID is nil")
	}

	integritySID, err := label.Label.Sid.String()
	if err != nil {
		return IntegrityUnknown, 0, fmt.Errorf("format token integrity SID: %w", err)
	}

	rid, err := integrityRIDFromSID(integritySID)
	if err != nil {
		return IntegrityUnknown, 0, err
	}

	return classifyIntegrityLevel(rid), rid, nil
}

func integrityRIDFromSID(sid string) (uint32, error) {
	const mandatoryLabelPrefix = "S-1-16-"

	if !strings.HasPrefix(sid, mandatoryLabelPrefix) {
		return 0, fmt.Errorf("unexpected token integrity SID %q", sid)
	}

	ridText := strings.TrimPrefix(sid, mandatoryLabelPrefix)
	rid, err := strconv.ParseUint(ridText, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse token integrity RID: %w", err)
	}

	return uint32(rid), nil
}

func classifyIntegrityLevel(rid uint32) IntegrityLevel {
	switch {
	case rid < 0x1000:
		return IntegrityUntrusted
	case rid < 0x2000:
		return IntegrityLow
	case rid < 0x3000:
		return IntegrityMedium
	case rid < 0x4000:
		return IntegrityHigh
	case rid < 0x5000:
		return IntegritySystem
	case rid >= 0x5000:
		return IntegrityProtected
	default:
		return IntegrityUnknown
	}
}
