package main

import (
	"fmt"
	"syscall"
	"time"
)

func processCreationTime(handle syscall.Handle) (time.Time, error) {
	var creationTime syscall.Filetime
	var exitTime syscall.Filetime
	var kernelTime syscall.Filetime
	var userTime syscall.Filetime

	if err := syscall.GetProcessTimes(
		handle,
		&creationTime,
		&exitTime,
		&kernelTime,
		&userTime,
	); err != nil {
		return time.Time{}, err
	}

	return filetimeToUTC(creationTime), nil
}

func processCreationTimeForPID(pid uint32) (creationTime time.Time, err error) {
	handle, err := openProcessForQuery(pid)
	if err != nil {
		return time.Time{}, fmt.Errorf("open process %d: %w", pid, err)
	}

	defer func() {
		closeErr := syscall.CloseHandle(handle)
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close process %d handle: %w", pid, closeErr)
		}
	}()

	creationTime, err = processCreationTime(handle)
	if err != nil {
		return time.Time{}, fmt.Errorf("query process %d creation time: %w", pid, err)
	}

	return creationTime, nil
}

func filetimeToUTC(filetime syscall.Filetime) time.Time {
	return time.Unix(0, filetime.Nanoseconds()).UTC()
}
