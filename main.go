package main

import (
	"fmt"
	"log"
	"time"
)

func main() {
	fmt.Println("WindoNetBlock")
	fmt.Println("Application-aware network control and process visibility for Windows")
	fmt.Println()

	currentProcess, err := inspectCurrentProcess()
	if err != nil {
		log.Fatalf("inspect current process: %v", err)
	}

	fmt.Println("Current process")
	fmt.Println("---------------")
	fmt.Printf("PID: %d\n", currentProcess.PID)
	fmt.Printf(
		"Created: %s\n",
		currentProcess.CreationTime.Format(time.RFC3339Nano),
	)
	fmt.Printf("Executable: %s\n", currentProcess.ExecutablePath)
	fmt.Printf("File identity: %s\n", currentProcess.FileIdentity)
	fmt.Printf("SHA-256: %s\n", currentProcess.ExecutableSHA256)
	fmt.Printf(
		"Authenticode: %s (offline, 0x%08X)\n",
		currentProcess.Signature.Status,
		currentProcess.Signature.StatusCode,
	)
	fmt.Printf("User SID: %s\n", currentProcess.Security.UserSID)

	if currentProcess.Security.Account != "" {
		fmt.Printf("Account: %s\n", currentProcess.Security.Account)
	}

	fmt.Printf(
		"Integrity: %s (0x%X)\n",
		currentProcess.Security.Integrity,
		currentProcess.Security.IntegrityRID,
	)
	fmt.Println()

	processes, err := enumerateProcesses()
	if err != nil {
		log.Fatalf("enumerate processes: %v", err)
	}

	fmt.Printf("Running processes: %d\n", len(processes))
	fmt.Println()

	for _, process := range processes {
		fmt.Printf(
			"PID: %d | PPID: %d | %s\n",
			process.PID,
			process.ParentPID,
			process.Name,
		)

		if process.TimingError != nil {
			fmt.Printf("  Created: <unavailable: %v>\n", process.TimingError)
		} else if !process.CreationTime.IsZero() {
			fmt.Printf(
				"  Created: %s\n",
				process.CreationTime.Format(time.RFC3339Nano),
			)
		}

		if process.PathError != nil {
			fmt.Printf("  Path: <unavailable: %v>\n", process.PathError)
		} else {
			fmt.Printf("  Path: %s\n", process.ExecutablePath)
		}

		if process.IdentityError != nil {
			fmt.Printf("  File identity: <unavailable: %v>\n", process.IdentityError)
		} else if process.FileIdentity != (ExecutableFileIdentity{}) {
			fmt.Printf("  File identity: %s\n", process.FileIdentity)
		}

		if process.HashError != nil {
			fmt.Printf("  SHA-256: <unavailable: %v>\n", process.HashError)
		} else if process.ExecutableSHA256 != "" {
			fmt.Printf("  SHA-256: %s\n", process.ExecutableSHA256)
		}

		if process.SignatureError != nil {
			fmt.Printf("  Authenticode: <unavailable: %v>\n", process.SignatureError)
		} else if process.Signature.Status != "" {
			fmt.Printf(
				"  Authenticode: %s (offline, 0x%08X)\n",
				process.Signature.Status,
				process.Signature.StatusCode,
			)
		}

		if process.SecurityError != nil {
			fmt.Printf("  Security: <unavailable: %v>\n", process.SecurityError)
			continue
		}

		fmt.Printf("  User SID: %s\n", process.Security.UserSID)

		if process.Security.Account != "" {
			fmt.Printf("  Account: %s\n", process.Security.Account)
		}

		fmt.Printf(
			"  Integrity: %s (0x%X)\n",
			process.Security.Integrity,
			process.Security.IntegrityRID,
		)
	}
}
