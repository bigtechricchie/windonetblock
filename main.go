package main

import (
	"fmt"
	"log"
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
	fmt.Printf("Executable: %s\n", currentProcess.ExecutablePath)
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

		if process.PathError != nil {
			fmt.Printf("  Path: <unavailable: %v>\n", process.PathError)
			continue
		}

		fmt.Printf("  Path: %s\n", process.ExecutablePath)
	}
}
