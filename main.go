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
	fmt.Println()

	processes, err := enumerateProcesses()
	if err != nil {
		log.Fatalf("enumerate processes: %v", err)
	}

	fmt.Printf("Running processes: %d\n", len(processes))
	fmt.Println()
	fmt.Printf("%-8s %-8s %s\n", "PID", "PPID", "NAME")
	fmt.Printf("%-8s %-8s %s\n", "---", "----", "----")

	for _, process := range processes {
		fmt.Printf(
			"%-8d %-8d %s\n",
			process.PID,
			process.ParentPID,
			process.Name,
		)
	}
}
