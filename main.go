package main

import (
	"fmt"
	"log"
)

func main() {
	fmt.Println("WindoNetBlock")
	fmt.Println("Application-aware network control and process visibility for Windows")

	process, err := inspectCurrentProcess()
	if err != nil {
		log.Fatalf("inspect current process: %v", err)
	}

	fmt.Println("Current process")
	fmt.Println("---------------")
	fmt.Printf("PID: %d\n", process.PID)
	fmt.Printf("Executable: %s\n", process.ExecutablePath)
}
