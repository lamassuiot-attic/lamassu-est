package main

import (
	"fmt"
	configs2 "github.com/lamassuiot/lamassu-est/configs"
)

func main() {

	// Test Configuration

	b, _ := configs2.NewConfigEnvServer("lalala")



	fmt.Println(b)



	fmt.Println("Hello world")
}