package main

import (
	"fmt"
	"github.com/lamassuiot/lamassu-est/client/configs"
	"github.com/lamassuiot/lamassu-est/client/estclient"
)

func main() {

	// Test Configuration
	a, _ := configs.NewConfigJson("/home/xpb/Desktop/ikl/lamassu/lamassu-est/client/config.json")
	b, _ := configs.NewConfigEnv("est")

	c, _ := configs.NewConfig(a)
	d, _ := configs.NewConfig(b)

	fmt.Println(a, b, c, d)

	// Test Get CA certificates
	caCerts, err := estclient.GetCaCerts()
	if err != nil {
		fmt.Println(err)
	}

	// Test write CA certificates to a file
	estclient.WriteCertsFile(nil, "lalala.crt", caCerts)

	// Test enroll


}
