package main

import (
	"fmt"
	"github.com/lamassuiot/lamassu-est/client/estclient"
	configs2 "github.com/lamassuiot/lamassu-est/configs"
)

func main() {

	// Test Configuration
	a, _ := configs2.NewConfigJson("/home/xpb/Desktop/ikl/lamassu/lamassu-est/client/config.json")
	b, _ := configs2.NewConfigEnvClient("est")

	c, _ := configs2.NewConfig(a)
	d, _ := configs2.NewConfig(b)

	fmt.Println(a, b, c, d)

	// Test Get CA certificates
	caCerts, err := estclient.GetCaCerts("Lamassu-DMS")
	if err != nil {
		fmt.Println(err)
	}

	// Test write CA certificates to a file
	estclient.WriteCertsFile(nil, "lalala.crt", caCerts)

	// Test enroll


}
