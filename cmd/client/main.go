package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/lamassuiot/lamassu-est/client/estclient"
	"github.com/lamassuiot/lamassu-est/configs"
	"io/ioutil"
)

func main() {

	configStr, err := configs.NewConfigEnvClient("est")
	if err != nil {
		 fmt.Errorf("failed to laod env variables %v", err)
	}

	cfg, err := configs.NewConfig(configStr)
	if err != nil {
		fmt.Errorf("failed to make EST client's configurations: %v", err)
	}

	client, err := estclient.NewClient(cfg)

	caCerts, err := client.GetCAs("")


	// load client certificate request
	csrFile, err := ioutil.ReadFile("/home/xpb/Desktop/ikl/lamassu/lamassu-est/lalala.csr")
	if err != nil {
		panic(err)
	}
	csrData, _ := pem.Decode(csrFile)
	if csrData == nil {
		panic("pem.Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(csrData.Bytes)
	if err != nil {
		panic(err)
	}
	cert, err := client.Enroll(csr, "")

	certRe, err := client.Reenroll(csr, "")
	fmt.Println(cfg, client, caCerts, err, cert, certRe)
}
