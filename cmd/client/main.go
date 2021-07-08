package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/lamassuiot/lamassu-est/client/estclient"
	"io/ioutil"
)

func main() {

	// Test Configuration
	/*a, _ := configs2.NewConfigJson("/home/xpb/Desktop/ikl/lamassu/lamassu-est/client/config.json")
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
	estclient.WriteCertsFile(nil, "lalala.crt", caCerts)*/

	// Test rernroll

	data, err := ioutil.ReadFile("//home/xpb/Desktop/ikl/lamassu/lamassu-est/lalala.csr")
	fmt.Print(err)
	b, _ := pem.Decode(data)
	var csr *x509.CertificateRequest
	if b == nil {
		csr, err = x509.ParseCertificateRequest(data)
	} else {
		csr, err = x509.ParseCertificateRequest(b.Bytes)
	}
	res, err := estclient.Enroll(csr, "Lamassu-Root-CA1-RSA4096")
	fmt.Print(err)
	fmt.Print(res)


}
