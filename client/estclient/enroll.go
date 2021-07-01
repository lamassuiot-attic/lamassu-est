package estclient

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	configs2 "github.com/lamassuiot/lamassu-est/configs"
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// Enroll requests a new certificate.
func Enroll(csr *x509.CertificateRequest, caName string) (cert *x509.Certificate, error error) {
	return enrollCommon(csr, caName,false)
}

// Reenroll renews an existing certificate.
func Reenroll(csr *x509.CertificateRequest, caName string) (cert *x509.Certificate, error error) {
	return enrollCommon(csr, caName,true)
}

// enrollCommon services both enroll and reenroll.
func enrollCommon(csr *x509.CertificateRequest, caName string, renew bool) (cert *x509.Certificate, error error) {

	configStr, err := configs2.NewConfigEnvClient("est")
	if err != nil {
		return nil, fmt.Errorf("failed to laod env variables %v", err)
	}

	cfg, err := configs2.NewConfig(configStr)
	if err != nil {
		return nil, fmt.Errorf("failed to make EST client's configurations: %v", err)
	}

	cfg.APS = caName

	client, err := NewClient(&cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to make EST client: %v", err)
	}

	ctx, cancel := cfg.MakeContext()
	defer cancel()
	
	if renew {
		cert, err = client.Reenroll(ctx, csr)
		return cert, err
	} else {
		cert, err = client.Enroll(ctx, csr)
		return cert, err
	}
}