package estclient

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/lamassuiot/lamassu-est/client/configs"
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// Enroll requests a new certificate.
func Enroll(csr *x509.CertificateRequest) (cert *x509.Certificate, error error) {
	return enrollCommon(csr, false)
}

// Reenroll renews an existing certificate.
func Reenroll(csr *x509.CertificateRequest) (cert *x509.Certificate, error error) {
	return enrollCommon(csr, true)
}

// enrollCommon services both enroll and reenroll.
func enrollCommon(csr *x509.CertificateRequest, renew bool) (cert *x509.Certificate, error error) {

	//TODO: Load it from environment variables
	filename := "/home/xpb/Desktop/ikl/lamassu/lamassu-est/client/configs/config.json"

	cfg, err := configs.NewConfig(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to make EST client: %v", err)
	}

	client, err := NewClient(cfg)
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

