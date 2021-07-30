package estclient

import (
	"crypto/x509"
	"encoding/asn1"
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// Enroll requests a new certificate.
func enroll(client *EstClient, csr *x509.CertificateRequest, caName string) (cert *x509.Certificate, error error) {
	return enrollCommon(client, csr, caName,false)
}

// Reenroll renews an existing certificate.
func reenroll(client *EstClient, csr *x509.CertificateRequest, caName string) (cert *x509.Certificate, error error) {
	return enrollCommon(client, csr, caName,true)
}

// enrollCommon services both enroll and reenroll.
func enrollCommon(client *EstClient, csr *x509.CertificateRequest, caName string, renew bool) (cert *x509.Certificate, error error) {

	if caName != "" {
		client.config.APS = caName
		client.client.AdditionalPathSegment = caName
	}

	ctx, cancel := client.config.MakeContext()
	defer cancel()
	
	if renew {
		cert, err := client.client.Reenroll(ctx, csr)
		return cert, err
	} else {
		cert, err := client.client.Enroll(ctx, csr)
		return cert, err
	}
}
