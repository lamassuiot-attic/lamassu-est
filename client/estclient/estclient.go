package estclient

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/lamassuiot/est"
	"github.com/lamassuiot/lamassu-est/configs"
)

var (
	errNoPrivateKey = errors.New("no private key provided")
	errNoServer     = errors.New("EST server not specified")
)

type EstClient struct {
	client est.Client
	config configs.ConfigClient
}

// NewClient builds an EST client from a configuration file, overriding the values with command line options, if applicable.
func NewClient(config configs.ConfigClient) (*EstClient, error) {
	var estClient EstClient

	client := est.Client{
		Host:                  config.Server,
		AdditionalPathSegment: config.APS,
		ExplicitAnchor:        config.ExplicitAnchor,
		PrivateKey:            config.PrivateKey,
		Certificates:          config.Certificates,
	}

	estClient.client = client
	estClient.config = config

	// Host is the only required field for all operations.
	if client.Host == "" {
		return nil, errNoServer
	}

	return &estClient, nil
}

func (client *EstClient) GetCAs(caName string) ([]*x509.Certificate, error) {
	return getCaCerts(client, caName)
}

func (client *EstClient) Enroll(csr *x509.CertificateRequest, caName string) (cert *x509.Certificate, error error) {
	return enroll(client, csr, caName)
}

func (client *EstClient) Reenroll(csr *x509.CertificateRequest, caName string) (cert *x509.Certificate, error error) {
	return reenroll(client, csr, caName)
}

/*
Auxiliary functions
*/

// MaybeRedirect maybeRedirect returns the provided io.Writer if filename is the empty
// string, otherwise it opens and returns the named file, creating it with
// the specified permissions if it doesn't exist. The caller is responsible
// for closing the file with the returned function.
func MaybeRedirect(w io.Writer, filename string, perm os.FileMode) (io.Writer, func() error, error) {
	if filename == "" {
		return w, func() error { return nil }, nil
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output file: %v", err)
	}

	return f, f.Close, nil
}

/*func ChangeClientCert(client *est.Client) error {
	client.Certificates =
}*/
