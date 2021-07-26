package estclient

import (
	"crypto/x509"
	"fmt"
	"github.com/globalsign/pemfile"
	"io"
)


func WriteCertsFile(writer io.Writer, certName string, certs []*x509.Certificate) error {

	out, closeFunc, err := MaybeRedirect(writer, certName, 0666)
	if err != nil {
		return err
	}
	defer closeFunc()

	if err := pemfile.WriteCerts(out, certs); err != nil {
		return fmt.Errorf("failed to write CA certificates: %v", err)
	}

	return nil
}

func getCaCerts(client *EstClient, caName string) ([]*x509.Certificate, error) {

	client.config.APS = caName

	ctx, cancel := client.config.MakeContext()
	defer cancel()

	certs, err := client.client.CACerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificates: %v", err)
	}

	return certs, nil
}
