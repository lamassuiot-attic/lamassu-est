package estclient

import (
	"crypto/x509"
	"fmt"
	"github.com/globalsign/pemfile"
	"github.com/lamassuiot/lamassu-est/configs"
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

func GetCaCerts(caName string) ([]*x509.Certificate, error) {

	configStr, err := configs.NewConfigEnvClient("est")
	if err != nil {
		return nil, fmt.Errorf("failed to laod env variables %v", err)
	}

	cfg, err := configs.NewConfig(configStr)
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

	certs, err := client.CACerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificates: %v", err)
	}

	return certs, nil
}
