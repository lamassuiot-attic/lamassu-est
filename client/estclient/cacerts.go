package estclient

import (
	"fmt"
	"github.com/globalsign/pemfile"
	"github.com/lamassuiot/lamassu-est/client/configs"
	"io"
)

func Cacerts(w io.Writer, crtfilename string) error {

	//TODO: Load it from environment variables
	filename := "/home/xpb/Desktop/ikl/lamassu/lamassu-est/client/configs/config.json"

	cfg, err := configs.NewConfig(filename)
	if err != nil {
		return fmt.Errorf("failed to make EST client: %v", err)
	}

	client, err := NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to make EST client: %v", err)
	}

	ctx, cancel := cfg.MakeContext()
	defer cancel()

	certs, err := client.CACerts(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CA certificates: %v", err)
	}

	/*
		if cfg.FlagWasPassed(rootOutFlag) {
			var root *x509.Certificate
			for _, cert := range certs {
				if bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil {
					root = cert
					break
				}
			}
			if root == nil {
				return errors.New("failed to find a root certificate in CA certificates")
			}
			certs = []*x509.Certificate{root}
		}
	*/

	out, closeFunc, err := MaybeRedirect(w, crtfilename, 0666)
	if err != nil {
		return err
	}
	defer closeFunc()

	if err := pemfile.WriteCerts(out, certs); err != nil {
		return fmt.Errorf("failed to write CA certificates: %v", err)
	}

	return nil
}