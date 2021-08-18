package estserver

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/globalsign/pemfile"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/est"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets/vault"
	"github.com/lamassuiot/lamassu-est/configs"
)

// NewServerCa  builds an EST server from a configuration file and a CA.
func NewServerCa(ca est.CA) (*http.Server, error) {

	config, err := configs.NewConfigEnvServer("est")

	if err != nil {
		return nil, errConfig
	}

	serverCerts, err := pemfile.ReadCerts(config.Certs)
	if err != nil {
		return nil, errCerts
	}

	var tlsCerts [][]byte
	for i := range serverCerts {
		tlsCerts = append(tlsCerts, serverCerts[i].Raw)
	}

	// Handle Private key
	serverKey, err := pemfile.ReadPrivateKey(config.PrivateKey)
	if err != nil {
		return nil, errPrivateKey
	}

	// Handle client certs
	var clientCACerts []*x509.Certificate
	for _, certPath := range config.ClientCAs {
		certs, err := pemfile.ReadCerts(certPath)
		if err != nil {
			return nil, errPrivateKey
		}
		clientCACerts = append(clientCACerts, certs...)
	}

	clientCAs := x509.NewCertPool()
	for _, cert := range clientCACerts {
		clientCAs.AddCert(cert)
	}

	/****** VAULT CLIENT for verifying CAs *****/

	configVault, err := configs.NewConfigEnvServer("ca")
	if err != nil {
		fmt.Errorf("failed to laod env variables %v", err)
	}

	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	secretsVault, err := vault.NewVaultSecrets(configVault.VaultAddress, configVault.VaultRoleID, configVault.VaultSecretID, configVault.VaultCA, configVault.OcspUrl, configVault logger)
	if err != nil {
		return nil, err
	}

	/******************************************/

	if err != nil {
		return nil, errPrivateKey
	}

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCerts,
				PrivateKey:  serverKey,
				Leaf:        serverCerts[0],
			},
		},
		//ClientCAs: clientCAs, // This is filled later
	}

	tlsConfig.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, len(certificates))
		for i, asn1Data := range certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}

		cas, err := secretsVault.GetCAs(secrets.AllCAs)
		if err != nil {
			return err
		}

		// Handle client certs
		for _, ca := range cas.Certs {
			block, _ := pem.Decode([]byte(ca.CRT))
			if block == nil {
				panic("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic("failed to parse certificate: " + err.Error())

			}
			clientCAs.AddCert(cert)
		}

		tlsConfig.ClientCAs = clientCAs

		opts := x509.VerifyOptions{
			Roots:         tlsConfig.ClientCAs, // On the server side, use config.RootCAs.
			DNSName:       tlsConfig.ServerName,
			Intermediates: x509.NewCertPool(),
			// On the server side, set KeyUsages to ExtKeyUsageClientAuth. The
			// default value is appropriate for clients side verification.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err = certs[0].Verify(opts)

		return err
	}

	serverConfig := est.ServerConfig{
		CA:             ca,
		Timeout:        0,
		CheckBasicAuth: nil,
	}

	handler, err := est.NewRouter(&serverConfig)

	// Create and start server.
	s := &http.Server{
		Addr:      config.ListenAddr,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	return s, nil
}
