package estserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/globalsign/est"
	"github.com/globalsign/pemfile"
	"github.com/lamassuiot/lamassu-est/client/estclient"
	"github.com/lamassuiot/lamassu-est/configs"
	"log"
	"net/http"
)

var (
	errCerts    = errors.New("error parsing server certificates")
	errPrivateKey = errors.New("error parsing private key")
	errClientCA = errors.New("error parsing client CA")
	errConfig = errors.New("error getting configuration")
	errGetCa = errors.New("error getting CAs")
)

// NewServer  builds an EST server from a configuration file and a CA.
func NewServer(ca est.CA) (*http.Server, error) {

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
			log.Fatalf("failed to read client CA certificates from file: %v", err)
		}
		clientCACerts = append(clientCACerts, certs...)
	}

	clientCAs := x509.NewCertPool()
	for _, cert := range clientCACerts {
		clientCAs.AddCert(cert)
	}


	/****** EST CLIENT for verifying CAs *****/

	configStr, err := configs.NewConfigEnvClient("est")
	if err != nil {
		fmt.Errorf("failed to laod env variables %v", err)
	}
	cfg, err := configs.NewConfig(configStr)
	if err != nil {
		fmt.Errorf("failed to make EST client's configurations: %v", err)
	}

	 estClient, err := estclient.NewClient(cfg)

	if err != nil {
		fmt.Errorf("failed to make EST client: %v", err)
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


		caCerts, err := estClient.GetCAs("")
		if err != nil {
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}

		for _, caCert := range caCerts {
			clientCAs.AddCert(caCert)
		}

		tlsConfig.ClientCAs = clientCAs

		opts := x509.VerifyOptions{
			Roots:         tlsConfig.ClientCAs, // On the server side, use config.RootCAs.
			DNSName:       tlsConfig.ServerName,
			Intermediates: x509.NewCertPool(),
			// On the server side, set KeyUsages to ExtKeyUsageClientAuth. The
			// default value is appropriate for clients side verification.
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

