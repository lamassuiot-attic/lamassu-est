package estserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/globalsign/est"
	"github.com/globalsign/pemfile"
	"github.com/lamassuiot/lamassu-est/configs"
	"net/http"
)

var (
	errCerts    = errors.New("error parsing server certificates")
	errPrivateKey = errors.New("error parsing private key")
	errClientCA = errors.New("error parsing client CA")
)

// NewServer  builds an EST server from a configuration file and a CA.
func NewServer(config *configs.ConfigStrServer, ca est.CA) (*http.Server, error) {

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
	certs, err := pemfile.ReadCerts(config.ClientCA)
	if err != nil {
		return nil, errClientCA
	}
	clientCACerts = append(clientCACerts, certs...)
	clientCAs := x509.NewCertPool()
	for _, cert := range clientCACerts {
		clientCAs.AddCert(cert)
	}

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCerts,
				PrivateKey:  serverKey,
				Leaf:        serverCerts[0],
			},
		},
		ClientCAs: clientCAs,
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

