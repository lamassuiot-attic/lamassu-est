package main

import (
	_ "context"
	"crypto/tls"
	"crypto/x509"
	_ "encoding/pem"
	"fmt"
	"github.com/globalsign/est"
	"github.com/globalsign/pemfile"
	configs2 "github.com/lamassuiot/lamassu-est/server/configs"
	_ "io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lamassuiot/lamassu-est/server/caservice"
)

const (
	vaultAddr    = "https://vault.lamassu.zpd.ikerlan.es:8200"
	caCert = "/home/xpb/Desktop/ikl/lamassu/lamassu-est/cmd/server/certs/vault.crt"
	roleId = "9865a0bd-0975-482d-9561-5d8016c2b71d"
	secretId = "49a86de2-efbb-069f-9ac5-889019248788"
	caName = "Lamassu-Root-CA1-RSA4096"

	defaultListenAddr   = "https://localhost:8087/v1"
	configFilePath = "//home/xpb/Desktop/ikl/lamassu/lamassu-est/cmd/server/configs/configs.json"
	)

/*
func (vaultClient *vaultClient) SignCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	signPath := vaultClient.caName + "/sign/enroller"
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	options := map[string]interface {} {
		"csr": string(csrBytes),
		"common_name": csr.Subject.CommonName,
	}
	data, err := vaultClient.caservice.Logical().Write(signPath, options)
	if err != nil {
		return nil, err
	}
	certData := data.Data["certificate"]
	certPEMBlock, _ := pem.Decode([]byte(certData.(string)))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return nil, err
	}

	return certPEMBlock.Bytes, nil
}*/


func main() {

	/*vaultClient, err := vault.Init(vaultAddr, caName, caCert, roleId, secretId)
	if err != nil {
		log.Println(err)
	}

	err = vaultClient.Login()
	if err != nil {
		log.Println(err)
	}*/

	var ca *caservice.VaultService
	cl := caservice.NewClient(nil)
	cl.BaseURL, _ = url.Parse(defaultListenAddr)
	ca = cl.Vault


	/*ctx, cancel := context.WithTimeout(context.Background(), time.Second * 60)
	defer cancel()

	data, err := ioutil.ReadFile("/home/xpb/Desktop/ikl/lamassu/lamassu-est/cmd/server/certs/lalala.csr")
	if err != nil {
		log.Fatalf("failed to parse EST server certificate request: %v", err)
	}

	b, _ := pem.Decode(data)
	var csr *x509.CertificateRequest
	if b == nil {
		csr, err = x509.ParseCertificateRequest(data)
	} else {
		csr, err = x509.ParseCertificateRequest(b.Bytes)
	}
	if err != nil {
		log.Fatalf("failed to parse EST server certificate request: %v", err)
	}

	cert, err := ca.Enroll(ctx, csr, "", nil)*/


	/***********************************************************************/

	// Load and process configuration.
	cfg, err := configs2.ConfigFromFile(configFilePath)
	if err != nil {
		log.Fatalf("failed to read configuration file: %v", err)
	}

	var listenAddr = defaultListenAddr
	var serverKey interface{}
	var serverCerts []*x509.Certificate
	var clientCACerts []*x509.Certificate

	serverKey, err = pemfile.ReadPrivateKey(cfg.TLS.Key)
	if err != nil {
		log.Fatalf("failed to read server private key   file: %v", err)
	}

	serverCerts, err = pemfile.ReadCerts(cfg.TLS.Certs)
	if err != nil {
		log.Fatalf("failed to read server certificates from file: %v", err)
	}

	for _, certPath := range cfg.TLS.ClientCAs {
		certs, err := pemfile.ReadCerts(certPath)
		if err != nil {
			log.Fatalf("failed to read caservice CA certificates from file: %v", err)
		}
		clientCACerts = append(clientCACerts, certs...)
	}

	listenAddr = cfg.TLS.ListenAddr

	var tlsCerts [][]byte
	for i := range serverCerts {
		tlsCerts = append(tlsCerts, serverCerts[i].Raw)
	}

	clientCAs := x509.NewCertPool()
	for _, cert := range clientCACerts {
		clientCAs.AddCert(cert)
	}

	tlsCfg := &tls.Config{
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

	// Create server mux.TODO: Fill nils
	r, err := est.NewRouter(&est.ServerConfig{
		CA:             ca,
		Logger:         nil,
		AllowedHosts:   cfg.AllowedHosts,
		Timeout:        time.Duration(cfg.Timeout) * time.Second,
		RateLimit:      cfg.RateLimit,
		CheckBasicAuth: nil,
	})
	if err != nil {
		log.Fatalf("failed to create new EST router: %v", err)
	}

	// Create and start server.
	s := &http.Server{
		Addr:      listenAddr,
		Handler:   r,
		TLSConfig: tlsCfg,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	//logger.Infof("Starting EST server FOR NON-PRODUCTION USE ONLY")

	go func() {
		err := s.ListenAndServeTLS("", "")
		if err != nil {
			// TODO: Log
		}
	}()

	// Wait for signal.
	got := <-stop

	// Shutdown server.
	//logger.Infof("Closing EST server with signal %v", got)

	err = s.Close()
	if err != nil {
		return
	}

	/***********************************************************************/


	fmt.Println(err, r, got) //TODO delete
	
}