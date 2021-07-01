package configs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/globalsign/pemfile"
	"github.com/kelseyhightower/envconfig"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

// ConfigClient Configuration parameters for the client
type ConfigClient struct {
	Server         string
	APS            string
	Certificates   []*x509.Certificate
	ExplicitAnchor *x509.CertPool
	PrivateKey     interface{}
	Timeout        time.Duration
}

// ConfigStrClient Read JSON or environment variables
type ConfigStrClient struct {
	Server             string `json:"server"`
	APS                string `json:"additional_path_segment"`
	ExplicitAnchorPath string `json:"explicit_anchor"`
	PrivateKeyPath     string `json:"private_key,omitempty"`
	CertificatesPath   string `json:"client_certificates"`
}

// ConfigStrServer  contains the EST server configuration in string format.
type ConfigStrServer struct {
	ListenAddr string `json:"listen_address"`
	Certs      string `json:"certificate"`
	PrivateKey string `json:"private_key"`
	ClientCA   string `json:"client_cas"` //TODO: make it an array
}

// NewConfigJson Wrapper for different configurations
func NewConfigJson(filename string) (ConfigStrClient, error) {
	var cfg ConfigStrClient

	// Get working directory.
	wd, err := os.Getwd()
	if err != nil {
		return ConfigStrClient{}, fmt.Errorf("failed to get working directory: %v", err)
	}

	// If filename is not an absolute path, look for it in a set sequence of locations.
	if !filepath.IsAbs(filename) {
		// Check current working directory first.
		searchPaths := []string{wd}

		// Check in the user's home directory, if we can find it.
		if hd, err := os.UserHomeDir(); err == nil {
			searchPaths = append(searchPaths, hd)
		}

		// Search for the file itself.
		for _, searchPath := range searchPaths {
			fp := filepath.Join(searchPath, filename)
			if info, err := os.Stat(fp); err == nil && info.Mode().IsRegular() {
				filename = fp
				break
			}
		}
	}

	// Read the file and parse the configuration.
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return ConfigStrClient{}, fmt.Errorf("failed to open configuration file: %v", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return ConfigStrClient{}, fmt.Errorf("failed to unmarshal configuration file: %v", err)
	}

	return cfg, nil
}

func NewConfigEnvClient(prefix string) (ConfigStrClient, error) {

	var cfg ConfigStrClient

	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return ConfigStrClient{}, fmt.Errorf("failed to load configuration from env variables: %v", err)
	}

	return cfg, nil
}

func NewConfigEnvServer(prefix string) (ConfigStrServer, error) {

	var cfg ConfigStrServer

	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return ConfigStrServer{}, fmt.Errorf("failed to load configuration from env variables: %v", err)
	}

	return cfg, nil
}

func NewConfig(cfgStr ConfigStrClient) (ConfigClient, error) {

	var cfg ConfigClient

	cfg.Timeout = 1000000000 //TODO: hardcoded for the moment
	cfg.Server = cfgStr.Server
	cfg.APS = cfgStr.APS

	// Process explicit  anchor databases.
	for _, anchor := range []struct {
		name   string
		field  *string
		anchor **x509.CertPool
	}{
		{
			name:   "explicit",
			field:  &cfgStr.ExplicitAnchorPath,
			anchor: &cfg.ExplicitAnchor,
		},
	} {

		if *anchor.field != "" {
			*anchor.anchor = x509.NewCertPool()

			certs, err := pemfile.ReadCerts(*anchor.field)
			if err != nil {
				return ConfigClient{}, fmt.Errorf("failed to read %s anchor file: %v", anchor.name, err)
			}

			for _, cert := range certs {
				(*anchor.anchor).AddCert(cert)
			}
		}
	}

	if cfgStr.CertificatesPath != "" {
		certs, err := pemfile.ReadCerts(cfgStr.CertificatesPath)
		if err != nil {
			return ConfigClient{}, fmt.Errorf("failed to read client certificates: %v", err)
		}
		cfg.Certificates = certs
	}

	if cfg.PrivateKey != "" {
		privateKey, err := pemfile.ReadPrivateKeyWithPasswordFunc(cfgStr.PrivateKeyPath, nil)
		if err != nil {
			return ConfigClient{}, fmt.Errorf("failed to read private key: %v", err)
		}
		cfg.PrivateKey = privateKey
	}

	return cfg, nil
}

// MakeContext returns a context with the configured timeout, and its cancel function.
func (cfg *ConfigClient) MakeContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), cfg.Timeout)
}
