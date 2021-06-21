package configs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/globalsign/pemfile"
	"github.com/kelseyhightower/envconfig"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	prefixConsul string = "consul"
	prefixProxy  string = "proxy"
)

var (
	errNoPrivateKey = errors.New("no private key provided")
	errNoServer     = errors.New("EST server not specified")
)

type Config struct {
	Server            string            `json:"server"`
	APS               string            `json:"additional_path_segment"`
	AdditionalHeaders map[string]string `json:"additional_headers,omitempty"`
	HostHeader        string            `json:"host_header"`
	Username          string            `json:"username"`
	Password          string            `json:"password"`
	Explicit          string            `json:"explicit_anchor"`
	Implicit          string            `json:"implicit_anchor"`
	PrivateKey        *privateKey       `json:"private_key,omitempty"`
	CertificatesStr   string            `json:"client_certificates"`

	Certificates   []*x509.Certificate
	ekcerts        []*x509.Certificate
	baseDir        string
	closeFuncs     []func() error
	ExplicitAnchor *x509.CertPool
	ImplicitAnchor *x509.CertPool
	Insecure       bool
	openPrivateKey interface{}
	timeout        time.Duration
}

// privateKey specifies the source of a private key, which could be a file,
// a hardware security module (HSM), a Trusted Platform Module (TPM) device,
// or another source.
type privateKey struct {
	Path string
	HSM  *hsmKey
	TPM  *tpmKey
}

// hsmKey is an HSM-resident private key.
type hsmKey struct {
	LibraryPath string   `json:"pkcs11_library_path"`
	Label       string   `json:"token_label"`
	PIN         string   `json:"token_pin"`
	KeyID       *big.Int `json:"key_id"`
}

// tpmKey is a TPM-resident private key.
type tpmKey struct {
	Device      string   `json:"device"`
	Persistent  *big.Int `json:"persistent_handle,omitempty"`
	Storage     *big.Int `json:"storage_handle,omitempty"`
	EK          *big.Int `json:"ek_handle,omitempty"`
	KeyPass     string   `json:"key_password"`
	StoragePass string   `json:"storage_password"`
	EKPass      string   `json:"ek_password"`
	EKCerts     string   `json:"ek_certs"`
	Public      string   `json:"public_area"`
	Private     string   `json:"private_area"`
}

// NewConfig Wrapper for different configurations
func NewConfig(filename string) (*Config, error) {
	var cfg = Config{
		timeout: 1000000000000000000,
	}

	// Get working directory.
	wd, err := os.Getwd()
	if err != nil {
		return &Config{}, fmt.Errorf("failed to get working directory: %v", err)
	}

	// If filename is not an absolute path, look for it in a set sequence
	// of locations.
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
		return &Config{}, fmt.Errorf("failed to open configuration file: %v", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return &Config{}, fmt.Errorf("failed to unmarshal configuration file: %v", err)
	}

	cfg.baseDir = filepath.Clean(filepath.Dir(filename))

	// TODO: Insert anchor stuff
	// Process explicit and implicit anchor databases.
	for _, anchor := range []struct {
		name   string
		field  *string
		anchor **x509.CertPool
	}{
		{
			name:   "explicit",
			field:  &cfg.Explicit,
			anchor: &cfg.ExplicitAnchor,
		},
	} {

		*anchor.field = fullPath(cfg.baseDir, *anchor.field)

		if *anchor.field != "" {
			*anchor.anchor = x509.NewCertPool()

			certs, err := pemfile.ReadCerts(*anchor.field)
			if err != nil {
				return &Config{}, fmt.Errorf("failed to read %s anchor file: %v", anchor.name, err)
			}

			for _, cert := range certs {
				(*anchor.anchor).AddCert(cert)
			}
		}
	}


	// Process client certificate(s).
	cfg.CertificatesStr = fullPath(cfg.baseDir, cfg.CertificatesStr)

	if cfg.CertificatesStr != "" {
		certs, err := pemfile.ReadCerts(cfg.CertificatesStr)
		if err != nil {
			return &Config{}, fmt.Errorf("failed to read client certificates: %v", err)
		}
		cfg.Certificates = certs
	}

	if cfg.PrivateKey != nil {
		privkey, closeFunc, err := cfg.PrivateKey.Get(cfg.baseDir)
		if err != nil {
			return &Config{}, fmt.Errorf("failed to get private key: %v", err)
		}

		cfg.openPrivateKey = privkey
		cfg.closeFuncs = append(cfg.closeFuncs, closeFunc)
	}


	return &cfg, nil
}

func configFromEnv(prefix string, config interface{}) error {

	err := envconfig.Process(prefix, config)
	if err != nil {
		return err
	}
	return nil
}

// fullPath returns filename if it is an absolute path, or filename joined to
// baseDir if it is not.
func fullPath(baseDir, filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}

	return filepath.Clean(filepath.Join(baseDir, filename))
}

// Get returns a private key and a close function.
func (k *privateKey) Get(baseDir string) (interface{}, func() error, error) {
	switch {
	case k.Path != "":
		key, err := pemfile.ReadPrivateKeyWithPasswordFunc(fullPath(baseDir, k.Path), nil)
		if err != nil {
			return nil, nil, err
		}

		return key, func() error { return nil }, nil
		/*
			case k.HSM != nil:
				return k.HSM.Get(baseDir)

			case k.TPM != nil:
				return k.TPM.Get(baseDir)
			}*/
	}

	return nil, nil, errNoPrivateKey
}

// MakeContext returns a context with the configured timeout, and its cancel
// function.
func (cfg *Config) MakeContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), cfg.timeout)
}
