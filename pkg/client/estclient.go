package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/globalsign/pemfile"
	"github.com/lamassuiot/lamassu-est/pkg/utils"
	"go.mozilla.org/pkcs7"
)

type LamassuEstClientConfig struct {
	Client                 BaseClient
	EstServerAddress       string
	EstServerCaCertificate *x509.CertPool
	EstClientCertificate   *x509.Certificate
	EstClientKey           interface{}
	logger                 log.Logger
}

type LamassuEstClient interface {
	CACerts() ([]*x509.Certificate, error)
	Enroll(aps string, csr *x509.CertificateRequest) (*x509.Certificate, error)
	Reenroll(csr *x509.CertificateRequest /*, crt *x509.Certificate*/) (*x509.Certificate, error)
	ServerKeyGen(aps string, csr *x509.CertificateRequest) (*x509.Certificate, []byte, error)
}

func NewLamassuEstClient(estServerAddress string, estServerCaCertFile string, estClientCertificateFile string, estClientKeyFile string, logger log.Logger) (LamassuEstClient, error) {
	serverCertPool, err := utils.CreateCAPool(estServerCaCertFile)
	if err != nil {
		return nil, err
	}

	certContent, err := ioutil.ReadFile(estClientCertificateFile)
	if err != nil {
		return nil, err
	}
	cpb, _ := pem.Decode(certContent)

	crt, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := ioutil.ReadFile(estClientKeyFile)
	if err != nil {
		return nil, err
	}
	privateKey, err := pemfile.ReadPrivateKeyWithPasswordFunc(estClientKeyFile, nil)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certContent, key)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            serverCertPool,
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
	}

	u, err := url.Parse(estServerAddress)
	if err != nil {
		return nil, err
	}

	return &LamassuEstClientConfig{
		Client:                 NewBaseClient(u, httpClient),
		EstServerAddress:       estServerAddress,
		EstServerCaCertificate: serverCertPool,
		EstClientCertificate:   crt,
		EstClientKey:           privateKey,
		logger:                 logger,
	}, nil
}
func (c *LamassuEstClientConfig) CACerts() ([]*x509.Certificate, error) {
	req, err := c.Client.NewRequest(http.MethodGet, "/cacerts", c.EstServerAddress, "", "", "", "application/pkcs7-mime", nil)

	if err != nil {
		return nil, err
	}

	resp, b, err := c.Client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, "application/pkcs7-mime", "base64"); err != nil {
		return nil, err
	}

	decoded, err := utils.Base64Decode(b)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode HTTP response body: %w", err)
	}

	p7, err := pkcs7.Parse(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS7 : %w", err)
	}
	return p7.Certificates, nil

}

func (c *LamassuEstClientConfig) Enroll(aps string, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	level.Info(c.logger).Log("msg", aps)
	reqBody := ioutil.NopCloser(bytes.NewBuffer(utils.Base64Encode(csr.Raw)))

	req, err := c.Client.NewRequest(http.MethodPost, "/simpleenroll", c.EstServerAddress, aps, "application/pkcs10", "base64", "application/pkcs7-mime", reqBody)
	if err != nil {
		return nil, err
	}

	resp, b, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, "application/pkcs7-mime", "base64"); err != nil {
		return nil, err
	}

	decoded, err := utils.Base64Decode(b)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode HTTP response body: %w", err)
	}

	certs, err := utils.DecodePKCS7CertsOnly(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS7: %w", err)
	}

	return certs[0], nil
}

func (c *LamassuEstClientConfig) Reenroll(csr *x509.CertificateRequest /*, crt *x509.Certificate*/) (*x509.Certificate, error) {
	reqBody := ioutil.NopCloser(bytes.NewBuffer(utils.Base64Encode(csr.Raw)))

	req, err := c.Client.NewRequest(http.MethodPost, "/simplereenroll", c.EstServerAddress, "", "application/pkcs10", "base64", "application/pkcs7-mime", reqBody)
	if err != nil {
		return nil, err
	}

	resp, b, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, "application/pkcs7-mime", "base64"); err != nil {
		return nil, err
	}

	decoded, err := utils.Base64Decode(b)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode HTTP response body: %w", err)
	}

	certs, err := utils.DecodePKCS7CertsOnly(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS7: %w", err)
	}

	return certs[0], nil
}

func (c *LamassuEstClientConfig) ServerKeyGen(aps string, csr *x509.CertificateRequest) (*x509.Certificate, []byte, error) {
	reqBody := ioutil.NopCloser(bytes.NewBuffer(utils.Base64Encode(csr.Raw)))
	req, err := c.Client.NewRequest(http.MethodPost, "/serverkeygen", c.EstServerAddress, aps, "application/pkcs10", "base64", "multipart/mixed", reqBody)
	if err != nil {
		return nil, nil, err
	}
	resp, body, err := c.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}

	decoded, err := utils.Base64Decode(body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to base64-decode HTTP response body: %w", err)
	}

	resp.Body = ioutil.NopCloser(bytes.NewBuffer(decoded))
	if err := checkResponseError(resp); err != nil {
		return nil, nil, err
	}

	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, fmt.Errorf("missing or malformed %s header: %w", "Content-Type", err)
	} else if !strings.HasPrefix(mediaType, "multipart/mixed") {
		return nil, nil, fmt.Errorf("unexpected %s: %s", "Content-Type", mediaType)
	}

	mpr := multipart.NewReader(resp.Body, params["boundary"])

	cert, key, err := ProcessAllParts(mpr)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil

}

func checkResponseError(r *http.Response) error {
	if r.StatusCode == http.StatusOK {
		return nil
	}
	var msg string
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil || r.Header.Get("Content-Type") == "" {
		switch mediaType {
		case "", "text/plain", "application/json", "application/problem+json":
			data, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return err
			}

			if len(data) > 0 {
				msg = string(data)
			} else {
				msg = http.StatusText(r.StatusCode)
			}

		default:
			msg = fmt.Sprintf("%s (%s)",
				http.StatusText(r.StatusCode), mediaType)
		}
	}
	var retryAfter int
	if secs := r.Header.Get("Retry-After"); secs != "" {
		retryAfter, err = strconv.Atoi(secs)
		if err != nil {
			if t, err := http.ParseTime(secs); err == nil {
				retryAfter = int(t.Sub(time.Now()).Seconds())
			}
		}

		if retryAfter < 0 {
			retryAfter = 0
		}
	}

	return &estError{
		status:     r.StatusCode,
		desc:       msg,
		retryAfter: retryAfter,
	}
}

func verifyResponseType(r *http.Response, t, e string) error {
	ctype, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return fmt.Errorf("missing or malformed %s header: %w", "Content-Type", err)
	}

	if !strings.HasPrefix(ctype, t) {
		return fmt.Errorf("unexpected %s: %s", "Content-Type", ctype)
	}

	cenc := r.Header.Get("Content-Transfer-Encoding")
	if cenc == "" {
		return fmt.Errorf("missing %s header", "Content-Transfer-Encoding")
	}

	if strings.ToUpper(cenc) != strings.ToUpper(e) {
		return fmt.Errorf("unexpected %s: %s", "Content-Transfer-Encoding", cenc)
	}

	return nil
}
func ProcessAllParts(mpr *multipart.Reader) (*x509.Certificate, []byte, error) {
	var cert *x509.Certificate
	var key []byte
	var numParts = 2
	for i := 1; ; i++ {
		part, err := mpr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
		}
		defer part.Close()
		if i > numParts {
			return nil, nil, fmt.Errorf("more than %d parts in HTTP response", numParts)
		}

		if ce := part.Header.Get("Content-Transfer-Encoding"); ce == "" {
			return nil, nil, fmt.Errorf("missing %s header", "Content-Transfer-Encoding")
		} else if strings.ToUpper(ce) != strings.ToUpper("base64") {
			return nil, nil, fmt.Errorf("unexpected %s: %s", "Content-Transfer-Encoding", ce)
		}

		mediaType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return nil, nil, fmt.Errorf("missing or malformed %s header: %w", "Content-Type", err)
		}

		switch {
		case strings.HasPrefix(mediaType, "application/pkcs8"):
			key, err = utils.ReadAllBase64Response(part)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
			}

		case strings.HasPrefix(mediaType, "application/pkcs7-mime"):
			t := params["smime-type"]

			switch t {
			case "server-generated-key":
				key, err = utils.ReadAllBase64Response(part)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to read HTTP response part: %w", err)
				}

			case "certs-only":
				cert, err = utils.ReadCertResponse(part)
				if err != nil {
					return nil, nil, err
				}

			default:
				return nil, nil, fmt.Errorf("unexpected %s: %s", "smime-type", t)

			}

		default:
			return nil, nil, fmt.Errorf("unexpected %s: %s", "Content-Type", mediaType)
		}
	}

	if cert == nil {
		return nil, nil, errors.New("no certificate returned")
	} else if key == nil {
		return nil, nil, errors.New("no private key returned")
	}

	return cert, key, nil
}
