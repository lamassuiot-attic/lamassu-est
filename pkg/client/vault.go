package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/globalsign/est"
	"log"
	"net/http"
)

type VaultService struct {
	client *Client
}

func (ca *VaultService) CACerts(ctx context.Context, aps string, req *http.Request, ) ([]*x509.Certificate, error) {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	url := "v1/cas"

	var bearer = "Bearer " + "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDLWxGZU9OY1d2ZnBHYWVXeUppREYxeVFlOS1uU0VYVkYyQnZkV2dJckhzIn0.eyJleHAiOjE3MDk0NjgyNzgsImlhdCI6MTYyMzA2ODI3OCwianRpIjoiMDQ2ZGMyZGMtODkwZS00YTIzLWEwOGEtNTgxODNhNmI5ZmE2IiwiaXNzIjoiaHR0cHM6Ly9rZXljbG9hay5sYW1hc3N1LnpwZC5pa2VybGFuLmVzOjg0NDMvYXV0aC9yZWFsbXMvbGFtYXNzdSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyNmJmYTExMC1mN2ExLTQ1ODctODNmNS1mZTgwOGQ1OThhYWEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJsYW1hc3N1LWVucm9sbGVyIiwic2Vzc2lvbl9zdGF0ZSI6Ijc1ODU2NGNiLTM4NDMtNGNlOS04YzI5LTc0NDIwN2VhNjg5MCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1sYW1hc3N1Iiwib2ZmbGluZV9hY2Nlc3MiLCJhZG1pbiIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJlbnJvbGxlciJ9.RqjUhSTbwNDbVhRhKewBJFucU0KlAcUXQl9Jp9ZosOu5dRH_iAb5C700qIMpDgXHyv5KuaSrZY9zmpUqs5XIik1da6Q9Jzlly-dqkpuITjf3MsOkjL2o8JBFE_3BrIVVWWDN9Esr7V7b-oZrH1Lbqx3V36TSCAKh5OGprIbJsKQIPi-eSaZzelf7zf-IPO2uyDMEqOsrPCTxmGWjZEtp9UQu2mvkshiT73YAIY5JKbw_1N1G14cV_Wyc78ov2Fl3KDZFVyVrC7ym5HS-p8_afDe650ycOj3hnmxkksf7D7fPutCeoK-2-yIZxBrUl8uqZTI3zGIdqd4_XkeP9vuNPg"

	req, err := ca.client.newRequest("GET", url, nil)
	if err != nil {
		log.Println("Error on creating request.\n[ERROR] -", err)
	}
	req.Header.Add("Authorization", bearer)

	var certs []Cert
	_, err = ca.client.do(req, &certs)
	if err != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}

	var filteredCerts []*x509.Certificate

	for _, v := range certs {
		block, _ := pem.Decode([]byte(v.CRT))
		if block == nil {
			panic("failed to parse certificate PEM")
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Println("Error on response.\n[ERROR] -", err)
		}
		filteredCerts = append(filteredCerts, crt)
	}

	return []*x509.Certificate{}, err
}

func (ca *VaultService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	// TODO: Process any requested triggered errors.
	return nil, nil
}

func (ca *VaultService) CSRAttrs(ctx context.Context, aps string, r *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs {}, nil
}

func (ca *VaultService) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	return nil, nil
}

func (ca *VaultService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	return nil, nil, nil
}

func (ca *VaultService) TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}


type Cert struct {
	// The status of the CA
	// required: true
	// example: issued | expired
	Status string `json:"status,omitempty"`

	// The serial number of the CA
	// required: true
	// example: 7e:36:13:a5:31:9f:4a:76:10:64:2e:9b:0a:11:07:b7:e6:3e:cf:94
	SerialNumber string `json:"serial_number,omitempty"`

	// The serial number of the CA
	// required: true
	// example: 7e:36:13:a5:31:9f:4a:76:10:64:2e:9b:0a:11:07:b7:e6:3e:cf:94
	CaName string `json:"ca_name,omitempty"`

	// PEM ca certificate
	// required: false
	// example: ----BEGIN CERTIFICATE-----\nMIID2TCCAsGgAwIBAgIUcYimUsFDI6395PM2WbAvPEtbfjowDQYJKoZIhvcNAQEL\nBQAwczELMAkGA1UEBhMCRVMxETAPBgNVBAgTCEdpcHV6a29hMREwDwYDVQQHEwhB\ncnJhc2F0ZTEhMA4GA1UEChMHUy4gQ29vcDAPBgNVBAoTCExLUyBOZXh0MRswGQYD\nVQQDExJMS1MgTmV4dCBSb290IENBIDIwIBcNMjEwNTE4MTEzNzM2WhgPMjA1MTA1\nMTExMTM4MDZaMHMxCzAJBgNVBAYTAkVTMREwDwYDVQQIEwhHaXB1emtvYTERMA8G\nA1UEBxMIQXJyYXNhdGUxITAOBgNVBAoTB1MuIENvb3AwDwYDVQQKEwhMS1MgTmV4\ndDEbMBkGA1UEAxMSTEtTIE5leHQgUm9vdCBDQSAyMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA2ePwTAHaGPd3H/I3mRkLqL0GxgcZw/VlSHfT0I6clIvQ\n1Ulc7kL0NZRTYPOsBQIjWuu61PwSwPgop/N+slMYpG/NOJwKzH9JHAjNKISuNasS\n66Q3pLBK/QMHIZsaRkPOCfVlQeV75YFhehtabxM10CLdJq9HE5iKY/B1SEdCcAz4\nGbzVy/DzdqAtHrdwyjlS2DM+hYWEvUwbZIzSAWlOtIMHCYypd5wvYTN3tfsYtjft\nTwT3gIdoQTz4eOF/HGmE3NglO3qJspze7sgMDmcfBrgo51C+XOfmZ5zYk1cJSkjM\nsT3tcmwJlBP6va2AGTuTtCQDhbGbnXM33uIlh7L9JQIDAQABo2MwYTAOBgNVHQ8B\nAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUMfBBHj4BJqvG8FRH\n2nMrdF/JZo8wHwYDVR0jBBgwFoAUMfBBHj4BJqvG8FRH2nMrdF/JZo8wDQYJKoZI\nhvcNAQELBQADggEBANWH9n6Ezh0hmozhtu8HGKybIxAVTmxiXirY3sYwIsMyB1Ns\nljbGaah4qqmzQKCAqfaeQbd1YMER+C98OnA7S/xV0Vxucu5g/obFekXyJf1U9SLW\nfh5tuCtsfgkSNPLk21hWMFfZR3hJKfcK6GuoTOW6cBUf+VbWLO6tsO011xWF4tYj\nfppbk7wHT6LIFY3wsKl5ti16U0gd/s9XfqYR84y9bZWZ+SGzNC3n9OWxvYnOrX/B\nNO/ucnBKon7kpHX91kkj9kWRNONAf2lWTeg0WcUm2e1sim6fEekux7cg1PCqz3Li\n2zRuHYvLO1cBeXQ+8olyCpBQDWaXMWkoNW49xbY=\n-----END CERTIFICATE-----
	CRT string `json:"crt,omitempty"`

	PublicKey string `json:"pub_key,omitempty"`

	// Common name of the CA certificate
	// required: true
	// example: Lamassu-Root-CA1-RSA4096
	CN string `json:"common_name"`

	// Algorithm used to create CA key
	// required: true
	// example: RSA
	KeyType string `json:"key_type"`

	// Length used to create CA key
	// required: true
	// example: 4096
	KeyBits int `json:"key_bits"`

	// Strength of the key used to the create CA
	// required: true
	// example: low
	KeyStrength string `json:"key_strength,omitempty"`

	// Organization of the CA certificate
	// required: true
	// example: Lamassu IoT
	O string `json:"organization"`

	// Organization Unit of the CA certificate
	// required: true
	// example: Lamassu IoT department 1
	OU string `json:"organization_unit"`

	// Country Name of the CA certificate
	// required: true
	// example: ES
	C string `json:"country"`

	// State of the CA certificate
	// required: true
	// example: Guipuzcoa
	ST string `json:"state"`

	// Locality of the CA certificate
	// required: true
	// example: Arrasate
	L string `json:"locality"`

	// Expiration period of the new emmited CA
	// required: true
	// example: 262800h
	CaTTL int `json:"ca_ttl,omitempty"`

	EnrollerTTL int `json:"enroller_ttl,omitempty"`

	ValidFrom string
	ValidTO   string
}

type CAImport struct {
	PEMBundle string `json:"pem_bundle"`
	TTL       int    `json:"ttl"`
}

// CAs represents a list of CAs with minimum information
// swagger:model
type Certs struct {
	Certs []Cert `json:"certs"`
}

type Secrets interface {
	GetCAs() (Certs, error)
	CreateCA(caName string, ca Cert) error
	ImportCA(caName string, caImport CAImport) error
	DeleteCA(caName string) error

	GetIssuedCerts(caName string) (Certs, error)
	DeleteCert(caName string, serialNumber string) error
}

