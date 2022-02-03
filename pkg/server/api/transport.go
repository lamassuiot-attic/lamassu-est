package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/lamassuiot/lamassu-est/pkg/server/api/mtls"
	"github.com/lamassuiot/lamassu-est/pkg/utils"

	"github.com/gorilla/mux"
	stdopentracing "github.com/opentracing/opentracing-go"
	"go.mozilla.org/pkcs7"
)

type errorer interface {
	error() error
}
type contextKey string

const (
	LamassuLoggerContextkey contextKey = "LamassuLogger"
)

func HTTPToContext(logger log.Logger) httptransport.RequestFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		// Try to join to a trace propagated in `req`.
		logger := log.With(logger, "span_id", stdopentracing.SpanFromContext(ctx))
		return context.WithValue(ctx, LamassuLoggerContextkey, logger)
	}
}
func MakeHTTPHandler(service Service, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	router := mux.NewRouter()
	endpoints := MakeServerEndpoints(service, otTracer)

	options := []httptransport.ServerOption{
		httptransport.ServerBefore(HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(EncodeError),
	}

	// MUST as per rfc7030
	router.Methods("GET").Path("/.well-known/est/cacerts").Handler(httptransport.NewServer(
		endpoints.GetCAsEndpoint,
		DecodeRequest,
		EncodeGetCaCertsResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "cacerts", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/{aps}/simpleenroll").Handler(httptransport.NewServer(
		mtls.NewParser()(endpoints.EnrollerEndpoint),
		//endpoints.EnrollerEndpoint,
		DecodeEnrollRequest,
		EncodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simpleenroll", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/simplereenroll").Handler(httptransport.NewServer(
		mtls.NewParser()(endpoints.ReenrollerEndpoint),
		//endpoints.ReenrollerEndpoint,
		DecodeReenrollRequest,
		EncodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "simplereenroll", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	router.Methods("POST").Path("/.well-known/est/{aps}/serverkeygen").Handler(httptransport.NewServer(
		mtls.NewParser()(endpoints.ServerKeyGenEndpoint),
		//endpoints.ServerKeyGenEndpoint,
		DecodeServerkeygenRequest,
		EncodeServerkeygenResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "serverkeygen", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	return router
}

func DecodeRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req EmptyRequest
	return req, nil
}

func DecodeEnrollRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	aps, ok := vars["aps"]

	if !ok {
		return nil, ErrInvalidAPS
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/pkcs10" {
		return nil, ErrIncorrectType
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, ErrEmptyBody
	}

	decodedCsr, err := utils.Base64Decode(data)
	if err != nil {
		return nil, ErrInvalidBase64
	}

	csr, _ := x509.ParseCertificateRequest(decodedCsr)

	ClientCert := r.Header.Get("X-Forwarded-Client-Cert")

	if len(ClientCert) != 0 {
		splits := strings.Split(ClientCert, ";")
		Cert := splits[1]
		Cert = strings.Split(Cert, "=")[1]
		Cert = strings.Replace(Cert, "\"", "", -1)
		decodedCert, _ := url.QueryUnescape(Cert)

		block, _ := pem.Decode([]byte(decodedCert))

		certificate, _ := x509.ParseCertificate(block.Bytes)
		req := EnrollRequest{
			csr: csr,
			crt: certificate,
			aps: aps,
		}
		return req, nil

	} else if len(r.TLS.PeerCertificates) != 0 {
		cert := r.TLS.PeerCertificates[0]

		req := EnrollRequest{
			csr: csr,
			crt: cert,
			aps: aps,
		}
		return req, nil

	} else {
		return nil, ErrNoClientCertificate
	}
}

func DecodeReenrollRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/pkcs10" {
		return nil, ErrIncorrectType
	}
	/*certContent, err := ioutil.ReadFile("/home/ikerlan/tmp/device1.crt")
	cpb, _ := pem.Decode(certContent)

	crt, err := x509.ParseCertificate(cpb.Bytes)*/
	data, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return nil, ErrEmptyBody
	}

	decodedCsr, err := utils.Base64Decode(data)
	if err != nil {
		return nil, ErrInvalidBase64
	}
	csr, _ := x509.ParseCertificateRequest(decodedCsr)

	ClientCert := r.Header.Get("X-Forwarded-Client-Cert")
	if len(ClientCert) != 0 {
		splits := strings.Split(ClientCert, ";")
		Cert := splits[1]
		Cert = strings.Split(Cert, "=")[1]
		Cert = strings.Replace(Cert, "\"", "", -1)
		decodedCert, _ := url.QueryUnescape(Cert)

		block, _ := pem.Decode([]byte(decodedCert))

		certificate, _ := x509.ParseCertificate(block.Bytes)

		req := ReenrollRequest{
			csr: csr,
			crt: certificate,
		}
		return req, nil

	} else if len(r.TLS.PeerCertificates) != 0 {
		cert := r.TLS.PeerCertificates[0]

		req := ReenrollRequest{
			csr: csr,
			crt: cert,
		}
		return req, nil

	} else {
		return nil, ErrNoClientCertificate
	}

}

func DecodeServerkeygenRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	aps, ok := vars["aps"]

	if !ok {
		return nil, ErrInvalidAPS
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/pkcs10" {
		return nil, ErrIncorrectType
	}
	data, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return nil, ErrEmptyBody
	}

	decodedCsr, err := utils.Base64Decode(data)
	if err != nil {
		return nil, ErrInvalidBase64
	}
	csr, _ := x509.ParseCertificateRequest(decodedCsr)

	req := ServerKeyGenRequest{
		csr: csr,
		aps: aps,
	}
	return req, nil

}

func EncodeServerkeygenResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		EncodeError(ctx, e.error(), w)
		return nil
	}
	Serverkeygenresponse := response.(ServerKeyGenResponse)
	key := Serverkeygenresponse.Key
	cert := Serverkeygenresponse.Cert
	var keyContentType string

	_, p8err := x509.ParsePKCS8PrivateKey(key)
	_, p7err := pkcs7.Parse(key)
	if p8err == nil {
		keyContentType = "application/pkcs8"
	} else if p7err == nil {
		keyContentType = "application/pkcs7-mime; smime-type=server-generated-key"
	} else {
		EncodeError(ctx, p7err, w)
		return p7err

	}
	data, contentType, err := utils.EncodeMultiPart(
		"estServerKeyGenBoundary",
		[]utils.MultipartPart{
			{ContentType: keyContentType, Data: key},
			{ContentType: "application/pkcs7-mime; smime-type=certs-only", Data: cert},
		},
	)
	if err != nil {
		return err
	}
	body := utils.Base64Encode(data.Bytes())
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return nil
}

func EncodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		EncodeError(ctx, e.error(), w)
		return nil
	}
	enrollResponse := response.(EnrollReenrollResponse)
	cert := enrollResponse.Cert
	var cb []byte
	cb = append(cb, cert.Raw...)

	body, err := pkcs7.DegenerateCertificate(cb)
	if err != nil {
		EncodeError(ctx, err, w)
		return nil
	}
	body = utils.Base64Encode(body)

	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return nil
}

func EncodeGetCaCertsResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		EncodeError(ctx, e.error(), w)
		return nil
	}
	getCAsResponse := response.(GetCasResponse)
	var cb []byte
	for _, cert := range getCAsResponse.Certs {
		cb = append(cb, cert.Raw...)
	}

	body, err := pkcs7.DegenerateCertificate(cb)
	if err != nil {
		EncodeError(ctx, err, w)
		return nil
	}

	body = utils.Base64Encode(body)

	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")

	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return nil
}

func EncodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	http.Error(w, err.Error(), codeFrom(err))
}

func codeFrom(err error) int {
	switch err {
	default:
		return http.StatusInternalServerError
	}
}
