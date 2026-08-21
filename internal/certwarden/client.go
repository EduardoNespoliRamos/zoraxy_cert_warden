// Package certwarden retrieves certificate material from the Cert Warden API.
package certwarden

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultTimeout   = 30 * time.Second
	maximumBodyBytes = 1 << 20
)

// ErrorKind identifies a category of fetch failure.
type ErrorKind string

const (
	ErrorKindNetwork          ErrorKind = "network"
	ErrorKindTLS              ErrorKind = "tls"
	ErrorKindAuthentication   ErrorKind = "authentication"
	ErrorKindNotFound         ErrorKind = "not_found"
	ErrorKindServer           ErrorKind = "server"
	ErrorKindTimeout          ErrorKind = "timeout"
	ErrorKindResponseTooLarge ErrorKind = "response_too_large"
	ErrorKindInvalidResponse  ErrorKind = "invalid_response"
)

// Credentials contains the two components of a Cert Warden download credential.
type Credentials struct {
	CertificateAPIKey string
	PrivateKeyAPIKey  string
}

// Material is the certificate chain and private key returned by Cert Warden.
type Material struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	RetrievedAt    time.Time
	HTTPStatus     int
	Latency        time.Duration
}

// FetchError is a sanitized error returned by Fetch.
type FetchError struct {
	Kind       ErrorKind
	HTTPStatus int
}

func (e *FetchError) Error() string {
	if e == nil {
		return "certwarden fetch failed"
	}
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("certwarden fetch failed: %s (HTTP %d)", e.Kind, e.HTTPStatus)
	}
	return fmt.Sprintf("certwarden fetch failed: %s", e.Kind)
}

// Client retrieves certificate material from one Cert Warden origin.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient validates the origin and credentials and constructs a client.
// A supplied HTTP client is copied before its redirect and timeout settings are
// changed. Pass nil to use a copy of http.DefaultClient.
func NewClient(baseURL string, credentials Credentials, httpClient *http.Client) (*Client, error) {
	origin, err := validateOrigin(baseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(credentials.CertificateAPIKey) == "" || strings.TrimSpace(credentials.PrivateKeyAPIKey) == "" {
		return nil, errors.New("certwarden credentials are required")
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	clientCopy := *httpClient
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = defaultTimeout
	}
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Client{
		baseURL:    origin,
		apiKey:     strings.TrimSpace(credentials.CertificateAPIKey) + "." + strings.TrimSpace(credentials.PrivateKeyAPIKey),
		httpClient: &clientCopy,
	}, nil
}

// Fetch downloads and separates a named certificate chain and private key.
func (c *Client) Fetch(ctx context.Context, certificateName string) (Material, error) {
	if strings.TrimSpace(certificateName) == "" {
		return Material{}, &FetchError{Kind: ErrorKindInvalidResponse}
	}

	endpoint := c.baseURL + "/certwarden/api/v1/download/privatecertchains/" + url.PathEscape(certificateName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Material{}, &FetchError{Kind: ErrorKindInvalidResponse}
	}
	req.Header.Set("X-API-Key", c.apiKey)

	started := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Material{}, &FetchError{Kind: transportErrorKind(ctx, err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Material{}, &FetchError{Kind: statusErrorKind(resp.StatusCode), HTTPStatus: resp.StatusCode}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maximumBodyBytes+1))
	if err != nil {
		return Material{}, &FetchError{Kind: transportErrorKind(ctx, err), HTTPStatus: resp.StatusCode}
	}
	if len(body) > maximumBodyBytes {
		return Material{}, &FetchError{Kind: ErrorKindResponseTooLarge, HTTPStatus: resp.StatusCode}
	}

	certificates, privateKey, err := splitMaterial(body)
	if err != nil {
		return Material{}, &FetchError{Kind: ErrorKindInvalidResponse, HTTPStatus: resp.StatusCode}
	}

	return Material{
		CertificatePEM: certificates,
		PrivateKeyPEM:  privateKey,
		RetrievedAt:    time.Now(),
		HTTPStatus:     resp.StatusCode,
		Latency:        time.Since(started),
	}, nil
}

func validateOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", errors.New("certwarden base URL must be an HTTPS origin")
	}
	return "https://" + u.Host, nil
}

func statusErrorKind(status int) ErrorKind {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrorKindAuthentication
	case status == http.StatusNotFound:
		return ErrorKindNotFound
	case status >= http.StatusInternalServerError:
		return ErrorKindServer
	default:
		return ErrorKindInvalidResponse
	}
}

func transportErrorKind(ctx context.Context, err error) ErrorKind {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return ErrorKindTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrorKindTimeout
	}

	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateError x509.CertificateInvalidError
	var rootsError x509.SystemRootsError
	var recordError tls.RecordHeaderError
	var alertError tls.AlertError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostnameError) || errors.As(err, &certificateError) || errors.As(err, &rootsError) || errors.As(err, &recordError) || errors.As(err, &alertError) {
		return ErrorKindTLS
	}
	return ErrorKindNetwork
}

func splitMaterial(body []byte) ([]byte, []byte, error) {
	var certificates []byte
	var privateKey []byte
	rest := body

	for len(bytes.TrimSpace(rest)) != 0 {
		begin := bytes.Index(rest, []byte("-----BEGIN "))
		if begin < 0 || len(bytes.TrimSpace(rest[:begin])) != 0 {
			return nil, nil, errors.New("unexpected response material")
		}
		block, remaining := pem.Decode(rest[begin:])
		if block == nil {
			return nil, nil, errors.New("malformed PEM response")
		}

		encoded := rest[begin : len(rest)-len(remaining)]
		switch block.Type {
		case "CERTIFICATE":
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, nil, errors.New("invalid certificate material")
			}
			certificates = append(certificates, encoded...)
		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
			if len(privateKey) != 0 || parsePrivateKey(block) != nil {
				return nil, nil, errors.New("invalid private key material")
			}
			privateKey = encoded
		default:
			return nil, nil, errors.New("unknown response material")
		}
		rest = remaining
	}

	if len(certificates) == 0 || len(privateKey) == 0 {
		return nil, nil, errors.New("incomplete response material")
	}
	return certificates, privateKey, nil
}

func parsePrivateKey(block *pem.Block) error {
	switch block.Type {
	case "RSA PRIVATE KEY":
		_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return err
	case "EC PRIVATE KEY":
		_, err := x509.ParseECPrivateKey(block.Bytes)
		return err
	default:
		_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		return err
	}
}
