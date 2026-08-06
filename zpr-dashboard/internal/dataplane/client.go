// Package dataplane is the HTTP client for the ZPR data plane API. It can talk
// to a local HTTPS service using a self-signed certificate.
package dataplane

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"neboagency.com/zpr-dashborad/internal/config"
)

// apiKeyHeader is the header vs-admin sends the API key in on every request.
const apiKeyHeader = "X-API-Key"

// Default location of the local admin API and the credential files used to
// reach it (relative to the process's working directory).
const (
	defaultBaseURL = "https://127.0.0.1:8182"
	defaultCAFile  = "server.crt"
	defaultKeyFile = "key.txt"
)

type Config struct {
	BaseURL string
	Timeout time.Duration
	CA      string
	APIKey  string
}

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}

	if cfg.CA == "" {
		return nil, fmt.Errorf("CA is required")
	}

	// vs-admin requires an API key on every admin request.
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("APIKey is required")
	}

	pem, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, fmt.Errorf("Read CA file: %w", err)
	}

	// Security measure, trust CA only if (1) well fomed and (2) the one we provided
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("No certificate found in %s", cfg.CA)
	}

	// Default is 30s
	timeout := cmp.Or(cfg.Timeout, 30*time.Second)

	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    pool,

					// Drop this with using a CA certificate with a valid SANs
					InsecureSkipVerify: true,
					VerifyConnection: func(cs tls.ConnectionState) error {
						opts := x509.VerifyOptions{
							Roots:         pool,
							Intermediates: x509.NewCertPool(),
						}
						for _, cert := range cs.PeerCertificates[1:] {
							opts.Intermediates.AddCert(cert)
						}
						_, err := cs.PeerCertificates[0].Verify(opts)
						return err
					},
				},
			},
		},
	}, nil
}

// NewDefault builds a Client for the local admin API from the environment,
// falling back to the constants above. config.Load exports those variables from
// config.toml, so calling it first is what makes the file take effect.
func NewDefault() (*Client, error) {
	keyFile := cmp.Or(os.Getenv(config.EnvKeyFile), defaultKeyFile)

	// The key may be passed inline; otherwise it lives in a file.
	apiKey := os.Getenv(config.EnvAPIKey)
	if apiKey == "" {
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("Read API key file: %w", err)
		}
		apiKey = strings.TrimSpace(string(keyBytes))
	}

	// Empty means "use the default in New".
	var timeout time.Duration
	if raw := os.Getenv(config.EnvTimeout); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("Parse %s: %w", config.EnvTimeout, err)
		}
		timeout = parsed
	}

	return New(Config{
		BaseURL: cmp.Or(os.Getenv(config.EnvBaseURL), defaultBaseURL),
		CA:      cmp.Or(os.Getenv(config.EnvCAFile), defaultCAFile),
		APIKey:  apiKey,
		Timeout: timeout,
	})
}

// This is blocking and therefore must be run on a background context (see actor_test.go)
func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader

	// Encode body
	if body != nil {
		b, err := json.Marshal(body)

		if err != nil {
			return nil, fmt.Errorf("Encode body: %w", err)
		}

		reader = bytes.NewReader(b)
	}

	// Setup request
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)

	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Authenticate: vs-admin sends the API key on every admin request.
	req.Header.Set(apiKeyHeader, c.apiKey)

	// Send!
	return c.http.Do(req)
}

/* -------------------------------------------------------------------------- */
/*                           HTTP Request Shortcuts                           */
/* -------------------------------------------------------------------------- */

func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.do(ctx, http.MethodGet, path, nil)
}

func (c *Client) Post(ctx context.Context, path string, body any) (*http.Response, error) {
	return c.do(ctx, http.MethodPost, path, body)
}

func (c *Client) Delete(ctx context.Context, path string) (*http.Response, error) {
	return c.do(ctx, http.MethodDelete, path, nil)
}
