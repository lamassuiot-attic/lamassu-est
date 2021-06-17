package caservice

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

type Client struct {
	BaseURL  *url.URL
	httpClient *http.Client

	Vault *VaultService
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	client := &Client { httpClient: httpClient }
	client.Vault = &VaultService{Client: client }

	return client
}

func (client *Client) newRequest(method string, path string, body interface{}) (*http.Request, error) {
	rel := &url.URL{ Path: path }
	u := client.BaseURL.ResolveReference(rel)
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func (client *Client) do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(v)

	return resp, err
}

