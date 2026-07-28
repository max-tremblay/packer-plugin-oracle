// Copyright IBM Corp. 2013, 2025
// SPDX-License-Identifier: MPL-2.0

package oci

// Opt-in workaround for an OCI edge/load-balancer bug where the HTTP/1.1
// response to certain Compute API calls (observed on CreateImage, POST
// /20160918/images) contains a corrupted header line, e.g.:
//
//	application/json: application/json
//
// "application/json" is not a valid HTTP header field-name ('/' is outside
// the RFC 7230 token grammar), so Go's net/textproto.ReadMIMEHeader
// correctly, per spec, refuses to parse the response, and the whole
// request fails with:
//
//	net/http: HTTP/1.x transport connection broken: malformed MIME header
//	line: "application/json: application/json"
//
// The request has actually already succeeded on OCI's backend; only the
// client-side parse fails. Setting OCI_LENIENT_HTTP_PARSING=1 installs an
// HTTP client that scans the raw response byte stream for header lines
// with an invalid field-name and drops them before net/http ever sees
// them, so well-formed responses are completely unaffected and only the
// offending line(s) get stripped.
//
// This forces HTTP/1.1 (ALPN restricted to "http/1.1") because the
// sanitizer only understands HTTP/1.1's text-based header framing, and it
// disables keep-alives so each response gets its own connection -- the
// sanitizer's "still inside the header block" state is per-connection,
// and that's only unambiguous if a connection carries exactly one
// response. It also hand-rolls HTTP CONNECT proxy tunneling (mirroring
// http.ProxyFromEnvironment), since setting Transport.DialTLSContext
// bypasses Go's built-in proxy handling for HTTPS requests.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const lenientHTTPParsingEnvVar = "OCI_LENIENT_HTTP_PARSING"

func lenientHTTPParsingEnabled() bool {
	return os.Getenv(lenientHTTPParsingEnvVar) == "1"
}

// isValidHeaderFieldNameByte reports whether b is a legal HTTP token
// character per RFC 7230 section 3.2.6.
func isValidHeaderFieldNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// isValidHeaderLine reports whether line (including its trailing CRLF/LF)
// is a syntactically valid "field-name: field-value" HTTP header line, by
// checking that the field-name portion (before the first colon) consists
// solely of legal token characters. The blank line ending the header
// block, and any line that doesn't look like key:value at all, are left
// alone -- only unambiguously-invalid field-names are flagged.
func isValidHeaderLine(line string) bool {
	trimmed := strings.TrimRight(line, "\r\n")
	if trimmed == "" {
		return true
	}
	colon := strings.IndexByte(trimmed, ':')
	if colon <= 0 {
		return true
	}
	for i := 0; i < colon; i++ {
		if !isValidHeaderFieldNameByte(trimmed[i]) {
			return false
		}
	}
	return true
}

// headerSanitizingConn wraps an already-negotiated (post-TLS) net.Conn and
// strips header lines with an invalid field-name from the response stream
// before handing bytes to net/http's reader. It only inspects bytes up to
// the blank line ending the header block; everything after passes through
// untouched. Requires the connection to carry exactly one response (see
// DisableKeepAlives in newLenientHTTPClient).
type headerSanitizingConn struct {
	net.Conn
	r         *bufio.Reader
	sanitized bytes.Buffer
	inHeaders bool
}

func newHeaderSanitizingConn(c net.Conn) *headerSanitizingConn {
	return &headerSanitizingConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		inHeaders: true,
	}
}

func (c *headerSanitizingConn) Read(p []byte) (int, error) {
	if !c.inHeaders {
		if c.sanitized.Len() > 0 {
			return c.sanitized.Read(p)
		}
		return c.r.Read(p)
	}

	for c.sanitized.Len() == 0 {
		line, err := c.r.ReadString('\n')
		if len(line) > 0 {
			if isValidHeaderLine(line) {
				c.sanitized.WriteString(line)
			}
			if strings.TrimRight(line, "\r\n") == "" {
				c.inHeaders = false
			}
		}
		if err != nil {
			if c.sanitized.Len() == 0 {
				return 0, err
			}
			break
		}
		if !c.inHeaders {
			break
		}
	}
	return c.sanitized.Read(p)
}

// dialWithOptionalProxy dials addr directly, or -- if HTTP_PROXY/HTTPS_PROXY/
// NO_PROXY resolve a proxy for it -- dials the proxy and establishes a
// CONNECT tunnel to addr, mirroring what http.Transport would normally do
// for us before DialTLSContext takes over that responsibility.
func dialWithOptionalProxy(ctx context.Context, dialer *net.Dialer, addr string) (net.Conn, error) {
	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
	if err != nil {
		return nil, fmt.Errorf("resolving proxy for %s: %w", addr, err)
	}
	if proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", addr)
	}

	conn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("dialing proxy %s: %w", proxyURL.Host, err)
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		creds := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		connectReq.Header.Set("Proxy-Authorization", "Basic "+creds)
	}

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("writing CONNECT to proxy %s: %w", proxyURL.Host, err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading CONNECT response from proxy %s: %w", proxyURL.Host, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT to %s via %s failed: %s", addr, proxyURL.Host, resp.Status)
	}

	return conn, nil
}

// newLenientHTTPClient builds the HTTPRequestDispatcher installed on the
// compute client when OCI_LENIENT_HTTP_PARSING=1 is set.
func newLenientHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := dialWithOptionalProxy(ctx, dialer, addr)
			if err != nil {
				return nil, err
			}

			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName: host,
				NextProtos: []string{"http/1.1"},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}

			return newHeaderSanitizingConn(tlsConn), nil
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 3 * time.Second,
	}

	return &http.Client{Transport: transport, Timeout: 60 * time.Second}
}
