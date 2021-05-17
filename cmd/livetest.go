package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
)

func LiveTest() error {
	var err error

	// Server

	tlsVersion := func(ver uint16) string {
		switch ver {
		case tls.VersionTLS10:
			return "TLSv1.0"
		case tls.VersionTLS11:
			return "TLSv1.1"
		case tls.VersionTLS12:
			return "TLSv1.2"
		case tls.VersionTLS13:
			return "TLSv1.3"
		}
		return "You must live in the future."
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %v", tlsVersion(r.TLS.Version), r.Proto)
	}))
	defer ts.Close()

	ts.TLS, err = ServerTLSConfig()
	if err != nil {
		return err
	}
	ts.EnableHTTP2 = true
	ts.StartTLS()

	// Client

	clientTLSConfig, err := ClientTLSConfig()
	if err != nil {
		return err
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLSConfig, ForceAttemptHTTP2: true}}

	fmt.Printf("GET %s\n", ts.URL)
	resp, err := client.Get(ts.URL)
	if err != nil {
		return fmt.Errorf("client.Get(\"%s\"): %w", ts.URL, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("ioutil.ReadAll(resp.Body): %v", err)
	}
	fmt.Printf("%s - %s\n", resp.Status, string(body))
	return nil
}

func RootCertPool() (*x509.CertPool, error) {
	rootCertPool := x509.NewCertPool()
	rootPEM, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		return nil, err
	}
	if ok := rootCertPool.AppendCertsFromPEM(rootPEM); !ok {
		return nil, fmt.Errorf("failed to append root CA PEM")
	}

	return rootCertPool, nil
}

func ServerTLSConfig() (*tls.Config, error) {
	rootCertPool, err := RootCertPool()
	if err != nil {
		return nil, err
	}

	certificate, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		RootCAs:      rootCertPool,
		Certificates: []tls.Certificate{certificate},

		ClientCAs: rootCertPool,
		VerifyConnection: func(state tls.ConnectionState) error {
			const expectedSAN = "MySQL Service Account"
			hasClientAuth := false
			hasExpectedSAN := false
			var dnsNames []string
			for _, peerCert := range state.PeerCertificates {
				for _, extKeyUsage := range peerCert.ExtKeyUsage {
					if extKeyUsage == x509.ExtKeyUsageClientAuth {
						hasClientAuth = true
						break
					}
				}
				for _, dnsName := range peerCert.DNSNames {
					if dnsName == expectedSAN {
						hasExpectedSAN = true
						break
					}
					dnsNames = append(dnsNames, dnsName)
				}
				if hasClientAuth && hasExpectedSAN {
					return nil
				}
			}
			return fmt.Errorf("client_auth: %v dns_names: %q expected: %q", hasClientAuth, strings.Join(dnsNames, ","), expectedSAN)
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}, nil
}

func ClientTLSConfig() (*tls.Config, error) {
	rootCertPool, err := RootCertPool()
	if err != nil {
		return nil, err
	}

	certificate, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		RootCAs:      rootCertPool,
		Certificates: []tls.Certificate{certificate},
		ServerName:   "MySQL",
	}, nil
}
