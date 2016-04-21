// Copyright (c) 2014-2016 Bitmark Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// global system configuration for the program
type SystemConfiguration struct {
	Listen        string                `libucl:"listen"`         // e.g. "127.0.0.1:1234"
	ServerName    string                `libucl:"server_name"`    // e.g. "proxy.domain.tld"
	ClientAuth    bool                  `libucl:"client_auth"`    // e.g. true (then clients must use certificate)
	CACertificate string                `libucl:"ca_certificate"` // e.g. "ca.crt"
	Certificate   string                `libucl:"certificate"`    // e.g. "server.crt"
	PrivateKey    string                `libucl:"private_key"`    // e.g. "server.key"
	RunAs         RunAsConfiguration    `libucl:"run_as"`         // currently only applies to FreeBSD
	Chain         string                `libucl:"chain"`          // e.g. "testnet" or "livenet"
	Remotes       []RemoteConfiguration `libucl:"remotes"`
}

type RunAsConfiguration struct {
	Username string `libucl:"username"` // e.g. "nobody",
}

type RemoteConfiguration struct {
	Enable        bool   `libucl:"enable"`         // e.g. true
	Username      string `libucl:"username"`       // e.g. "user",
	Password      string `libucl:"password"`       // e.g. "some securepassword"
	CACertificate string `libucl:"ca_certificate"` // e.g. "ca.crt"
	Certificate   string `libucl:"certificate"`    // e.g. "client.crt"
	PrivateKey    string `libucl:"private_key"`    // e.g. "client.key"
	URL           string `libucl:"url"`            // e.g. "http://127.0.0.1:17001" or https and use certificates/key
	ServerName    string `libucl:"server_name"`    // e.g. "proxy.domain.tld"
}

// entry point
func main() {
	if len(os.Args) < 2 {
		log.Printf("%s version: %s\n", os.Args[0], Version)
		log.Fatalf("usage: %s miniature-spoon.conf\n", os.Args[0])
	}
	configurationFileName := os.Args[1]

	var system SystemConfiguration
	err := readConfigurationFile(configurationFileName, &system)
	if nil != err {
		log.Fatalf("configuration error: %v\n", err)
	}

	//log.Printf("system: %v\n", system)

	server := &http.Server{
		Addr:           system.Listen,
		Handler:        pageHandler("dummy argument"),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// server TLS data
	certificatePool, keyPair, err := getCertificateData(system.CACertificate, system.Certificate, system.PrivateKey)
	if err != nil {
		log.Fatalf("server configuration error: %v\n", err)
	}

	// optional authentication
	clientAuth := tls.RequireAndVerifyClientCert
	if !system.ClientAuth {
		clientAuth = tls.VerifyClientCertIfGiven
	}

	if "" == system.ServerName {
		log.Fatal("server configuration server_name cannot be empty\n")
	}
	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{
			*keyPair,
		},
		NameToCertificate:        nil,
		GetCertificate:           nil,
		NextProtos:               nil,
		ServerName:               system.ServerName,
		ClientAuth:               clientAuth,      // server client certificate policy
		ClientCAs:                certificatePool, // servers use to verify a client certificate
		InsecureSkipVerify:       false,
		CipherSuites:             nil,
		PreferServerCipherSuites: true,
		MinVersion:               12, // force 1.2 and above
		MaxVersion:               0,  // no maximum
		CurvePreferences:         nil,
	}

	connections := 0
	continueRunning := true
	for i, remote := range system.Remotes {
		if !remote.Enable {
			continue
		}

		tlsConfiguration := (*tls.Config)(nil)
		// client TLS data enabled
		if strings.HasPrefix(remote.URL, "https:") {

			certificatePool, keyPair, err := getCertificateData(remote.CACertificate, remote.Certificate, remote.PrivateKey)
			if err != nil {
				log.Fatalf("client configuration error: %v\n", err)
			}
			tlsConfiguration = &tls.Config{
				// client configuration for TLS

				Certificates: []tls.Certificate{
					*keyPair,
				},
				NameToCertificate:        nil,
				GetCertificate:           nil,
				RootCAs:                  certificatePool, // client verify server certificate
				NextProtos:               nil,
				ServerName:               remote.ServerName,
				InsecureSkipVerify:       false,
				CipherSuites:             nil,
				PreferServerCipherSuites: true,
				MinVersion:               12, // force 1.2 and above
				MaxVersion:               0,  // no maximum
				CurvePreferences:         nil,
			}

		} else if !strings.HasPrefix(remote.URL, "http:") {
			log.Printf("remote[%d] invalid URL: %q\n", i, remote.URL)
		}

		rpcconn, err := NewRemoteConnection(remote.URL, remote.Username, remote.Password, system.Chain, tlsConfiguration)
		if ErrAccessDenied == err {
			log.Printf("remote[%d] %q error: %v\n", i, remote.URL, err)
			continueRunning = false
		} else if nil != err {
			log.Printf("remote[%d] %q  error: %v\n", i, remote.URL, err)
		} else {
			connections += 1
			defer rpcconn.Destroy()
		}
	}
	if 0 == connections {
		log.Fatal("no connected remote servers")
	} else if !continueRunning {
		log.Fatal("invalid bitcoin authentication configuration")
	}

	if "" != system.RunAs.Username {
		err := DropPrivTo(system.RunAs.Username)
		if nil != err {
			log.Fatalf("RunAs username: %q error: %v\n", system.RunAs.Username, err)
		}
	}

	log.Fatal(server.ListenAndServeTLS("", ""))
}

// check if file exists
func ensureFileExists(name string) bool {
	_, err := os.Stat(name)
	return nil == err
}

// fetch the CA, certificate and key data
func getCertificateData(caCertificateFile string, certificateFile string, privateKeyFile string) (*x509.CertPool, *tls.Certificate, error) {

	if !ensureFileExists(caCertificateFile) {
		return nil, nil, fmt.Errorf("file: %q does not exist", caCertificateFile)
	}
	if !ensureFileExists(certificateFile) {
		return nil, nil, fmt.Errorf("file: %q does not exist", certificateFile)
	}
	if !ensureFileExists(privateKeyFile) {
		return nil, nil, fmt.Errorf("file: %q does not exist", privateKeyFile)
	}

	// verification pool
	certificatePool := x509.NewCertPool()

	data, err := ioutil.ReadFile(caCertificateFile)
	if err != nil {
		return nil, nil, err
	}

	if !certificatePool.AppendCertsFromPEM(data) {
		return nil, nil, err
	}

	// set up TLS
	keyPair, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, nil, err
	}

	return certificatePool, &keyPair, nil
}
