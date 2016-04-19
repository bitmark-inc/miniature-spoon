// Copyright (c) 2014-2016 Bitmark Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
)

// global system configuration for the program
type SystemConfiguration struct {
	Listen        string                 `json:"listen"`         // e.g. "127.0.0.1:1234"
	ServerName    string                 `json:"server_name"`    // e.g. "proxy.domain.tld"
	TLS           bool                   `json:"tls"`            // e.g. true (then files below must exist)
	ClientAuth    bool                   `json:"client_auth"`    // e.g. true (then client must use certificate)
	CACertificate string                 `json:"ca_certificate"` // e.g. "ca.crt"
	Certificate   string                 `json:"certificate"`    // e.g. "server.crt"
	PrivateKey    string                 `json:"private_key"`    // e.g. "server.key"
	RunAs         RunAsConfiguration     `json:"run_as"`
	Bitcoin       []BitcoinConfiguration `json:"bitcoin"`
}

type RunAsConfiguration struct {
	Username string `json:"username"` // e.g. "nobody",
}

type BitcoinConfiguration struct {
	Enable   bool   `json:"enable"`   // e.g. true
	Username string `json:"username"` // e.g. "user",
	Password string `json:"password"` // e.g. "some securepassword"
	URL      string `json:"url"`      // e.g. "http://127.0.0.1:17001"
}

// entry point
func main() {
	if len(os.Args) < 2 {
		log.Printf("%s version: %s\n", os.Args[0], Version)
		log.Fatalf("usage: %s config-file.json\n", os.Args[0])
	}
	configurationFileName := os.Args[1]

	var system SystemConfiguration
	parseConfigurationFile(configurationFileName, &system)

	server := &http.Server{
		Addr:           system.Listen,
		Handler:        pageHandler("dummy argument"),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if !system.TLS {
		for i, btConf := range system.Bitcoin {
			rpcconn, err := NewBitcoinConnection(btConf.URL, btConf.Username, btConf.Password)
			if nil != err {
				log.Fatalf("Bitcoin[%d] error: %v\n", i, err)
			}
			defer rpcconn.Destroy()
		}

		if "" != system.RunAs.Username {
			err := DropPrivTo(system.RunAs.Username)
			if nil != err {
				log.Fatalf("RunAs username: %q error: %v\n", system.RunAs.Username, err)
			}
		}

		log.Fatal(server.ListenAndServe())
	}

	// all TLS code below
	if !ensureFileExists(system.CACertificate) {
		log.Fatalf("file: %s does not exist\n", system.CACertificate)
	}
	if !ensureFileExists(system.Certificate) {
		log.Fatalf("file: %s does not exist\n", system.Certificate)
	}
	if !ensureFileExists(system.PrivateKey) {
		log.Fatalf("file: %s does not exist\n", system.PrivateKey)
	}

	// set up TLS
	keyPair, err := tls.LoadX509KeyPair(system.Certificate, system.PrivateKey)
	if err != nil {
		log.Fatalf("failed to load keypair(%q,%q) error: %v", system.Certificate, system.PrivateKey, err)
	}

	certificatePool := x509.NewCertPool()

	data, err := ioutil.ReadFile(system.CACertificate)
	if err != nil {
		log.Fatalf("failed to parse certificate from: %q", system.CACertificate)
	}

	if !certificatePool.AppendCertsFromPEM(data) {
		log.Fatalf("failed to parse certificate from: %q", system.CACertificate)
	}

	// optional authentication
	clientAuth := tls.RequireAndVerifyClientCert
	if !system.ClientAuth {
		clientAuth = tls.VerifyClientCertIfGiven
	}

	serverName := "bitcoin-proxy"
	if "" != system.ServerName {
		serverName = system.ServerName
	}
	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{
			keyPair,
		},
		NameToCertificate:        nil,
		GetCertificate:           nil,
		RootCAs:                  certificatePool,
		NextProtos:               nil,
		ServerName:               serverName,
		ClientAuth:               clientAuth,
		ClientCAs:                certificatePool,
		InsecureSkipVerify:       false,
		CipherSuites:             nil,
		PreferServerCipherSuites: true,
		MinVersion:               12, // force 1.2 and above
		MaxVersion:               0,  // no maximum
		CurvePreferences:         nil,
	}

	connections := 0
	continueRunning := true
	for i, btConf := range system.Bitcoin {
		if !btConf.Enable {
			continue
		}
		rpcconn, err := NewBitcoinConnection(btConf.URL, btConf.Username, btConf.Password)
		if ErrAccessDenied == err {
			log.Printf("Bitcoin[%d] %q error: %v\n", i, btConf.URL, err)
			continueRunning = false
		} else if nil != err {
			log.Printf("Bitcoin[%d] %q  error: %v\n", i, btConf.URL, err)
		} else {
			connections += 1
			defer rpcconn.Destroy()
		}
	}
	if 0 == connections {
		log.Fatal("no connected Bitcoin servers")
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

// read a configuration file, convert JSON, fail if any error
// use the "omitempty" json: tag to decideif field is optional or not
// in error log show json: name for value (if set)
func parseConfigurationFile(fileName string, config interface{}) {

	rv := reflect.ValueOf(config)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		log.Fatal("config parameter must be a pointer")
	}

	s := rv.Elem()
	if s.Kind() != reflect.Struct {
		log.Fatal("config parameter must be a pointer to a struct")
	}

	// read in the whole file
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatalf("cannot open configuration file: %q\n", fileName)
	}

	// parse JSON
	err = json.Unmarshal(data, config)
	if nil != err {
		log.Fatalf("cannot parse configuration file: %q\n", fileName)
	}

	// scan struct to see if configuration items are required to be non-blank
	st := s.Type()
	for i := 0; i < s.NumField(); i += 1 {
		field := st.Field(i)
		if "" == s.Field(i).String() {
			required := true
			name := field.Name
			jsonTags := strings.Split(field.Tag.Get("json"), ",")
			if len(jsonTags) >= 1 {
				if "" != jsonTags[0] {
					name = jsonTags[0]
				}
			scanTags:
				for _, t := range jsonTags[1:] {
					if "omitempty" == t {
						required = false
						break scanTags
					}
				}
			}
			if required {
				log.Fatalf("setting for: %q is missing from configuration file: %q", name, fileName)
			}
		}
	}
}

// check if file exists
func ensureFileExists(name string) bool {
	_, err := os.Stat(name)
	return nil == err
}
