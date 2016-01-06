// Copyright (c) 2014-2016 Bitmark Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type Request struct {
	ID         json.RawMessage   `json:"id"`
	Method     string            `json:"method"`
	Parameters []json.RawMessage `json:"params"`
}

type theResult struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

type errorResult struct {
	ID     json.RawMessage `json:"id"`
	Result []byte          `json:"result"`
	Error  string          `json:"error"`
}

type aHandler struct {
	arg string
}

// set up the HTTP handling
func pageHandler(arg string) http.Handler {

	return &aHandler{
		arg: arg,
	}
}

func (f aHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//log.Printf("req: %v\n", r)

	if "POST" != r.Method {
		http.NotFound(w, r)
		return
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if nil != err {
		http.NotFound(w, r)
		return
	}

	var data Request
	err = json.Unmarshal(body, &data)
	if nil != err {
		log.Printf("json.Unmarshal result error: %v\n", err)
		http.NotFound(w, r)
		return
	}

	var result interface{}

	//log.Printf("path: %s\n", r.URL.Path)

	switch r.URL.Path {

	case "/rpc-call":
		result = f.send(w, r, &data)

	default:
		err = errors.New("invalid path")
	}

	if nil != err {
		http.NotFound(w, r)
		return
	}

	buffer, err := json.Marshal(result)
	if nil != err {
		log.Printf("json.Marshal result error: %v\n", err)
		http.NotFound(w, r)
		return
	}
	r.Header.Add("Content-Type", "application/json")
	fmt.Fprintln(w, string(buffer))
}

// send a record
func (f aHandler) send(w http.ResponseWriter, r *http.Request, data *Request) interface{} {

	//log.Printf("data: %v\n", data)

	resp, rpcerr, err := BitcoinCall(data.Method, data.Parameters)
	//log.Printf("resp: %v\n", resp)
	//log.Printf("resp: %s\n", resp)
	//log.Printf("RPC error: %v\n", rpcerr)
	//log.Printf("error: %v\n", err)

	if nil != err {
		return &errorResult{
			ID:     data.ID,
			Result: []byte{},
			Error:  err.Error(),
		}
	}

	return &theResult{
		ID:     data.ID,
		Result: resp,
		Error:  rpcerr,
	}
}
