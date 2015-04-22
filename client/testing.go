// Copyright 2015 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License. See the AUTHORS file
// for names of contributors.
//
// Author: Marc Berhault (marc@cockroachlabs.com)

package client

import (
	"net/http"

	"github.com/cockroachdb/cockroach/rpc"
)

// CreateTestHTTPClient initialises a new http client with insecure TLS config.
// TODO(marc): load test certs when enforced.
func CreateTestHTTPClient() *http.Client {
	tlsConfig := rpc.LoadInsecureClientTLSConfig().Config()
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
}

// CreateTestHTTPSender initializes a new HTTPSender for 'addr'.
// It uses an insecure TLS config.
func CreateTestHTTPSender(addr string) *HTTPSender {
	return &HTTPSender{
		server: addr,
		client: CreateTestHTTPClient(),
	}
}