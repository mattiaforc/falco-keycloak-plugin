// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 Mattia Forcellese

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	webServerShutdownTimeoutSecs = 5
	webServerEventChanBufSize    = 1024 * 1024
	webServerMaxPayloadSize      = 1025 * 1024 * 10
)

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (p *Plugin) Open(params string) (source.Instance, error) {
	u, err := url.Parse(params)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http":
		return p.OpenWebServer(u.Host, u.Path, false)
	case "https":
		return p.OpenWebServer(u.Host, u.Path, true)
	}

	return nil, fmt.Errorf(`scheme "%s" is not supported`, u.Scheme)
}

// OpenWebServer opens a source.Instance event stream that receives Keycloak user/admin events
// by starting a server and listening for the keycloak event exporter HTTP calls.
// Refer to the keyloak-falco-exporter repository for more informations on how to configure Keycloak
// to send events to keycloak.
func (p *Plugin) OpenWebServer(address, endpoint string, ssl bool) (source.Instance, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	serverEvtChan := make(chan []byte, webServerEventChanBufSize)
	evtChan := make(chan source.PushEvent)

	m := http.NewServeMux()
	s := &http.Server{Addr: address, Handler: m}
	sendBody := func(b []byte) {
		defer func() {
			if r := recover(); r != nil {
				p.logger.Println("request dropped while shutting down server ")
			}
		}()
		serverEvtChan <- b
	}

	// The endpoint that will receive keycloak events
	m.HandleFunc(fmt.Sprintf("POST %s", endpoint), func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, int64(webServerMaxPayloadSize))
		bytes, err := io.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("bad request: %s", err.Error())
			p.logger.Println(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		sendBody(bytes)
	})

	go func() {
		defer close(serverEvtChan)
		var err error
		if ssl {
			err = s.ListenAndServeTLS(p.Config.SSLCertificate, p.Config.SSLKey)
		} else {
			err = s.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			evtChan <- source.PushEvent{Err: err}
		}
	}()

	// launch event-parser goroutine. This received webhook payloads
	// and parses their content to extract the list of audit events contained.
	// Then, events are sent to the Push-mode event source instance channel.
	go func() {
		defer close(evtChan)
		for {
			select {
			case bytes, ok := <-serverEvtChan:
				if !ok {
					return
				}
				p.parseKeycloakEventAndPush(bytes, evtChan)
			case <-ctx.Done():
				return
			}
		}
	}()

	// open new instance in with "push" prebuilt
	return source.NewPushInstance(
		evtChan,
		source.WithInstanceContext(ctx),
		source.WithInstanceClose(func() {
			// on close, attempt shutting down the webserver gracefully
			timedCtx, cancelTimeoutCtx := context.WithTimeout(ctx, time.Second*webServerShutdownTimeoutSecs)
			defer cancelTimeoutCtx()
			s.Shutdown(timedCtx)
			cancelCtx()
		}),
	)
}

func (p *Plugin) parseKeycloakEventAndPush(payload []byte, c chan<- source.PushEvent) {
	var e BaseKeycloakEvent
	if err := json.Unmarshal(payload, &e); err != nil {
		p.logger.Println("error while unmarshaling keycloak event", err.Error())
		return
	}

	v := &source.PushEvent{}
	v.Timestamp = time.UnixMilli(e.Time)
	v.Data = payload

	c <- *v
}
