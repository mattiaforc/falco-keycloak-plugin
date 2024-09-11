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
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

// Extract allows Falco plugin framework to get values for all available fields
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	msg := p.lastKeycloakEventMessage
	userEvent := p.lastKeycloakUserEventMessage
	adminEvent := p.lastKeycloakAdminEventMessage

	// For avoiding to Unmarshal the same message for each field to extract
	// we store it with its EventNum. When it's a new event with a new message, we
	// update the Plugin struct.
	if evt.EventNum() != p.lastKeycloakEventNumber {
		rawData, err := io.ReadAll(evt.Reader())
		if err != nil {
			fmt.Println(err.Error())
			return err
		}

		if err = json.Unmarshal(rawData, &msg); err != nil {
			return err
		}
		if err = json.Unmarshal(rawData, &userEvent); err != nil {
			p.logger.Println("error unmarshalling as user event", err)
		}
		if err = json.Unmarshal(rawData, &adminEvent); err != nil {
			p.logger.Println("error unmarshalling as admin event", err)
		}

		p.lastKeycloakEventMessage = msg
		p.lastKeycloakAdminEventMessage = adminEvent
		p.lastKeycloakUserEventMessage = userEvent
		p.lastKeycloakEventNumber = evt.EventNum()
	}

	switch req.Field() {
	case "keycloak.eventID":
		req.SetValue(msg.ID)
	case "keycloak.error":
		req.SetValue(msg.Error)
	case "keycloak.realmID":
		req.SetValue(msg.RealmID)

	case "keycloak.user.eventType":
		req.SetValue(userEvent.Type)
	case "keycloak.user.clientID":
		req.SetValue(userEvent.ClientID)
	case "keycloak.user.userID":
		req.SetValue(userEvent.UserID)
	case "keycloak.user.sessionID":
		req.SetValue(userEvent.SessionID)
	case "keycloak.user.ipAddress":
		ip := net.ParseIP(userEvent.IPAddress)
		if ip != nil {
			req.SetValue(ip)
		}
	case "keycloak.user.details":
		req.SetValue(userEvent.Details)

	case "keycloak.admin.authDetails.realmID":
		req.SetValue(adminEvent.AuthDetails.RealmID)
	case "keycloak.admin.authDetails.clientID":
		req.SetValue(adminEvent.AuthDetails.ClientID)
	case "keycloak.admin.authDetails.userID":
		req.SetValue(adminEvent.AuthDetails.UserID)
	case "keycloak.admin.authDetails.ipAddress":
		ip := net.ParseIP(adminEvent.AuthDetails.IPAddress)
		if ip != nil {
			req.SetValue(ip)
		}
	case "keycloak.admin.resourceType":
		req.SetValue(adminEvent.ResourceType)
	case "keycloak.admin.operationType":
		req.SetValue(adminEvent.OperationType)
	case "keycloak.admin.resourcePath":
		req.SetValue(adminEvent.ResourcePath)

	default:
		return fmt.Errorf("unknown field: %s", req.Field())
	}

	return nil
}
