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

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

// Extract allows Falco plugin framework to get values for all available fields
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	msg := p.lastKeycloakEventMessage
	var userEvent KeycloakAdminEvent
	var adminEvent KeycloakAdminEvent

	// For avoiding to Unmarshal the same message for each field to extract
	// we store it with its EventNum. When it's a new event with a new message, we
	// update the Plugin struct.
	if evt.EventNum() != p.lastKeycloakEventNumber {
		rawData, err := io.ReadAll(evt.Reader())
		if err != nil {
			fmt.Println(err.Error())
			return err
		}

		err = json.Unmarshal(rawData, &msg)
		if err != nil {
			return err
		}
		json.Unmarshal(rawData, &userEvent)
		json.Unmarshal(rawData, &adminEvent)

		p.lastKeycloakEventMessage = msg
		p.lastKeycloakEventNumber = evt.EventNum()
	}

	switch req.Field() {
	case "keycloak.eventID":
		req.SetValue(msg.ID)
	case "keycloak.error":
		req.SetValue(msg.Error)
	case "keycloak.realmID":
		req.SetValue(msg.RealmID)
	case "keycloak.admin.resourceType":
		req.SetValue(adminEvent.ResourceType)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}
