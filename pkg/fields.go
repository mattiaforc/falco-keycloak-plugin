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

import "github.com/falcosecurity/plugin-sdk-go/pkg/sdk"

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "keycloak.eventID", Desc: "The ID of the keycloak event."},
		{Type: "string", Name: "keycloak.error", Desc: "The event error, if any."},
		{Type: "string", Name: "keycloak.realmID", Desc: "The ID of the realm."},

		{Type: "string", Name: "keycloak.user.eventType", Desc: "The event type."},
		{Type: "string", Name: "keycloak.user.clientID", Desc: "The ID of the client."},
		{Type: "string", Name: "keycloak.user.userID", Desc: "The ID of the user."},
		{Type: "string", Name: "keycloak.user.sessionID", Desc: "The user session ID."},
		{Type: "ipaddr", Name: "keycloak.user.ipAddress", Desc: "The user IP address."},

		{Type: "string", Name: "keycloak.admin.authDetails.realmID", Desc: "The authentication realmID for this AdminEvent."},
		{Type: "string", Name: "keycloak.admin.authDetails.clientID", Desc: "The authentication clientID for this AdminEvent."},
		{Type: "string", Name: "keycloak.admin.authDetails.userID", Desc: "The authenticated userID that triggered this AdminEvent."},
		{Type: "ipaddr", Name: "keycloak.admin.authDetails.ipAddress", Desc: "The IP address of the user that triggered this AdminEvent."},
		{Type: "string", Name: "keycloak.admin.resourceType", Desc: "The resource the AdminEvent was triggered for."},
		{Type: "string", Name: "keycloak.admin.operationType", Desc: "The type of the AdminEvent operation."},
		{Type: "string", Name: "keycloak.admin.resourcePath", Desc: "The resource path for the AdminEvent."},
	}
}
