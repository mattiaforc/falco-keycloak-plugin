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

type PluginConfig struct {
	SSLCertificate string `json:"sslCertificate"       jsonschema:"title=SSL certificate,description=The SSL Certificate to be used with the HTTPS endpoint (Default: /etc/falco/falco.pem),default=/etc/falco/falco.pem"`
	SSLKey         string `json:"sslKey"       jsonschema:"title=SSL Key,description=The SSL Kwy to be used with the HTTPS endpoint (Default: /etc/falco/key.pem),default=/etc/falco/key.pem"`
}

// setDefault is used to set default values before mapping with InitSchema()
func (p *PluginConfig) setDefault() {
	p.SSLCertificate = "/etc/falco/falco.pem"
	p.SSLKey = "/etc/falco/key.pem"
}
