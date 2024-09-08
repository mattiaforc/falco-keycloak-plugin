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
	"log"
	"os"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
)

var (
	ID          uint32
	Name        string
	Description string
	Contact     string
	Version     string
	EventSource string
)

// Plugin represents our plugin
type Plugin struct {
	plugins.BasePlugin
	Config PluginConfig
	logger *log.Logger

	lastKeycloakEventMessage BaseKeycloakEvent // TODO: fix typing
	lastKeycloakEventNumber  uint64
}

// SetInfo is used to set the Info of the plugin
func (p *Plugin) SetInfo(id uint32, name, description, contact, version, eventSource string) {
	ID = id
	Name = name
	Contact = contact
	Version = version
	EventSource = eventSource
}

// Info displays information of the plugin to Falco plugin framework
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          ID,
		Name:        Name,
		Description: Description,
		Contact:     Contact,
		Version:     Version,
		EventSource: EventSource,
	}
}

// InitSchema map the configuration values with Plugin structure through JSONSchema tags
func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (p *Plugin) Init(config string) error {
	p.Config.setDefault()

	// setup internal logger
	p.logger = log.New(os.Stderr, "["+Name+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)

	return json.Unmarshal([]byte(config), &p.Config)
}

// String represents the raw value of on event
// (not currently used by Falco plugin framework, only there for future usage)
func (Plugin *Plugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := io.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)
	return fmt.Sprintf("%v", evtStr), nil
}
