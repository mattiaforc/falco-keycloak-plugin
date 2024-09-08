package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	keycloak "github.com/mattiaforc/falco-keycloak-plugin/pkg"
)

const (
	PluginID          uint32 = 20
	PluginName               = "keycloak"
	PluginDescription        = "Keycloak User/Admin Events"
	PluginContact            = "github.com/mattiaforc/falco-keycloak-plugin"
	PluginVersion            = "0.1.0"
	PluginEventSource        = "keycloak"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &keycloak.Plugin{}
		p.SetInfo(
			PluginID,
			PluginName,
			PluginDescription,
			PluginContact,
			PluginVersion,
			PluginEventSource,
		)
		extractor.Register(p)
		source.Register(p)
		return p
	})
}

func main() {}
