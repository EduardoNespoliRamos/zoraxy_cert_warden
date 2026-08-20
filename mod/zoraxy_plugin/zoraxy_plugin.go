package zoraxy_plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PluginType defines the kind of plugin.
type PluginType int

const (
	PluginType_Router    PluginType = 0
	PluginType_Utilities PluginType = 1
)

// StaticCaptureRule defines a static traffic capture rule.
type StaticCaptureRule struct {
	CapturePath string `json:"capture_path"`
}

// ControlStatusCode is returned by router plugins to indicate handling.
type ControlStatusCode int

const (
	ControlStatusCode_CAPTURED  ControlStatusCode = 280
	ControlStatusCode_UNHANDLED ControlStatusCode = 284
	ControlStatusCode_ERROR     ControlStatusCode = 580
)

// SubscriptionEvent represents a Zoraxy event forwarded to the plugin.
type SubscriptionEvent struct {
	EventName   string `json:"event_name"`
	EventSource string `json:"event_source"`
	Payload     string `json:"payload"`
}

// RuntimeConstantValue contains runtime constants passed by Zoraxy.
type RuntimeConstantValue struct {
	ZoraxyVersion    string `json:"zoraxy_version"`
	ZoraxyUUID       string `json:"zoraxy_uuid"`
	DevelopmentBuild bool   `json:"development_build"`
}

// PermittedAPIEndpoint describes an API endpoint the plugin may call.
type PermittedAPIEndpoint struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason"`
}

// IntroSpect is the metadata returned by -introspect.
type IntroSpect struct {
	ID                    string                 `json:"id"`
	Name                  string                 `json:"name"`
	Author                string                 `json:"author"`
	AuthorContact         string                 `json:"author_contact"`
	Description           string                 `json:"description"`
	URL                   string                 `json:"url"`
	Type                  PluginType             `json:"type"`
	VersionMajor          int                    `json:"version_major"`
	VersionMinor          int                    `json:"version_minor"`
	VersionPatch          int                    `json:"version_patch"`
	StaticCapturePaths    []StaticCaptureRule    `json:"static_capture_paths"`
	StaticCaptureIngress  string                 `json:"static_capture_ingress"`
	DynamicCaptureSniff   string                 `json:"dynamic_capture_sniff"`
	DynamicCaptureIngress string                 `json:"dynamic_capture_ingress"`
	UIPath                string                 `json:"ui_path"`
	SubscriptionPath      string                 `json:"subscription_path"`
	SubscriptionsEvents   map[string]string      `json:"subscriptions_events"`
	PermittedAPIEndpoints []PermittedAPIEndpoint `json:"permitted_api_endpoints"`
}

// ServeIntroSpect prints the introspect JSON and exits if -introspect is provided.
func ServeIntroSpect(pluginSpect *IntroSpect) {
	if len(os.Args) > 1 && os.Args[1] == "-introspect" {
		jsonData, _ := json.MarshalIndent(pluginSpect, "", "  ")
		fmt.Println(string(jsonData))
		os.Exit(0)
	}
}

// ConfigureSpec is passed by Zoraxy when starting the plugin.
type ConfigureSpec struct {
	Port         int                  `json:"port"`
	RuntimeConst RuntimeConstantValue `json:"runtime_const"`
	APIKey       string               `json:"api_key,omitempty"`
	ZoraxyPort   int                  `json:"zoraxy_port,omitempty"`
}

// RecvConfigureSpec parses the -configure argument.
func RecvConfigureSpec() (*ConfigureSpec, error) {
	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "-configure=") {
			var configSpec ConfigureSpec
			if err := json.Unmarshal([]byte(arg[11:]), &configSpec); err != nil {
				return nil, err
			}
			return &configSpec, nil
		} else if arg == "-configure" {
			var configSpec ConfigureSpec
			if len(os.Args) > i+1 {
				if err := json.Unmarshal([]byte(os.Args[i+1]), &configSpec); err != nil {
					return nil, err
				}
			} else {
				return nil, fmt.Errorf("no port specified after -configure flag")
			}
			return &configSpec, nil
		}
	}
	return nil, fmt.Errorf("no -configure flag found")
}

// ServeAndRecvSpec runs ServeIntroSpect and returns the configure spec.
func ServeAndRecvSpec(pluginSpect *IntroSpect) (*ConfigureSpec, error) {
	ServeIntroSpect(pluginSpect)
	return RecvConfigureSpec()
}
