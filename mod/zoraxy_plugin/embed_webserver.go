package zoraxy_plugin

import (
	"embed"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// PluginUiRouter serves embedded static files for a Zoraxy plugin UI.
type PluginUiRouter struct {
	PluginID         string
	TargetFs         *embed.FS
	TargetFsPrefix   string
	HandlerPrefix    string
	EnableDebug      bool
	terminateHandler func()
}

// NewPluginEmbedUIRouter creates a UI router for embedded static files.
func NewPluginEmbedUIRouter(pluginID string, targetFs *embed.FS, targetFsPrefix string, handlerPrefix string) *PluginUiRouter {
	if !strings.HasPrefix(targetFsPrefix, "/") {
		targetFsPrefix = "/" + targetFsPrefix
	}
	targetFsPrefix = strings.TrimSuffix(targetFsPrefix, "/")

	if !strings.HasPrefix(handlerPrefix, "/") {
		handlerPrefix = "/" + handlerPrefix
	}
	handlerPrefix = strings.TrimSuffix(handlerPrefix, "/")

	return &PluginUiRouter{
		PluginID:       pluginID,
		TargetFs:       targetFs,
		TargetFsPrefix: targetFsPrefix,
		HandlerPrefix:  handlerPrefix,
	}
}

func (p *PluginUiRouter) populateCSRFToken(r *http.Request, fsHandler http.Handler) http.Handler {
	csrfToken := escapeCSRFToken(r.Header.Get("X-Zoraxy-Csrf"))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".html") {
			targetFilePath := strings.TrimPrefix(r.URL.Path, "/")
			targetFilePath = p.TargetFsPrefix + "/" + targetFilePath
			targetFilePath = strings.TrimPrefix(targetFilePath, "/")
			content, err := fs.ReadFile(*p.TargetFs, targetFilePath)
			if err != nil {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			body := strings.ReplaceAll(string(content), "{{.csrfToken}}", csrfToken)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(body))
			return
		} else if strings.HasSuffix(r.URL.Path, "/") {
			indexFilePath := strings.TrimPrefix(r.URL.Path, "/") + "index.html"
			indexFilePath = p.TargetFsPrefix + "/" + indexFilePath
			indexFilePath = strings.TrimPrefix(indexFilePath, "/")
			content, err := fs.ReadFile(*p.TargetFs, indexFilePath)
			if err == nil {
				body := strings.ReplaceAll(string(content), "{{.csrfToken}}", csrfToken)
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(body))
				return
			}
		}
		fsHandler.ServeHTTP(w, r)
	})
}

func escapeCSRFToken(token string) string {
	if token == "" {
		token = "missing-csrf-token"
	}
	return html.EscapeString(token)
}

// Handler returns the http.Handler for the plugin UI.
func (p *PluginUiRouter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.EnableDebug {
			fmt.Print("Request URL:", r.URL.Path, " rewriting to ")
		}

		rewrittenURL := r.RequestURI
		rewrittenURL = strings.TrimPrefix(rewrittenURL, p.HandlerPrefix)
		rewrittenURL = strings.ReplaceAll(rewrittenURL, "//", "/")
		r.URL, _ = url.Parse(rewrittenURL)
		r.RequestURI = rewrittenURL

		if p.EnableDebug {
			fmt.Println(r.URL.Path)
		}

		subFS, err := fs.Sub(*p.TargetFs, strings.TrimPrefix(p.TargetFsPrefix, "/"))
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		p.populateCSRFToken(r, http.FileServer(http.FS(subFS))).ServeHTTP(w, r)
	})
}

// RegisterTerminateHandler registers the /term endpoint for graceful shutdown.
func (p *PluginUiRouter) RegisterTerminateHandler(termFunc func(), mux *http.ServeMux) {
	p.terminateHandler = termFunc
	if mux == nil {
		mux = http.DefaultServeMux
	}
	mux.HandleFunc(p.HandlerPrefix+"/term", func(w http.ResponseWriter, r *http.Request) {
		p.terminateHandler()
		w.WriteHeader(http.StatusOK)
		go func() {
			time.Sleep(100 * time.Millisecond)
			os.Exit(0)
		}()
	})
}

// HandleFunc registers a handler under the UI prefix.
func (p *PluginUiRouter) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	if !strings.HasPrefix(pattern, p.HandlerPrefix) {
		pattern = p.HandlerPrefix + pattern
	}
	mux.HandleFunc(pattern, handler)
}

// AttachHandlerToMux attaches the UI handler to a mux.
func (p *PluginUiRouter) AttachHandlerToMux(mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	p.HandlerPrefix = strings.TrimSuffix(p.HandlerPrefix, "/")
	mux.Handle(p.HandlerPrefix+"/", p.Handler())
}
