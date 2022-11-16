package traefik_real_ip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const (
	xRealIP       = "X-Real-Ip"
	xForwardedFor = "X-Forwarded-For"
)

type Proxy struct {
	ProxyHeadername  string `yaml:"proxyHeadername"`
	ProxyHeadervalue string `yaml:"proxyHeadervalue"`
	RealIP           string `yaml:"realIP"`
	OverwriteXFF     bool   `yaml:"overwriteXFF"` // override X-Forwarded-For
}

// Config the plugin configuration.
type Config struct {
	Proxy       []Proxy  `yaml:"proxy"`
	SourceRange []string `yaml:"sourceRange,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// GetRealIP Define plugin
type GetRealIP struct {
	next        http.Handler
	name        string
	proxy       []Proxy
	allowLister *Checker
}

// New creates and returns a new realip plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("All Config: '%v'\n", config)

	var err error
	var checker *Checker

	if len(config.SourceRange) > 0 {
		checker, err = NewChecker(config.SourceRange)
		if err != nil {
			return nil, fmt.Errorf("Cannot parse CIDRs %s: %w \n", config.SourceRange, err)
		}
	}

	return &GetRealIP{
		next:        next,
		name:        name,
		proxy:       config.Proxy,
		allowLister: checker,
	}, nil
}

func (g *GetRealIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var realIP string
	for _, proxy := range g.proxy {
		if req.Header.Get(proxy.ProxyHeadername) == "*" || (req.Header.Get(proxy.ProxyHeadername) == proxy.ProxyHeadervalue) {
			nIP := req.Header.Get(proxy.RealIP)
			if proxy.RealIP == "RemoteAddr" {
				nIP, _, _ = net.SplitHostPort(req.RemoteAddr)
			}

			forwardedIPs := strings.Split(nIP, ",")
			for i := 0; i <= len(forwardedIPs)-1; i++ {
				trimmedIP := strings.TrimSpace(forwardedIPs[i])
				excluded := g.excludedIP(trimmedIP)
				if !excluded {
					realIP = trimmedIP
					break
				}
			}
		}

		if realIP != "" {
			if proxy.OverwriteXFF {
				fmt.Println("Modify XFF to:", realIP)
				req.Header.Set(xForwardedFor, realIP)
			}
			req.Header.Set(xRealIP, realIP)
			break
		}
	}

	if realIP != "" && g.allowLister != nil {
		err := g.allowLister.IsAuthorized(realIP)
		if err != nil {
			fmt.Println("Rejecting IP:", realIP, ", Error: ", err)
			reject(rw)
			return
		}
		fmt.Println("Accepting IP:", realIP)
	}
	g.next.ServeHTTP(rw, req)
}

func (g *GetRealIP) excludedIP(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil
}

func reject(rw http.ResponseWriter) {
	statusCode := http.StatusForbidden

	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		fmt.Println("Failed to send reject: ", err.Error())
	}
}
