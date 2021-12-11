package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"golang.org/x/crypto/acme/autocert"
)

var ShowErrorPage bool

type Route struct {
	URL          string `json:"URL"`
	HttpPort     string `json:"http"`
	HttpsPort    string `json:"https"`
	HttpsUpgrade bool   `json:"upgrade"`
}

type ReRoute struct {
	BaseURL string
	Proxy   *httputil.ReverseProxy
	Upgrade bool
}

type ReRouteMin struct {
	Proxy   *httputil.ReverseProxy
	Upgrade bool
}

func main() {
	ShowErrorPage = true
	//os.ReadFile("settings.json")
	f, err := os.Open("settings.json")
	if err != nil {
		fmt.Println("Could not open settings.json")
		panic(err)
	}

	var routes []Route
	decoder := json.NewDecoder(f)
	decoder.Decode(&routes)

	whiteListedURLs := make([]string, len(routes))
	httpRoutes := make([]ReRoute, len(routes))
	httpsRoutes := make([]ReRoute, len(routes))
	for x := range routes {
		urlhttp, err := url.Parse("http://127.0.0.1" /* + routes[x].URL */ + routes[x].HttpPort)
		if err != nil {
			fmt.Println("Trouble parsing http url")
			panic(err)
		}
		urlhttps, err := url.Parse("http://127.0.0.1" /* + routes[x].URL */ + routes[x].HttpsPort)
		if err != nil {
			fmt.Println("Trouble parsing https url")
			panic(err)
		}
		httpProx := httputil.NewSingleHostReverseProxy(urlhttp)
		httpsProx := httputil.NewSingleHostReverseProxy(urlhttps)
		httpRoutes[x] = ReRoute{BaseURL: routes[x].URL, Proxy: httpProx, Upgrade: routes[x].HttpsUpgrade}
		httpsRoutes[x] = ReRoute{BaseURL: routes[x].URL, Proxy: httpsProx}

		whiteListedURLs[x] = routes[x].URL
	}

	dir := "./cert"
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(whiteListedURLs...),
		Cache:      autocert.DirCache(dir),
		Email: "alexander.andrews@incompany.io",
		
	}

	//go http.ListenAndServe(http.HandlerFunc(certManager.HTTPHandler(nil)))
	httpserver := &http.Server{
		Addr:    ":80",
		Handler: certManager.HTTPHandler(http.HandlerFunc(CreateProxyHandler(httpRoutes, false))),
	}
	httpsserver := &http.Server{
		Addr:    ":443",
		Handler: http.HandlerFunc(CreateProxyHandler(httpsRoutes, true)),
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	errorChan := make(chan error)
	//httputil.New
	go runServer(httpserver, false, errorChan)
	go runServer(httpsserver, true, errorChan)
	//fmt.Println(<-errorChan)
	for x := range errorChan{
		_ = x
		//fmt.Println(x)
	}
}

func runServer(server *http.Server, isHttps bool, errChan chan error) {
	if isHttps {
		errChan <- server.ListenAndServeTLS("", "")
	} else { //Pretty sure this else is not needed
		errChan <- server.ListenAndServe()
	}

}

func CreateProxyHandler(routes []ReRoute, isHttps bool) func(w http.ResponseWriter, r *http.Request) {
	mappedRoutes := make(map[string]ReRouteMin)
	for x := range routes {
		temp := ReRouteMin{}
		temp.Proxy = routes[x].Proxy
		if !isHttps {
			temp.Upgrade = routes[x].Upgrade
		}
		mappedRoutes[routes[x].BaseURL] = temp
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := mappedRoutes[r.Host]; ok {
			if mappedRoutes[r.Host].Upgrade {
				//Code taken from autocert package
				if r.Method != "GET" && r.Method != "HEAD" {
					http.Error(w, "Use HTTPS", http.StatusBadRequest)
					return
				}
				target := "https://" + stripPort(r.Host) + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			mappedRoutes[r.Host].Proxy.ServeHTTP(w, r)
			return
		}
		if ShowErrorPage{
			type ErrorPage struct{
				Error string `json:"error"`
				Note string `json:"note"`
			}
			info := ErrorPage{}
			info.Error = "Page Not Found"
			info.Note = fmt.Sprintf("%s was not found. Please contact admin. \n", r.Host)
			b, err :=json.Marshal(info)
			if err != nil{
				fmt.Println("Failed to marshall our struct that says that a unknown hos was targeted")
			}
			w.Write(b)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return net.JoinHostPort(host, "443")
}
