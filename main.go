package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/zonesan/clog"
)

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	clog.Debug("from", r.RemoteAddr, r.Method, r.URL.RequestURI(), r.Proto)
	ssoproxy.ServeHTTP(w, r)
}

func debugSwitch(w http.ResponseWriter, r *http.Request) {
	switch method := r.Method; {
	case "DELETE" == method:
		clog.SetLogLevel(clog.LOG_LEVEL_INFO)
		clog.Info("DEBUG MODE DISABLED")
		fmt.Fprintf(w, "DEBUG MODE DISABLED")
	case "PUT" == method:
		clog.SetLogLevel(clog.LOG_LEVEL_DEBUG)
		clog.Debug("DEBUG MODE ENABLED")
		fmt.Fprintf(w, "DEBUG MODE ENABLED")
	default:
		fmt.Fprintf(w, "debug level: %s", clog.GetLogLevelText())
	}
}

var ssoproxy *SsoProxy
var loginBaseURL, logoutBaseURL, redeemBaseURL, logoutRedirectURL string
var lqMgr LogoutQueueManager

func main() {

	router := mux.NewRouter()

	// router.HandleFunc(`/api/{r:.*}`, ssoHandler)
	// router.HandleFunc(`/oapi/{r:.*}`, ssoHandler)
	// router.HandleFunc(`/apis/{r:.*}`, ssoHandler)
	// router.HandleFunc(`/ws/{r:.*}`, ssoHandler)
	// router.HandleFunc(`/{r:.*}`, ssoproxy.ServeHTTP)

	router.HandleFunc(`/{r:.*}`, ssoHandler)
	router.HandleFunc("/debug", debugSwitch)

	http.HandleFunc("/", ssoHandler)
	http.HandleFunc("/debug", debugSwitch)
	_ = router

	port := envOrDefault("SERVE_PORT", "9090")

	clog.Info("listening on port", port)
	clog.Fatal(http.ListenAndServe(":"+port, nil))
}

func init() {
	clog.Info("starting sso-proxy, VERSION:", version)

	loginBaseURL = makeAddrFromEnv("SSO_LOGIN_BASE_URL")
	logoutBaseURL = makeAddrFromEnv("SSO_LOGOUT_BASE_URL")
	redeemBaseURL = makeAddrFromEnv("SSO_REDEEM_BASE_URL")
	upstream := makeAddrFromEnv("SSO_UPSTREAM_URL")
	logoutRedirectURL = envOrDefault("SSO_LOGOUT_REDIRECT_URL", "/")
	ssoproxy = NewSsoProxy(upstream)

	clog.SetLogLevel(clog.LOG_LEVEL_INFO)
	clog.Info("Upstream target:", upstream)
	lqMgr = NewLogoutQueue()
}
