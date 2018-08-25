package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/zonesan/clog"
)

func setBaseURL(urlStr string) string {
	// Make sure the given URL end with no slash
	if strings.HasSuffix(urlStr, "/") {
		return setBaseURL(strings.TrimSuffix(urlStr, "/"))
	}
	return urlStr
}

func httpsAddr(addr string) string {
	if !strings.HasPrefix(strings.ToLower(addr), "http://") &&
		!strings.HasPrefix(strings.ToLower(addr), "https://") {
		return fmt.Sprintf("https://%s", addr)
	}

	return setBaseURL(addr)
}

func httpAddr(addr string) string {
	if !strings.HasPrefix(strings.ToLower(addr), "http://") &&
		!strings.HasPrefix(strings.ToLower(addr), "https://") {
		return fmt.Sprintf("http://%s", addr)
	}
	return setBaseURL(addr)
}

func makeAddr(addr string) string {
	if !strings.HasPrefix(strings.ToLower(addr), "https://") {
		return httpAddr(addr)
	}
	return httpsAddr(addr)
}

func makeAddrFromEnv(env string) string {
	addr := os.Getenv(env)
	if len(addr) == 0 {
		clog.Fatal(env, "must be specified.")
	}
	clog.Info(env, addr)
	return makeAddr(addr)
}

func makeAddrFromEnvOrDefault(env, value string) string {
	addr := os.Getenv(env)
	if len(addr) > 0 {
		clog.Info(env, addr)
		return makeAddr(addr)
	}
	clog.Warnf("%v is empty, using '%v' as default value.", env, value)
	return value
}

func envOrDefault(env, value string) string {
	val := os.Getenv(env)
	if len(val) > 0 {
		clog.Info(env, val)
		return val
	}
	clog.Warnf("%v is empty, using '%v' as default value.", env, value)
	return value
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// secretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func secretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}
