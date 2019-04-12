# sso-auth-proxy

## About

sso-proxy will serve on address 0.0.0.0:9090 by default. IPv6 not supported.

## Usage example

```bash

# ***** 必须设置的 *****

# 门户的登录地址
export SSO_LOGIN_BASE_URL="http://10.1.235.171:12005/dmc/dev/module/login/login.html?goto="
# 门户的退出地址
export SSO_LOGOUT_BASE_URL="http://192.168.11.136:12001/sptl-sso/sso/logout?token="
# 门户的认证地址
export SSO_REDEEM_BASE_URL="http://10.1.235.171:12005/dmc/ssoAuth?token="
# 前端页面地址
export SSO_UPSTREAM_URL="localhost:18080"

# ***** 可选设置 *****

export SSO_LOGOUT_REDIRECT_URL="/"
export SSO_REDIRECT_URI="/app/#/console/project/%s/dashboard"
export SSO_PROXY_PREFIX="/sso/abc"

# 本服务的端口号
export SERVE_PORT="19090"
./sso-proxy
```

## TODO

* set flags by command line arguments
* uri whitelist support.
* ...