# OAuth 1.0a for Martini

Allows your Martini application to support user login via an OAuth 1.0a backend. Requires sessions middleware. 


## Usage

```go
package main

import (
	"github.com/go-martini/martini"
	"github.com/jonthornton/martini-contrib-oauth1/oauth"
	"github.com/martini-contrib/sessions"
)

func main() {
	m := martini.Classic()
	m.Use(sessions.Sessions("my_session", sessions.NewCookieStore([]byte("secret123"))))
	m.Use(oauth1.NewProvider(&oauth1.Options{
		AuthorizeURL:    "https://api.twitter.com/oauth/authorize",
		RequestTokenURL: "https://api.twitter.com/oauth/request_token",
		AccessTokenURL:  "https://api.twitter.com/oauth/access_token",
		ClientKey:       "client-key",
		ClientSecret:    "client-secret",
		BaseURI:         "http://yourapp.com",
	}))

	// An initialized OAuth client is injected into the handlers
	m.Get("/", func(oaTransport *oauth1.Transport) string {
		if !oaTransport.Valid() {
			return "not logged in"
		}
		return "logged in"
	})

	// Routes that require a logged in user can be protected with
	// the oauth1.LoginRequired handler. If the user is not
	// authenticated, they will be redirected to the login path.
	m.Get("/protected", oauth1.LoginRequired, func() string {
		return "super secret stuff"
	})

	m.Run()
}
```

If a route requires login, you can add `oauth1.LoginRequired` to the handler chain. If user is not logged, they will be automatically redirected to the login path.

```go
m.Get("/login-required", oauth1.LoginRequired, func() {...})
```

## Authenticated Requests

The OAuth1 middleware injects a `Transport` struct into route handlers that contains a [Go-OAuth](https://github.com/garyburd/go-oauth) client and tokens.

Use the `Valid()` method to check if the user has been authenticated:

```go
m.Get("/", func(oaTransport *oauth1.Transport) string {
	if oaTransport.Valid() {
		return "logged in"
	} else {
		return "not logged in"
	}
})
```

Use the GO-OAuth client to make authenticated requests. Refer to the [GO-OAuth project](https://github.com/garyburd/go-oauth) for client documentation.

```go
m.Get("/protected", oauth1.LoginRequired, func(oaTransport *oauth1.Transport) string {
	resp, err := oaTransport.Client.Get(http.DefaultClient, oaTransport.Token,
		"https://api.twitter.com/1.1/statuses/home_timeline.json", nil)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	respBytes, _ := ioutil.ReadAll(resp.Body)
	return string(respBytes)
})
```

## Auth flow

* `/login` will redirect user to the OAuth 1.0a provider's permissions dialog. If there is a `next` query param provided, the user will redirected to the URL specified by that param afterwards.
* If user agrees to connect, OAuth 1.0a provider will redirect to `/oauth-callback` to let your app to make the handshake. You need to register `/oauth-callback` as a Redirect URL in your application settings.
* `/logout` will log the user out. If there is a `next` query param provided, user is redirected to the next page afterwards.

You can customize the login, logout, oauth-callback and error paths, as well as the next URL query param key:

```go
oauth1.PathLogin = "/my-login"
oauth1.PathLogout = "/my-logout"
...
```

*Inspired by [martini-contrib/oauth2](https://github.com/martini-contrib/oauth2)*
