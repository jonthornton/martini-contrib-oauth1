// Copyright 2014 Jon Thornton. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package oauth1 provides a Martini middleware to facilitate user login
// via an OAuth 1.0a backend.
package oauth1

import (
	"encoding/json"
	"errors"
	"github.com/garyburd/go-oauth/oauth"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/sessions"
	"log"
	"net/http"
	"net/url"
)

const (
	codeRedirect = 302
	keyToken     = "oauth1_access_token"
	keyTempToken = "oauth1_temp_token"
	KeyNextURL   = "next"
	PathLogin    = "/login"
	PathLogout   = "/logout"
	PathCallback = "/oauth-callback"
	PathError    = "/oauth-error"
)

type Options struct {
	ClientKey       string
	ClientSecret    string
	RequestTokenURL string
	AuthorizeURL    string
	AccessTokenURL  string
	BaseURI         string
}

type Transport struct {
	Client  oauth.Client
	Token   *oauth.Credentials
	BaseURI string
}

func (this *Transport) Valid() bool {
	return credentialsAreValid(this.Token)
}

func (this *Transport) Invalidate(s sessions.Session) {
	s.Delete(keyToken)
	this.Token = &oauth.Credentials{}
}

func credentialsAreValid(c *oauth.Credentials) bool {
	return c != nil && c.Token != "" && c.Secret != ""
}

func marshalCredentials(c *oauth.Credentials, s sessions.Session, key string) {
	val, _ := json.Marshal(c)
	s.Set(key, val)
}

func unmarshalCredentials(s sessions.Session, key string) (*oauth.Credentials, error) {
	if s.Get(key) == nil {
		return nil, errors.New("No stored credentials.")
	}
	data := s.Get(key).([]byte)
	var c oauth.Credentials
	json.Unmarshal(data, &c)
	return &c, nil
}

/*
oauth1.NewProvider is used to attach the oauth1 middleware.
Sample usage:
	m := martini.Classic()
	m.Use(oauth1.NewProvider(&oauth1.Options{
		AuthorizeURL:    "https://api.twitter.com/oauth/authorize",
		RequestTokenURL: "https://api.twitter.com/oauth/request_token",
		AccessTokenURL:  "https://api.twitter.com/oauth/access_token",
		ClientKey:       "your-apps-oauth-api-key",
		ClientSecret:    "your-apps-oauth-api-secret",
		BaseURI:         "http://yourapp.com",
	}))
*/
func NewProvider(opts *Options) martini.Handler {

	var baseClient = oauth.Client{
		TemporaryCredentialRequestURI: opts.RequestTokenURL,
		ResourceOwnerAuthorizationURI: opts.AuthorizeURL,
		TokenRequestURI:               opts.AccessTokenURL,
		Credentials: oauth.Credentials{
			Token:  opts.ClientKey,
			Secret: opts.ClientSecret,
		},
	}

	return func(s sessions.Session, c martini.Context, w http.ResponseWriter, r *http.Request) {
		token, _ := unmarshalCredentials(s, keyToken)
		client := Transport{
			Client:  baseClient,
			Token:   token,
			BaseURI: opts.BaseURI,
		}

		if r.Method == "GET" {
			switch r.URL.Path {
			case PathLogin:
				login(&client, s, w, r)
			case PathLogout:
				logout(&client, s, w, r)
			case PathCallback:
				handleOAuthCallback(&baseClient, s, w, r)
			}
		}
		c.Map(&client)
	}
}

// Attach the LoginRequired handler to route and it will redirect a user
// to the login page if the user is not logged in.
// Sample usage:
// m.Get("/login-required", oauth1.LoginRequired, func() {...})
var LoginRequired martini.Handler = func() martini.Handler {
	return func(s sessions.Session, c martini.Context, w http.ResponseWriter, r *http.Request) {

		_, err := unmarshalCredentials(s, keyToken)
		if err != nil {
			params := url.Values{}
			params.Add(KeyNextURL, r.URL.RequestURI())
			http.Redirect(w, r, PathLogin+"?"+params.Encode(), codeRedirect)
		}
	}
}()

func login(oaTransport *Transport, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	nextURL := getNextURL(r)

	if oaTransport.Valid() {
		// No need to login, redirect to the next page.
		http.Redirect(w, r, nextURL, codeRedirect)
	}

	params := url.Values{}
	params.Add(KeyNextURL, nextURL)
	callbackURL := oaTransport.BaseURI + PathCallback + "?" + params.Encode()
	tempToken, err := oaTransport.Client.RequestTemporaryCredentials(http.DefaultClient, callbackURL, nil)
	if err != nil {
		log.Fatal("RequestTemporaryCredentials:", err)
	}

	marshalCredentials(tempToken, s, keyTempToken)
	authUrl := oaTransport.Client.AuthorizationURL(tempToken, nil)
	http.Redirect(w, r, authUrl, codeRedirect)
}

func logout(oaTransport *Transport, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	nextURL := getNextURL(r)
	oaTransport.Invalidate(s)
	http.Redirect(w, r, nextURL, codeRedirect)
}

func handleOAuthCallback(oauthClient *oauth.Client, s sessions.Session, w http.ResponseWriter, r *http.Request) {
	nextURL := getNextURL(r)

	tempToken, err := unmarshalCredentials(s, keyTempToken)
	if err != nil {
		// missing temp token
		params := url.Values{}
		params.Add(KeyNextURL, nextURL)
		http.Redirect(w, r, PathLogin+"?"+params.Encode(), codeRedirect)
		return
	}

	if tempToken.Token != r.FormValue("oauth_token") {
		// TODO: add error handling
		log.Fatal("oauth token mismatch")
	}

	token, _, err := oauthClient.RequestToken(http.DefaultClient, tempToken, r.FormValue("oauth_verifier"))
	if err != nil {
		// TODO: add error handling
		log.Fatal("oauth-callback error:", err)
		// http.Redirect(w, r, PathError, codeRedirect)
		return
	}

	// Store the credentials in the session.
	marshalCredentials(token, s, keyToken)
	http.Redirect(w, r, nextURL, codeRedirect)
}

func getNextURL(r *http.Request) string {
	rawURL := r.URL.Query().Get(KeyNextURL)
	n, err := url.Parse(rawURL)
	if err != nil {
		return "/"
	}
	return n.Path
}
