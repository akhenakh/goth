package goth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	// DefaultDeniedHandler handles the requests that were denied access because
	// of OAuth1. By default, returns a 401 status code with a generic message.
	DefaultDeniedHandler = http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", 401)
	}))
)

type OAuth1 struct {
	// A function that return the consumer secret and the username of the associated consumer key
	CheckerFunc OAuthCheckerFunc

	// DeniedHandler is called if the request is unauthorized. If it is nil,
	// the DefaultDeniedHandler variable is used.
	DeniedHandler http.Handler

	// WithBodyHash will check for the optionnal oauth_body_hash, default to no
	// see http://oauth.googlecode.com/svn'/spec/ext/body_hash/1.0/drafts/4/spec.html
	WithBodyHash bool
}

type OAuthCheckerFunc func(consumerKey string) (userId string, consumerSecret string)

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

func splitAuthHeader(oAuthHeader string) map[string]string {
	// test it starts with OAuth
	if !strings.HasPrefix(oAuthHeader, "OAuth ") {
		return nil
	}
	m := make(map[string]string)
	// split the values by comma
	splitted := strings.Split(oAuthHeader[5:], ",")
	for _, oauthField := range splitted {
		oauthField := strings.TrimSpace(oauthField)

		// check this is a real oauth field
		if !strings.HasPrefix(oauthField, "oauth_") {
			continue
		}

		splittedField := strings.Split(oauthField, "=")
		if len(splittedField) < 2 {
			continue
		}
		key := splittedField[0]
		val := splittedField[1]

		// ensure val is surrounded by ""
		if !strings.HasPrefix(val, "\"") || !strings.HasSuffix(val, "\"") {
			continue
		}
		val = val[1 : len(val)-1]
		// url unescape
		m[key], _ = url.QueryUnescape(val)
	}
	return m
}

func signatureBase(r *http.Request, oAuthHeaders map[string]string) string {
	// we sort the oauth params alphabetically then normalize it
	orderedParams := make([]string, len(oAuthHeaders))
	var i int
	for k, _ := range oAuthHeaders {
		orderedParams[i] = k
		i++
	}

	sort.Strings(orderedParams)

	stringParams := make([]string, 0)
	for _, param := range orderedParams {
		// remove the oauth_signature
		if param == "oauth_signature" {
			continue
		}
		stringParams = append(stringParams, param+"="+oAuthHeaders[param])
	}

	normalizedParams := strings.Join(stringParams, "&")
	sign := fmt.Sprintf("%s&%s&%s",
		r.Method,
		// TODO: find real scheme
		url.QueryEscape("http://"+r.Host+r.URL.String()),
		url.QueryEscape(normalizedParams))
	return sign
}

// checkRequest is checking the request is OAuth 1.0a valid and check the body_hash
// return the oauth_consumer_key
func checkRequest(r *http.Request, checkBodyHash bool) (consumerKey string, body string, oAuthHeaders map[string]string) {
	// test we have a header Authorization
	if _, ok := r.Header["Authorization"]; !ok {
		return
	}
	oAuthHeaders = splitAuthHeader(r.Header.Get("Authorization"))

	// test for the most needed oauth_ entries
	if _, ok := oAuthHeaders["oauth_consumer_key"]; !ok {
		return
	}
	if _, ok := oAuthHeaders["oauth_timestamp"]; !ok {
		return
	}
	if _, ok := oAuthHeaders["oauth_signature"]; !ok {
		return
	}

	// check for timestamp
	timestamp, err := strconv.Atoi(oAuthHeaders["oauth_timestamp"])
	if err != (nil) {
		return
	}

	diff := int(time.Now().Unix()) - timestamp
	// stupid Abs for int
	if diff < 0 {
		diff = -diff
	}
	// if request is older than 120s
	if diff > 120 {
		return
	}

	// if the method is not GET and the content type is not url encoded
	// we have to check for oauth_body_hash
	if checkBodyHash && r.Method != "GET" && r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		if _, ok := oAuthHeaders["oauth_body_hash"]; !ok {
			return
		}
		hasher := sha1.New()

		// we need to read the body for oauth_body_hash to be calculated
		// but then restore it later for the others middleware to read it
		bodydata, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return
		}
		hasher.Write(bodydata)
		bodySign := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

		body = string(bodydata[:])
		if bodySign != oAuthHeaders["oauth_body_hash"] {
			return
		}
		// escape body hash for later signature regeneration
		oAuthHeaders["oauth_body_hash"] = url.QueryEscape(oAuthHeaders["oauth_body_hash"])
	}
	consumerKey = oAuthHeaders["oauth_consumer_key"]
	return
}

func (o *OAuth1) AuthProtect(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if consumerKey, body, oAuthHeaders := checkRequest(r, o.WithBodyHash); consumerKey != "" {
			// generate base signature string
			sign := signatureBase(r, oAuthHeaders)
			user, consumerSecret := o.CheckerFunc(consumerKey)
			if consumerSecret != "" {
				// in 3 legs should have consumer_key&secret_key
				// in 2 legs only one but keep &
				hashfun := hmac.New(sha1.New, []byte(consumerSecret+"&"))
				hashfun.Write([]byte(sign))
				rawsignature := hashfun.Sum(nil)
				base64signature := make([]byte, base64.StdEncoding.EncodedLen(len(rawsignature)))
				base64.StdEncoding.Encode(base64signature, rawsignature)
				sign = string(base64signature)

				if sign == oAuthHeaders["oauth_signature"] {
					r.Body = nopCloser{bytes.NewBufferString(body)}
					r.URL.User = url.UserPassword(user, "")
					h.ServeHTTP(w, r)
					return
				}
			}
		}
		dh := o.DeniedHandler
		if dh == nil {
			dh = DefaultDeniedHandler
		}
		dh.ServeHTTP(w, r)
	})
}
