goth
====

Go OAuth 1.0a 2 legs provider with oauth_body_hash support.  

Just provide a function conforms to `OAuthCheckerFunc` Goth will authenticate your requests.  

You can get the userId return by your auth function inside the handler at `r.URL.User.Username()`.

To enable oauth_body_hash check set `WithBodyHash` to true.

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/akhenakh/goth"
)

func myAuthFunc(consumerKey string) (userId string, consumerSecret string) {
	if consumerKey == "ckey" {
		return "myusername", "csecret"
	}
	return "", ""
}

func helloFunc(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello "+r.URL.User.Username())
}

func main() {
	o := goth.OAuth1{CheckerFunc: myAuthFunc}
	myHandler := http.HandlerFunc(helloFunc)
	http.ListenAndServe(":3000", o.AuthProtect(myHandler))
}
```
