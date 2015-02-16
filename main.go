package googleauth

import (
	"code.google.com/p/goauth2/oauth"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang/oauth2"
	"github.com/golang/oauth2/google"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Update your Google API project information here.
//"https://www.googleapis.com/auth/plus.login"
var (
	CLIENT_ID     = os.Getenv("GOOGLE_CLIENT_ID")
	CLIENT_SECRET = os.Getenv("GOOGLE_CLIENT_SECRET")
	SCOPE         = os.Getenv("GOOGLE_SCOPE")
	REDIRECT      = "http://localhost:3000/google-auth-callback"
)

// config is the configuration specification supplied to the OAuth package.
var config = &oauth.Config{
	ClientId:     CLIENT_ID,
	ClientSecret: CLIENT_SECRET,
	// Scope determines which API calls you are authorized to make
	Scope:    "https://www.googleapis.com/auth/plus.login",
	AuthURL:  "https://accounts.google.com/o/oauth2/auth",
	TokenURL: "https://accounts.google.com/o/oauth2/token",
	// Use "postmessage" for the code-flow for server side apps
	RedirectURL: "http://localhost:3000/google-auth-callback",
}

// store initializes the Gorilla session store.
var store = sessions.NewCookieStore([]byte(randomString(32)))

// Token represents an OAuth token response.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

// ClaimSet represents an IdToken response.
type ClaimSet struct {
	Sub string
}

// exchange takes an authentication code and exchanges it with the OAuth
// endpoint for a Google API bearer token and a Google+ ID
func Exchange(code string) (accessToken string, idToken string, err error) {
	// Exchange the authorization code for a credentials object via a POST request
	addr := "https://accounts.google.com/o/oauth2/token"
	values := url.Values{
		"Content-Type":  {"application/x-www-form-urlencoded"},
		"code":          {code},
		"client_id":     {CLIENT_ID},
		"client_secret": {CLIENT_SECRET},
		"redirect_uri":  {config.RedirectURL},
		"grant_type":    {"authorization_code"},
	}

	// fmt.Printf("Values: %v", values)
	resp, err := http.PostForm(addr, values)
	if err != nil {
		return "", "", fmt.Errorf("Exchanging code: %v", err)
	}
	defer resp.Body.Close()

	// Decode the response body into a token object
	var token Token
	err = json.NewDecoder(resp.Body).Decode(&token)
	defer resp.Body.Close()

	if err != nil {
		return "", "", fmt.Errorf("Decoding access token: %v", err)
	} else {

		//		fmt.Printf("Body: %s \n %s", token.AccessToken, token.IdToken)

		return token.AccessToken, token.IdToken, nil
	}

}

// decodeIdToken takes an ID Token and decodes it to fetch the Google+ ID within
func DecodeIdToken(idToken string) (gplusID string, err error) {
	// An ID token is a cryptographically-signed JSON object encoded in base 64.
	// Normally, it is critical that you validate an ID token before you use it,
	// but since you are communicating directly with Google over an
	// intermediary-free HTTPS channel and using your Client Secret to
	// authenticate yourself to Google, you can be confident that the token you
	// receive really comes from Google and is valid. If your server passes the ID
	// token to other components of your app, it is extremely important that the
	// other components validate the token before using it.
	var set ClaimSet
	if idToken != "" {
		// Check that the padding is correct for a base64decode
		parts := strings.Split(idToken, ".")
		if len(parts) < 2 {
			return "", fmt.Errorf("Malformed ID token")
		}
		// Decode the ID token
		b, err := base64Decode(parts[1])
		if err != nil {
			return "", fmt.Errorf("Malformed ID token: %v", err)
		}
		err = json.Unmarshal(b, &set)
		if err != nil {
			return "", fmt.Errorf("Malformed ID token: %v", err)
		}
	}
	return set.Sub, nil
}

// appHandler is to be used in error handling
type appHandler func(http.ResponseWriter, *http.Request) *appError

type appError struct {
	Err     error
	Message string
	Code    int
}

// serveHTTP formats and passes up an error
func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil { // e is *appError, not os.Error.
		log.Println(e.Err)
		http.Error(w, e.Message, e.Code)
	}
}

// randomString returns a random string with the specified length
func randomString(length int) (str string) {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func base64Decode(s string) ([]byte, error) {
	// add back missing padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// go https://console.developers.google.com/project
// returns url string
func GetGoogleAuthUrl() string {
	//Auth
	f, err := oauth2.New(
		oauth2.Client(CLIENT_ID, CLIENT_SECRET),
		oauth2.RedirectURL(REDIRECT),
		oauth2.Scope("https://www.googleapis.com/auth/plus.login"),
		google.Endpoint(),
	)
	if err != nil {
		log.Fatal(err)
	}
	url := f.AuthCodeURL("state", "online", "auto")

	return url
}
