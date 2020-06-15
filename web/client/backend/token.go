package main

import (
    "io"
    "log"
    "net/http"
	"time"
	"encoding/json"

    "github.com/auth0/go-jwt-middleware"
    "github.com/dgrijalva/jwt-go"
)

//need to make this secret
const (
    appKey = "authorizationplayground"
)


//Credentials Object for credential testing
type Credentials struct
{
	JSONstring string `json:"string"`
}

// TokenHandler is our handler to take a credential string and
// return a token used for future requests.
func TokenHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("Content-Type", "application/json")
	
	var creds Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"token_generation_failed"}`)
		return
	}

    // Building a token with an expiry of 1 hour.
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "cred": creds.JSONstring,
        "exp":  time.Now().Add(time.Hour * time.Duration(1)).Unix(),
        "iat":  time.Now().Unix(),
    })
    tokenString, err := token.SignedString([]byte(appKey))
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        io.WriteString(w, `{"error":"token_generation_failed"}`)
        return
    }
    io.WriteString(w, `{"token":"`+tokenString+`"}`)
    return
}

// AuthHandler checks if token is valid. Returning
// a 401 status to the client if it is not valid.
func AuthHandler(next http.Handler) http.Handler {
    if len(appKey) == 0 {
        log.Fatal("HTTP server unable to start, expected an APP_KEY for JWT auth")
    }
    jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
        ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
            return []byte(appKey), nil
        },
        SigningMethod: jwt.SigningMethodHS256,
    })
    return jwtMiddleware.Handler(next)
}

//OkHandler function to test is token in valid
func OkHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "application/json")
    io.WriteString(w, `{"status":"ok"}`)
}