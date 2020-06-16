package main

import (
    "io"
    "log"
    "net/http"
	"time"
	"os"
	"fmt"
	// "encoding/json"
    "github.com/auth0/go-jwt-middleware"
    "github.com/dgrijalva/jwt-go"
)

//need to make this secret
const (
    appKey = "authorizationplayground"
)


//Claims Object for credential testing
type Claims struct
{
	JSONfile *os.File
	jwt.StandardClaims
}

// TokenHandler is our handler to take a credential string and
// return a token used for future requests.
func TokenHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("Content-Type", "application/json")
	
	// opening the JSON file with the credentials

	jsonFile, err := os.Open("/usr/local/google/home/melyxlin/Downloads/shinfan-test-89c218991319.json")
    // if we os.Open returns an error then handle it
    if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"token_generation_failed"}`)
		return
    }
    fmt.Println("Successfully Opened jsonFile")
    // defer the closing of our jsonFile so that we can parse it later on
    // defer jsonFile.Close()

	// Building a token with an expiry of 5 minutes.
	expirationTime := time.Now().Add(5 * time.Minute)
	
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		JSONfile: jsonFile,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString([]byte(appKey))
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        io.WriteString(w, `{"error":"token_generation_failed"}`)
        return
	}
	
	fmt.Println("Sucessfully created token")

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
    // w.Header().Add("Content-Type", "application/json")
	// io.WriteString(w, `{"status":"ok"}`)
	fmt.Println("auth-ok")
}