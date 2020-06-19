package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
)

// Credentials object read body from the request body
type Credentials struct {
	RequestType string
	Args        map[string]interface{}
	UploadCredentials        map[string]interface{}
}

// Claims object that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	UploadCredentials map[string]interface{}
	jwt.StandardClaims
}

var jwtKey = []byte("my_secret_key")
var creds Credentials

// TokenHandler to create the Token
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(creds.UploadCredentials) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"cannot make token without credentials"}`)
		return
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(1440 * time.Minute)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		UploadCredentials: creds.UploadCredentials,

		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	io.WriteString(w, `{"token":"`+tokenString+`"}`)

}

// AuthHandler checks if token is valid. Returning a 401 status to the client if it is not valid.

func AuthHandler(next http.Handler) http.Handler {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})
	return jwtMiddleware.Handler(next)
}

//NoTokenHandler for the case when a cached token is not used
func NoTokenHandler(w http.ResponseWriter, r *http.Request) {
	var cacheCreds Credentials
	err := json.NewDecoder(r.Body).Decode(&cacheCreds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	creds = cacheCreds
	OkHandler(w, r)

}

//OkHandler function to test is token in valid
func OkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	newWrapperCommand := &WrapperCommand{
		RequestType: creds.RequestType,
		Args:        creds.Args,
	}
	response, err := newWrapperCommand.Execute()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	io.WriteString(w, `{"response":"`+response+`"}`)
}

func main() {
	fmt.Println("Authorization Playground")

	http.HandleFunc("/token", TokenHandler)

	http.Handle("/auth", AuthHandler(http.HandlerFunc(OkHandler)))

	http.HandleFunc("/notoken", NoTokenHandler)

	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatal(err)
	}
}
