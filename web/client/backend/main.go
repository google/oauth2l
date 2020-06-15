package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	fmt.Println("Authorization Playground")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello World")
	})
	http.HandleFunc("/token", TokenHandler)
	http.Handle("/auth", AuthHandler(http.HandlerFunc(OkHandler)))

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
