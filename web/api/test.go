package main

import (
	"fmt"
	"io/ioutil"
)

func main() {
	str, mem := getCredentialPath(Credential{})
	fmt.Println(str)

	file, _ := mem.Open(str)

	_, err2 := ioutil.ReadFile("/test/lol")

	if err2 != nil {
		fmt.Println("error")
		return
	}

	b := make([]byte, 4)
	file.Read(b)
	fmt.Println(string(b))
}
