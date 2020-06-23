package main

import (
	"fmt"
	// "io/ioutil"
)

func main() {
	cred := Credential{"credential": `{
		"client_id": "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com",
		"client_secret": "d-FL95Q19q7MQmFpd7hHD0Ty",
		"refresh_token": "1//0fSiQuKvDXZMUCgYIARAAGA8SNwF-L9IrfdCKsbXFGSz5ZDEWlNnU6oTCoTI3FEN3J_2BsHmbfcvtNoWqhv7nrJ8G9UDGdREM4Ms",
		"type": "authorized_user"
	  }`}

	wrapper := WrapperCommand{
		"fetch",
		Args{"--scope": []string{"cloud-platform"}},
		cred,
	}

	output, err := wrapper.Execute()

	fmt.Println("")

	// fd, err := allocateMemFile(jsonStr)

	// if err != nil {
	// 	fmt.Println("Error")
	// }

	// path := getCredentialPath(fd)

	// b, err := ioutil.ReadFile(path)

	// fmt.Println(string(b))
	
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(output)

	
}
