package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)


func TestWrapperCommandStructSingleArg(t *testing.T) {
	const expectedRequest = "test"
	var expectedArgs = Args{"flag": "value"}

	wrapper := WrapperCommand{
		expectedRequest,
		expectedArgs,
		Credential{},
	}

	if wrapper.RequestType != expectedRequest {
		t.Errorf("expected request value incorrect")
	}

	if !reflect.DeepEqual(wrapper.Args, expectedArgs) {
		t.Errorf("expected args are not correct")
	}
}

func TestWrapperCommandStructManyArgs(t *testing.T) {
	const expectedRequest = "test"
	var expectedArgs = Args{"flag": []string{"value1", "value2"}}

	wrapper := WrapperCommand{
		expectedRequest,
		expectedArgs,
		Credential{},
	}

	if wrapper.RequestType != expectedRequest {
		t.Errorf("expected request value incorrect")
	}

	if !reflect.DeepEqual(wrapper.Args, expectedArgs) {
		t.Errorf("expected args are not correct")
	}
}

func TestInvalidTypeInArgs(t *testing.T) {
	const expectedRequest = "test"
	var expectedArgs = Args{"flag": []int{2, 3}}

	wrapper := WrapperCommand{
		expectedRequest,
		expectedArgs,
		Credential{},
	}

	_, err := wrapper.Execute()

	if err.Error() != "invalid type found in args" {
		t.Errorf("invalid types not detected")
	}
}

func TestValidTypeInArgs(t *testing.T) {
	const expectedRequest = "test"
	var expectedArgs = Args{"flag": []string{"test"}}

	wrapper := WrapperCommand{
		expectedRequest,
		expectedArgs,
		Credential{},
	}

	_, err := wrapper.Execute()

	if err != nil {
		t.Errorf("valid types not detected")
	}
}

func TestJSONValidTypeInArgs(t *testing.T) {
	wrapper := WrapperCommand{}

	jsonString := []byte(`{
        "requesttype": "fetch",
        "args": {
            "--scope": ["cloud-platform","userinfo.email"]
		},
		"body": {}
	}`)
	
	json.Unmarshal(jsonString, &wrapper)

	_, err := wrapper.Execute()

	if err != nil {
		t.Errorf("valid types not detected")
	}
}

func TestJSONInvalidTypeInArgs(t *testing.T) {
	wrapper := WrapperCommand{}

	jsonString := []byte(`{
        "requesttype": "fetch",
        "args": {
            "--scope": 2
		},
		"body": {}
	}`)
	
	json.Unmarshal(jsonString, &wrapper)

	_, err := wrapper.Execute()

	if err.Error() != "invalid type found in args" {
		t.Errorf("invalid types not detected")
	}
}

func TestJSONValueInArgs(t *testing.T) {
	wrapper := WrapperCommand{}

	jsonString := []byte(`{
        "requesttype": "fetch",
        "args": {
            "--scope": ["cloud-platform", "userinfo.email"]
		},
		"body": {}
	}`)
	
	json.Unmarshal(jsonString, &wrapper)

	flattenedArgs, _ := combinedArgs(wrapper)

	if !reflect.DeepEqual(flattenedArgs, []string{"fetch", "--scope", "cloud-platform", "userinfo.email"}) {
		t.Errorf("flattened values not correct")
	}
}

func TestDummyOauth2lCommand(t *testing.T) {
	const expectedRequest = "test"
	var expectedArgs = Args{"--token": "ya29.justkiddingmadethisoneup"}

	wrapper := WrapperCommand{
		expectedRequest,
		expectedArgs,
		nil,
	}

	output, err := wrapper.Execute()
	fmt.Printf("%v", []byte(output))
	if output != "1" || err != nil {
		t.Errorf("error running basic command")
	}
}