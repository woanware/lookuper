package main

// Holds all of the helper functions and generic methods used throughout the application

import (
	util "github.com/woanware/goutil"
	"strings"
	"errors"
)

//
func getApiKeys(data string) (bool, []string) {

	//if strings.TrimSpace(data) == "[]" {
	//	return false, []string{}
	//}

	//data = strings.Replace(data, "[", "", 1)
	//data = strings.Replace(data, "]", "", 1)

	temp := strings.Split(data, ",")

	if len(temp) == 0 {
		return false, []string{}
	}

	return true, temp
}


//
func checkInputFile(data string) (error) {

	if len(data) == 0 {
		return errors.New("Input file not supplied")
	}

	if util.DoesFileExist(data) == false {
		return errors.New("Input file does not exist")
	}

	return nil
}