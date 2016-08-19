package main

// Holds all of the helper functions and generic methods used throughout the application

import (
	util "github.com/woanware/goutil"
	"strings"
	"errors"
	"log"
)

// ##### Methods #######################################################################################################

//
func getApiKeys(data string) (bool, []string) {

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

//
func checkOutputFile(data string) (error) {

	if len(data) == 0 {
		return errors.New("Output file not supplied")
	}

	return nil
}

// Helper method to check the return values from the "doesDataExistInDb". The aim is to reduce repeated code
func validateDbData(updateDate int64, staleTimestamp int64, err error) (error, bool) {

	log.Printf("%v", updateDate)
	log.Printf("%v", staleTimestamp)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows in result set") == true {
			log.Printf("%BLAH1")
			return nil, false
		} else {
			log.Printf("%BLAH2")
			return err, false
		}
	} else {
		if updateDate < staleTimestamp {
			log.Printf("%BLAH3")
			return nil, false
		} else {
			log.Printf("%BLAH4")
			return nil, true
		}
	}
}