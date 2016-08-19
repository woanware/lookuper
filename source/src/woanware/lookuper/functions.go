package main

// Holds all of the helper functions and generic methods used throughout the application

import (
	util "github.com/woanware/goutil"
	"strings"
	"errors"
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
func checkOutputDirectory(data string) (error) {

	if len(data) == 0 {
		return errors.New("Output directory value not supplied")
	}

	if util.DoesDirExist(data) == false {
		return errors.New("Invalid output directory value")
	}

	return nil
}

// Helper method to check the return values from the "doesDataExistInDb". The aim is to reduce repeated code
func validateDbData(updateDate int64, staleTimestamp int64, err error) (error, bool) {

	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows in result set") == true {
			return nil, false
		} else {
			return err, false
		}
	} else {
		if updateDate < staleTimestamp {
			return nil, false
		} else {
			return nil, true
		}
	}
}