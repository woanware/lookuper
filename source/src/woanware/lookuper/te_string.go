package main

import (
	util "github.com/woanware/goutil"
	"log"
	"strings"
	"time"
	"fmt"
	"net/http"
	"io/ioutil"
	"net/url"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "string_te" table
type TeString struct {
	Id         	int64	`db:"id"`
	String      string	`db:"string"`
	Count		int		`db:"count"`
	UpdateDate	int64 	`db:"update_date"`
}

// ##### Public Methods ################################################################################################

// Processes a TE request for a single string
func (s *TeString) Process(data string) int8 {
	httpClient := http.Client{}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://www.threatexpert.com/reports.aspx?find=%s&x=0&y=0", url.QueryEscape(data)), nil)
	if err != nil {
		log.Printf("Error creating request for TE report: %v", err)
		return WORK_RESPONSE_ERROR
	}

	resp, err := httpClient.Do(req)
	if resp == nil {
		log.Printf("No TE response: %v", err)
		return WORK_RESPONSE_ERROR
	}

	defer resp.Body.Close()
	if err != nil {
		log.Printf("Error sending request to TE: %v", err)
		return WORK_RESPONSE_ERROR
	}

	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body);
		if err != nil {
			log.Printf("Error reading TE response: %v", err)
			return WORK_RESPONSE_ERROR
		}

		if strings.Contains(string(body), "There were no ThreatExpert reports found that match your search criteria") == true {
			return WORK_RESPONSE_OK
		}

		return s.processResponse(data, string(body))
	}

	log.Printf("Error requesting TE report (string): %v (%d)", err, resp.StatusCode)
	return WORK_RESPONSE_ERROR
}

//
func (s *TeString) DoesDataExist(data string, staleTimestamp time.Time) (error, bool) {

	var temp TeString
	err := dbMap.SelectOne(&temp, "SELECT * FROM te_string WHERE string = $1", data)
	err, exists := validateDbData(temp.UpdateDate, staleTimestamp.Unix(), err)

	return err, exists
}

// ##### Private Methods ###############################################################################################

// Processes the TE response for a string
func (s *TeString) processResponse(data string, body string) int8 {
	regexMatch := regexTeStringMatch.FindAllStringSubmatch(string(body), -1)
	if regexMatch == nil {
		log.Printf("No regex match in TE string report")
		return WORK_RESPONSE_ERROR
	}

	return s.setRecord(data, int(util.ConvertStringToInt32(regexMatch[0][1])))
}

// Inserts a new TE string record, if that fails due to it already existing, then retrieve details and update
func (s *TeString) setRecord(data string, count int) int8 {
	stringTe := new(TeString)
	s.updateObject(stringTe, data, count)

	err := dbMap.Insert(stringTe)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") == false {
			log.Printf("Error inserting TE string record: %v", err)
			return WORK_RESPONSE_ERROR
		}

		err := dbMap.SelectOne(stringTe, "SELECT * FROM te_string WHERE string = $1", strings.ToLower(stringTe.String))
		if err != nil {
			log.Printf("Error retrieving TE string record: %v", err)
			return WORK_RESPONSE_ERROR
		}

		s.updateObject(stringTe, data, count)
		_, err = dbMap.Update(stringTe)
		if err != nil {
			log.Printf("Error updating TE string record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Generic method to copy the TE data to our string object
func (s *TeString) updateObject(
	stringTe *TeString,
	data string,
	count int) {

	stringTe.String = data
	stringTe.Count = count
	stringTe.UpdateDate = time.Now().UTC().Unix()
}
