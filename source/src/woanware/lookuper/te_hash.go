package main

import (
	"log"
	"strings"
	"time"
	"fmt"
	"net/http"
	"io/ioutil"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "hash_te" table
type TeHash struct {
	Id         	int64		`db:"id"`
	Md5        	string		`db:"md5"`
	Name     	string		`db:"name"`
	Severities  string		`db:"severities"`
	ScanDate   	int64 		`db:"scan_date"`
	UpdateDate	int64 		`db:"update_date"`
}

// ##### Methods #######################################################################################################

// Processes a TE request for a single hash
func (h *TeHash) Process(data string) int8 {
	httpClient := http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://www.threatexpert.com/report.aspx?md5=%s", data), nil)
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

		if strings.Contains(string(body), "<meta name=\"description\" content=\"ThreatExpert Report") == false {
			return WORK_RESPONSE_OK
		}

		return h.processResponse(data, string(body))
	}

	log.Printf("Error requesting TE report (MD5): %v", err)
	return WORK_RESPONSE_ERROR
}

//
func (h *TeHash) DoesDataExist(data string, staleTimestamp time.Time) (error, bool) {

	var temp TeHash
	err := dbMap.SelectOne(&temp, "SELECT * FROM te_hash WHERE md5 = $1", data)
	err, exists := validateDbData(temp.UpdateDate, staleTimestamp.Unix(), err)

	return err, exists
}

// Processes the TE response for a MD5
func (h *TeHash) processResponse(md5 string, body string) int8 {

	regexTitle := regexTeTitle.FindStringSubmatch(string(body))
	if regexTitle == nil {
		log.Printf("No Title regex matches in TE hash report")
		return WORK_RESPONSE_ERROR
	}

	regexDate := regexTeSubmissionDate.FindStringSubmatch(string(body))
	if regexDate == nil {
		log.Printf("No Submission Date regex matches in TE hash report")
		return WORK_RESPONSE_ERROR
	}

	regexSeverities := regexTeSeverity.FindAllStringSubmatch(string(body), -1)
	if regexSeverities == nil {
		log.Printf("No Severity regex matches in TE hash report")
		return WORK_RESPONSE_ERROR
	}

	severities := make([]string, 0)
	for _, r := range regexSeverities {
		severities = append(severities, r[1] + " (" + r[2] + "/10)")
	}

	return h.setHashTeRecord(md5, regexTitle[1], strings.Join(severities, ","), regexDate[1])
}

// Inserts a new hash record, if that fails due to it already existing, then retrieve details and update
func (h *TeHash) setHashTeRecord(md5 string, name string, severities string, submittedDate string) int8 {
	hash := new(TeHash)
	h.updateObject(hash, md5, name, severities, submittedDate)

	err := dbMap.Insert(hash)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") == false {
			log.Printf("Error inserting TE hash record: %v", err)
			return WORK_RESPONSE_ERROR
		}

		err := dbMap.SelectOne(hash, "SELECT * FROM te_hash WHERE md5 = $1", strings.ToLower(hash.Md5))
		if err != nil {
			log.Printf("Error retrieving TE hash record: %v", err)
			return WORK_RESPONSE_ERROR
		}

		h.updateObject(hash, md5, name, severities, submittedDate)
		_, err = dbMap.Update(hash)
		if err != nil {
			log.Printf("Error updating TE hash record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Generic method to copy the TE data to our hash object
func (h *TeHash) updateObject(
	hash *TeHash,
	md5 string,
	name string,
	severities string,
	submittedDate string) {

	hash.Md5 = strings.ToLower(md5)
	hash.Name = name
	hash.Severities = severities
	hash.UpdateDate = time.Now().UTC().Unix()

	// Parse the scan date string into a golang time
	t, err := time.Parse(DATE_TIME_LAYOUT_TE, submittedDate)
	if err != nil {
		log.Printf("Error parsing TE hash scan date: %v", err)
	} else {
		hash.ScanDate = t.Unix()
	}
}
