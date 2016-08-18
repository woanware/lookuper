package main

import (
	util "github.com/woanware/goutil"
	"log"
	"fmt"
	"strings"
	"time"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "url_sb" table
type GoogleSafeBrowsing struct {
	Id         	int64	`db:"id"`
	Url        	string	`db:"url"`
	UrlMd5     	string 	`db:"url_md5"`
	Data		string	`db:"data"`
	UpdateDate 	int64 	`db:"update_date"`
}

// ##### Methods #######################################################################################################

// Processes a Google SafeBrowsing API request for a single URL
func (g *GoogleSafeBrowsing) Process(data string) int8 {

	threats, err := safeBrowsing.LookupURLs([]string{data})
	if err != nil {
		log.Printf("Error processing Google SafeBrowsing URL report: %v", err)
		return WORK_RESPONSE_ERROR
	}

	response := ""
	if len(threats[0]) > 0 {
		response = fmt.Sprintf("Platform: %s#Type: %s#Entry Type: %s",
			threats[0][0].PlatformType, threats[0][0].ThreatType, threats[0][0].ThreatEntryType)
	}

	g.setRecord(data, response)

	return WORK_RESPONSE_OK
}

//// Processes the response for a Google SafeBrowsing URL report
//func (g *GoogleSafeBrowsing) processUrlGReport(data string, response string) int8 {
//	return g.setUrlGRecord(data, response)
//}

// Inserts a new URL record, if that fails due to it already existing, then retrieve details and update
func (g *GoogleSafeBrowsing) setRecord(url string, response string) int8 {
	gsb := new(GoogleSafeBrowsing)
	g.updateObject(gsb, url, response)

	err := dbMap.Insert(gsb)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") {

			err := dbMap.SelectOne(gsb, "SELECT * FROM url_g WHERE url_md5 = $1", util.Md5HashString(url))
			if err != nil {
				log.Printf("Error retrieving URL record: %v", err)
				return WORK_RESPONSE_ERROR
			} else {
				g.updateObject(gsb, url, response)
				_, err := dbMap.Update(gsb)
				if err != nil {
					log.Printf("Error updating URL (SB) record: %v", err)
					return WORK_RESPONSE_ERROR
				}
			}
		} else {
			log.Printf("Error inserting URL (SB) record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Generic method to copy the data to our Sb URL object
func (g *GoogleSafeBrowsing) updateObject(gsb *GoogleSafeBrowsing, data string, response string) {
	gsb.Url = data
	gsb.UrlMd5 = strings.ToLower(util.Md5HashString(data))
	gsb.Data = response
	gsb.UpdateDate = time.Now().UTC().Unix()
}
