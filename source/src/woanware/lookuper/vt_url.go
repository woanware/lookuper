package main

import (
	"github.com/williballenthin/govt"
	util "github.com/woanware/goutil"
	"log"
	"strings"
	"time"
	"sort"
	"fmt"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "url" table
type VtUrl struct {
	Id         	int64		`db:"id"`
	Url        	string		`db:"url"`
	UrlMd5     	string 		`db:"url_md5"`
	Positives  	int16		`db:"positives"`
	Total      	int16		`db:"total"`
	Permalink  	string		`db:"permalink"`
	Scans      	string		`db:"scans"`
	ScanDate   	int64 		`db:"scan_date"`
	UpdateDate 	int64 		`db:"update_date"`
	govtc		govt.Client	`db:"-"`
}

// ##### Methods #######################################################################################################

// Processes a VT API request for a URL(s)
func (u *VtUrl) Process(data []string) int8 {
	//if isSingleItem == true {
	//	ur, err := u.govtc.GetUrlReport(data[0])
	//	if err != nil {
	//		if strings.Contains(strings.ToLower(err.Error()), "unexpected status code: 204") {
	//			return WORK_RESPONSE_KEY_FAILED
	//		}
	//
	//		log.Printf("Error requesting VT URL report: %v", err)
	//		return WORK_RESPONSE_ERROR
	//	}
	//
	//	if ur.ResponseCode == 1 {
	//		u.processUrlReport(ur)
	//	}
	//} else {
		urr, err := u.govtc.GetUrlReports(data)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unexpected status code: 204") {
				return WORK_RESPONSE_KEY_FAILED
			}

			log.Printf("Error requesting VT MD5 report: %v", err)
			return WORK_RESPONSE_ERROR
		}

		for _, ur := range *urr {
			if ur.ResponseCode == 1 {
				u.setRecord(ur)
			}
		}
	//}

	return WORK_RESPONSE_OK
}

//// Processes the VT response for a VT URL report
//func (u *VtUrl) processResponse(ur *govt.UrlReport) int8 {
//	return u.setUrlRecord(*ur)
//}

// Inserts a new URL record, if that fails due to it already existing, then retrieve details and update
func (u *VtUrl) setRecord(ur govt.UrlReport) int8 {
	data := new(VtUrl)
	u.updateObject(data, ur)

	err := dbMap.Insert(data)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") {
			err := dbMap.SelectOne(data, "SELECT * FROM url WHERE url_md5 = $1", data.UrlMd5)
			if err != nil {
				log.Printf("Error retrieving URL record: %v", err)
				return WORK_RESPONSE_ERROR
			} else {
				u.updateObject(data, ur)
				_, err := dbMap.Update(data)
				if err != nil {
					log.Printf("Error updating URL record: %v", err)
					return WORK_RESPONSE_ERROR
				}
			}
		} else {
			log.Printf("Error inserting URL record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Generic method to copy the VT data to our URL object
func (u *VtUrl) updateObject(url *VtUrl, ur govt.UrlReport) {
	url.Url = ur.Resource
	url.UrlMd5 = strings.ToLower(util.Md5HashString(ur.Resource))
	url.Positives = int16(ur.Positives)
	url.Total = int16(ur.Total)
	url.Permalink = ur.Permalink
	url.Scans = u.generateUrlScansString(ur.Scans)
	url.UpdateDate = time.Now().UTC().Unix()

	// Parse the scan date string into a golang time
	t, err := time.Parse(DATE_TIME_LAYOUT, ur.ScanDate)
	if err != nil {
		log.Printf("Error parsing URL scan date: %v", err)
	} else {
		url.ScanDate = t.Unix()
	}
}

// Creates a comma delimited string with the scan engine and the result/malware/virus
func (u *VtUrl) generateUrlScansString(fs map[string]govt.UrlScan) string {
	// We need to sort the keys first, since the iteration is actually random if not
	var keys []string
	for e, s := range fs {
		if s.Detected == false {
			continue
		}

		keys = append(keys, e)
	}

	sort.Strings(keys)

	var temp []string
	for _, k := range keys {
		temp = append(temp, fmt.Sprintf("%s: %s", k, fs[k].Result))
	}

	return strings.Join(temp, ",")
}