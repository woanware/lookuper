package main

import (
	"github.com/williballenthin/govt"
	"strings"
	"log"
	"sort"
	"fmt"
	"time"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "vt_hash" table
type VtHash struct {
	Id      	int64        	`db:"id"`
	Md5        	string        	`db:"md5"`
	Sha256     	string        	`db:"sha256"`
	Positives  	int16        	`db:"positives"`
	Total      	int16        	`db:"total"`
	Permalink  	string        	`db:"permalink"`
	Scans      	string        	`db:"scans"`
	ScanDate   	int64        	`db:"scan_date"`
	UpdateDate 	int64        	`db:"update_date"`
	govtc      	govt.Client		`db:"-"`
}

// ##### Methods #######################################################################################################

// Processes a VT API request for multiple hashes
func(h *VtHash) Process(data []string) int8 {

	var err error
	var fr *govt.FileReport
	var frr *govt.FileReportResults
	if len(data) == 1 {
		fr, err = h.govtc.GetFileReport(data[0])
	} else {
		frr, err = h.govtc.GetFileReports(data)
	}

	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unexpected status code: 204") {
			return WORK_RESPONSE_KEY_FAILED
		}

		log.Printf("Error requesting VT hash report: %v", err)
		return WORK_RESPONSE_ERROR
	}

	if len(data) == 1 {
		h.setRecord(*fr)
	} else {
		for _, fr := range *frr {
			if fr.ResponseCode == 1 {
				h.setRecord(fr)
			}
		}
	}

	return WORK_RESPONSE_OK
}

//
func  (h *VtHash) DoesDataExist(isMd5 bool, data string, staleTimestamp time.Time) (error, bool) {

	sql := "SELECT * FROM vt_hash WHERE md5 = $1"
	if isMd5 == false {
		sql = "SELECT * FROM vt_hash WHERE sha256 = $1"
	}

	var hash VtHash
	err := dbMap.SelectOne(&hash, sql, strings.ToLower(data))
	err, exists := validateDbData(hash.UpdateDate, staleTimestamp.Unix(), err)

	return err, exists
}

// Inserts a new hash record, if that fails due to it already existing, then retrieve details and update
func (h *VtHash) setRecord(fr govt.FileReport) int8 {

	hash := new(VtHash)
	h.updateObject(hash, fr)

	err := dbMap.Insert(hash)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") == false {
			log.Printf("Error inserting VT hash record: %v (%s)", err, hash.Md5)
			return WORK_RESPONSE_ERROR
		}

		err := dbMap.SelectOne(hash, "SELECT * FROM vt_hash WHERE md5 = $1", strings.ToLower(hash.Md5))
		if err != nil {
			log.Printf("Error retrieving VT hash record: %v", err)
			return WORK_RESPONSE_ERROR
		}

		h.updateObject(hash, fr)
		_, err = dbMap.Update(hash)
		if err != nil {
			log.Printf("Error updating VT hash record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Generic method to copy the VT data to our hash object
func (h *VtHash) updateObject(hash *VtHash, fp govt.FileReport) {

	hash.Md5 = strings.ToLower(fp.Md5)
	hash.Sha256 = strings.ToLower(fp.Sha256)
	hash.Positives = int16(fp.Positives)
	hash.Total = int16(fp.Total)
	hash.Permalink = fp.Permalink
	hash.Scans = h.generateFileScansString(fp.Scans)
	hash.UpdateDate = time.Now().UTC().Unix()

	// Parse the scan date string into a golang time
	t, err := time.Parse(DATE_TIME_LAYOUT, fp.ScanDate)
	if err != nil {
		log.Printf("Error parsing VT hash scan date: %v", err)
	} else {
		hash.ScanDate = t.Unix()
	}
}

// Creates a comma delimited string with the scan engine and the result/malware/virus
func (h *VtHash) generateFileScansString(fs map[string]govt.FileScan) string {
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
