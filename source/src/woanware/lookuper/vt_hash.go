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

// Encapsulates the data from the "hash_vt" table
type VtHash struct {
	Id         	int64		`db:"id"`
	Md5        	string		`db:"md5"`
	Sha256     	string		`db:"sha256"`
	Positives  	int16		`db:"positives"`
	Total      	int16		`db:"total"`
	Permalink  	string		`db:"permalink"`
	Scans      	string		`db:"scans"`
	ScanDate   	int64 		`db:"scan_date"`
	UpdateDate 	int64 		`db:"update_date"`
	govtc		govt.Client	`db:"-"`
}

// ##### Methods #######################################################################################################

// Processes a VT API request for multiple hashes
func(h *VtHash) Process(data []string) int8 {
	frr, err := h.govtc.GetFileReports(data)

	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unexpected status code: 204") {
			return WORK_RESPONSE_KEY_FAILED
		}

		log.Printf("Error requesting VT MD5 report: %v", err)
		return WORK_RESPONSE_ERROR
	}

	for _, fr := range *frr {
		if fr.ResponseCode == 1 {
			h.processResponse(&fr)
		}
	}

	return WORK_RESPONSE_OK
}

//// Processes a VT API request for a single hash
//func (h *VtHash) ProcessBatchMd5Vt(data string) int8 {
//	frp, err := h.govtc.GetFileReport(data)
//	if err != nil {
//		if strings.Contains(strings.ToLower(err.Error()), "unexpected status code: 204") {
//			return WORK_RESPONSE_KEY_FAILED
//		}
//
//		log.Printf("Error requesting VT report (MD5): %v", err)
//		return WORK_RESPONSE_ERROR
//	}
//
//	if frp.ResponseCode == 1 {
//		return h.processFileReport(frp)
//	}
//
//	return WORK_RESPONSE_OK
//}

// Processes the VT response for a VT file report
func (h *VtHash) processResponse(fr *govt.FileReport) int8 {
	// If the number of positives is > than the threshold specified in the config file,
	// then we determine if 50% or less of the scan results don't contain the keywords
	// like "generic,toolbar" etc
	if config.ThresholdPercentage > 0 {
		if float32(fr.Positives) > config.ThresholdPercentage {
			log.Printf("Positives identified > threshold: %d/%f (MD5: %s)", int(fr.Positives), config.ThresholdPercentage, fr.Md5)
			numContainsKeyword := 0

			for _, s := range fr.Scans {
				if s.Detected == false {
					continue
				}

				for _,k := range config.IgnoreKeywordsArray {
					if strings.Contains(strings.ToLower(s.Result), k) == true {
						numContainsKeyword += 1
					}
				}
			}

			ret := (100.0 / float32(fr.Positives) * float32(numContainsKeyword))
			log.Printf("Keyword detection percentage: %f", ret)
			if ret <= config.ThresholdPercentage {
				//w.job.SetIdentifiedHighDetections()
				//w.HighDetectionsFunc(w.JobId, fmt.Sprintf("MD5: %s\nScans: %s", fr.Md5, w.generateFileScansString(fr.Scans)))
			}
		}
	}

	return h.setRecord(*fr)
}

// Inserts a new hash record, if that fails due to it already existing, then retrieve details and update
func (h *VtHash) setRecord(fr govt.FileReport) int8 {
	hash := new(VtHash)
	h.updateObject(hash, fr)

	err := dbMap.Insert(hash)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") == false {
			//log.Error("Error inserting VT hash record (%d): %v (%s)", w.JobId, err, hash.Md5)
			return WORK_RESPONSE_ERROR
		}

		err := dbMap.SelectOne(hash, "SELECT * FROM hash_vt WHERE md5 = $1", strings.ToLower(hash.Md5))
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
