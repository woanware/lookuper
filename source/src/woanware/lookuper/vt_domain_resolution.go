package main

import (
	"github.com/williballenthin/govt"
	util "github.com/woanware/goutil"
	"log"
	"strings"
	"time"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "domain_resolution" table
type VtDomainResolution struct {
	Id 				int64		`db:"id"`
	DomainMd5 		string 		`db:"domain_md5"`
	LastResolved	int64 		`db:"last_resolved"`
	IpAddress 		uint32 		`db:"ip_address"`
	UpdateDate 		int64 		`db:"update_date"`
	govtc			govt.Client	`db:"-"`
}

// Encapsulates the data from the "domain_detected_url" table
type VtDomainDetectedUrl struct {
	Id 				int64	`db:"id"`
	DomainMd5 		string 	`db:"domain_md5"`
	Url				string	`db:"url"`
	UrlMd5			string	`db:"url_md5"`
	Positives  		int16	`db:"positives"`
	Total      		int16	`db:"total"`
	ScanDate   		int64 	`db:"scan_date"`
	UpdateDate 		int64 	`db:"update_date"`
}

// ##### Methods #######################################################################################################

// Processes a VT API request for a single domain
func (d *VtDomainResolution) Process(data string) int8 {
	dr, err := d.govtc.GetDomainReport(data)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unexpected status code: 204") {
			return WORK_RESPONSE_KEY_FAILED
		}

		log.Printf("Error requesting VT Domain report: %v", err)
		return WORK_RESPONSE_ERROR
	}

	if dr.ResponseCode == 1 {
		return d.processResponse(data, dr)
	}

	return WORK_RESPONSE_OK
}

//
func  (d *VtDomainResolution) DoesDataExist(data string, staleTimestamp time.Time) (error, bool) {

	md5 := util.Md5HashString(data)

	var dr VtDomainResolution
	err := dbMap.SelectOne(&dr, "SELECT * FROM vt_domain_resolution WHERE domain_md5 = $1 ORDER BY update_date DESC LIMIT 1", strings.ToLower(md5))
	err, exists := validateDbData(dr.UpdateDate, staleTimestamp.Unix(), err)

	return err, exists
}

// Processes the VT response for a VT domain report
func (d *VtDomainResolution) processResponse(data string, dr *govt.DomainReport) int8 {

	for _, r := range dr.Resolutions {
		if d.setRecordDr(data, r) == WORK_RESPONSE_ERROR {
			return WORK_RESPONSE_ERROR
		}
	}

	for _, u := range dr.DetectedUrls {
		if d.setRecordDdu(data, u) == WORK_RESPONSE_ERROR {
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Inserts a new domain resolution record, if that fails due to it already existing, then retrieve details and update
func (d *VtDomainResolution) setRecordDr(domain string, dr govt.DomainResolution) int8 {

	data := new(VtDomainResolution)
	d.updateObjectDr(domain, data, dr)

	err := dbMap.Insert(data)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") {
			err := dbMap.SelectOne(data, "SELECT * FROM vt_domain_resolution WHERE domain_md5 = $1 and ip_address = $2", data.DomainMd5, data.IpAddress)
			if err != nil {
				log.Printf("Error retrieving domain resolution record: %v", err)
				return WORK_RESPONSE_ERROR
			} else {
				d.updateObjectDr(domain, data, dr)
				_, err := dbMap.Update(data)
				if err != nil {
					log.Printf("Error updating domain resolution record: %v", err)
					return WORK_RESPONSE_ERROR
				}
			}
		} else {
			log.Printf("Error inserting domain resolution record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Inserts a new domain detected URL record, if that fails due to it already existing, then retrieve details and update
func (d *VtDomainResolution) setRecordDdu(domain string, du govt.DetectedUrl) int8 {

	data := new(VtDomainDetectedUrl)
	d.updateObjectDdu(domain, data, du)

	err := dbMap.Insert(data)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") {
			err := dbMap.SelectOne(data, "SELECT * FROM vt_domain_detected_url WHERE domain_md5 = $1 and url_md5 = $2",  data.DomainMd5, data.UrlMd5)
			if err != nil {
				log.Printf("Error retrieving domain detected URL record: %v", err)
				return WORK_RESPONSE_ERROR
			} else {
				d.updateObjectDdu(domain, data, du)
				_, err := dbMap.Update(data)
				if err != nil {
					log.Printf("Error updating domain detected URL record: %v", err)
					return WORK_RESPONSE_ERROR
				}
			}
		} else {
			log.Printf("Error inserting domain detected URL record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

//
func (d *VtDomainResolution) updateObjectDr(domain string, data *VtDomainResolution, dr govt.DomainResolution) {

	data.DomainMd5 = strings.ToLower(util.Md5HashString(domain))
	temp, _ := util.InetAton(dr.IpAddress)
	data.IpAddress = temp
	data.UpdateDate = time.Now().UTC().Unix()

	// Parse the last resolved date string into a golang time
	t, err := time.Parse(DATE_TIME_LAYOUT, dr.LastResolved)
	if err != nil {
		log.Printf("Error parsing domain resolution last resolved date: %v", err)
	} else {
		data.LastResolved = t.Unix()
	}
}

//
func (d *VtDomainResolution) updateObjectDdu(domain string, data *VtDomainDetectedUrl, du govt.DetectedUrl) {

	data.DomainMd5 = strings.ToLower(util.Md5HashString(domain))
	data.Url = du.Url
	data.UrlMd5 = strings.ToLower(util.Md5HashString(du.Url))
	data.Positives = int16(du.Positives)
	data.Total = int16(du.Total)
	data.UpdateDate = time.Now().UTC().Unix()

	// Parse the scan date string into a golang time
	t, err := time.Parse(DATE_TIME_LAYOUT, du.ScanDate)
	if err != nil {
		log.Printf("Error parsing IP detected URL scan date: %v", err)
	} else {
		data.ScanDate = t.Unix()
	}
}