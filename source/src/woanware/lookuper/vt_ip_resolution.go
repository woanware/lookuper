package main

import (
	"github.com/williballenthin/govt"
	util "github.com/woanware/goutil"
	"log"
	"strings"
	"time"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "ip_resolution" table
type VtIpResolution struct {
	Id 				int64		`db:"id"`
	Ip 				int64		`db:"ip"`
	LastResolved	int64 		`db:"last_resolved"`
	HostName 		string 		`db:"host_name"`
	HostNameMd5 	string 		`db:"host_name_md5"`
	UpdateDate 		int64 		`db:"update_date"`
	govtc			govt.Client	`db:"-"`
}

// Encapsulates the data from the "ip_detected_url" table
type VtIpDetectedUrl struct {
	Id 				int64	`db:"id"`
	Ip 				uint32	`db:"ip"`
	Url				string	`db:"url"`
	UrlMd5			string	`db:"url_md5"`
	Positives  		int16	`db:"positives"`
	Total      		int16	`db:"total"`
	ScanDate   		int64 	`db:"scan_date"`
	UpdateDate 		int64 	`db:"update_date"`
}

// ##### Methods #######################################################################################################

// Processes a VT API request for a single IP
func (i *VtIpResolution) Process(data string) int8 {
	ipr, err := i.govtc.GetIpReport(data)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unexpected status code: 204") {
			return WORK_RESPONSE_KEY_FAILED
		}

		log.Printf("Error requesting VT IP report: %v", err)
		return WORK_RESPONSE_ERROR
	}

	if ipr.ResponseCode == 1 {
		i.processResponse(data, ipr)
	}

	return WORK_RESPONSE_OK
}

//
func (i *VtIpResolution) DoesDataExist(data uint32, staleTimestamp time.Time) (error, bool) {

	var ipRes VtIpResolution
	err := dbMap.SelectOne(&ipRes, "SELECT * FROM vt_ip_resolution WHERE ip = $1", data)
	err, exists := validateDbData(ipRes.UpdateDate, staleTimestamp.Unix(), err)

	return err, exists
}

// Processes the VT response for a VT IP report
func (i *VtIpResolution) processResponse(data string, ir *govt.IpReport) int8 {
	for _, r := range ir.Resolutions {
		if i.setRecordIr(data, r) == WORK_RESPONSE_ERROR {
			return WORK_RESPONSE_ERROR
		}
	}

	for _, d := range ir.DetectedUrls {
		if i.setRecordIdu(data, d) == WORK_RESPONSE_ERROR {
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Inserts a new IP resolution record, if that fails due to it already existing, then retrieve details and update
func (i *VtIpResolution) setRecordIr(ipAddress string, ir govt.IpResolution) int8 {
	data := new(VtIpResolution)
	i.updateObjectIr(ipAddress, data, ir)

	err := dbMap.Insert(data)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") {
			err := dbMap.SelectOne(data, "SELECT * FROM vt_ip_resolution WHERE ip = $1 and host_name_md5 = $2", data.Ip, data.HostNameMd5)
			if err != nil {
				log.Printf("Error retrieving IP resolution record: %v", err)
				return WORK_RESPONSE_ERROR
			} else {
				i.updateObjectIr(ipAddress, data, ir)
				_, err := dbMap.Update(data)
				if err != nil {
					log.Printf("Error updating IP resolution record: %v", err)
					return WORK_RESPONSE_ERROR
				}
			}
		} else {
			log.Printf("Error inserting IP resolution record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

// Inserts a new IP detected URL record, if that fails due to it already existing, then retrieve details and update
func (i *VtIpResolution) setRecordIdu(ipAddress string, du govt.DetectedUrl) int8 {
	data := new(VtIpDetectedUrl)
	i.updateObjectIdu(ipAddress, data, du)

	err := dbMap.Insert(data)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") {
			err := dbMap.SelectOne(data, "SELECT * FROM vt_ip_detected_url WHERE ip = $1 and url_md5 = $2", data.Ip, data.UrlMd5)
			if err != nil {
				log.Printf("Error retrieving IP detected URL record: %v", err)
				return WORK_RESPONSE_ERROR
			} else {
				i.updateObjectIdu(ipAddress, data, du)
				_, err := dbMap.Update(data)
				if err != nil {
					log.Printf("Error updating IP detected URL record: %v", err)
					return WORK_RESPONSE_ERROR
				}
			}
		} else {
			log.Printf("Error inserting IP detected URL record: %v", err)
			return WORK_RESPONSE_ERROR
		}
	}

	return WORK_RESPONSE_OK
}

//
func (i *VtIpResolution) updateObjectIr(ipAddress string, data *VtIpResolution, ip govt.IpResolution) {
	temp, _ := util.InetAton(ipAddress)
	data.Ip = int64(temp)
	data.HostName = ip.Hostname
	data.HostNameMd5 = strings.ToLower(util.Md5HashString(ip.Hostname))
	data.UpdateDate = time.Now().UTC().Unix()

	// Parse the last resolved date string into a golang time
	t, err := time.Parse(DATE_TIME_LAYOUT, ip.LastResolved)
	if err != nil {
		log.Printf("Error parsing IP resolution last resolved date: %v", err)
	} else {
		data.LastResolved = t.Unix()
	}
}

//
func (i *VtIpResolution) updateObjectIdu(ipAddress string, data *VtIpDetectedUrl, du govt.DetectedUrl) {
	temp, _ := util.InetAton(ipAddress)
	data.Ip = temp
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

