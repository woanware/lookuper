package main

import (
	util "github.com/woanware/goutil"
	"log"
	"path"
	"os"
	"encoding/csv"
	"strings"
	"strconv"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "job" table
type Job struct {
	Id 					int		`db:"id"`
	Type        		int		`db:"type"`
	ApiKeys        		string	`db:"api_keys"`
	AreApiKeysPrivate	bool	`db:"are_api_keys_private"`
}

// ##### Methods #######################################################################################################

//
func (j *Job) Save() {

	err := dbMap.Insert(j)
	if err != nil {
		log.Fatalf("Error storing config: %v", err)
	}
}

//
func (j *Job) Load() {

	var job Job
	err := dbMap.SelectOne(&job, "SELECT * FROM job WHERE id =  $1", 1)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	j.Id = job.Id
	j.Type = job.Type
	j.ApiKeys = job.ApiKeys
	j.AreApiKeysPrivate = job.AreApiKeysPrivate
}

// Creates a zip file containing the results CSV files for a job
func (j *Job) GenerateCsv(outputFilePath string) {

	switch j.Type {
	case dataTypeMd5Vt:
		j.OutputVtHashes(outputFilePath, false)

	case dataTypeSha256Vt:
		j.OutputVtHashes(outputFilePath, true)

	case dataTypeUrlVt:
		j.OutputVtUrls(outputFilePath)

	case dataTypeIpVt:
		j.OutputVtIps(outputFilePath)

	case dataTypeDomainVt:
		j.OutputVtDomains(outputFilePath)

	case dataTypeMd5Te:
		j.OutputTeHashes(outputFilePath)

	case dataTypeStringTe:
		j.OutputTeHashes(outputFilePath)

	case dataTypeGsb:
		j.OutputGsb(outputFilePath)
	}
}

// Creates a CSV results file for hash jobs
func (j *Job) OutputVtHashes(outputDir string, isSha256 bool) {

	w := Work{}
	data := w.GetAllWork()

	fileName := "lookuper-vt-md5.csv"
	if isSha256 == true {
		fileName = "lookuper-vt-sha256.csv"
	}

	file, err := os.Create(path.Join(outputDir, fileName));
	defer file.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, fileName))
	}

	csvWriter := csv.NewWriter(file)
	csvWriter.Write([]string{"MD5", "SHA256", "Permalink", "Positives", "Total", "ScanDate", "Scans"})

	var temp VtHash
	for _, d := range data {

		if isSha256 == true {
			err = dbMap.SelectOne(&temp, "SELECT * FROM vt_hash WHERE sha256 = $1", strings.ToLower(d))
		} else {
			err = dbMap.SelectOne(&temp, "SELECT * FROM vt_hash WHERE md5 = $1", strings.ToLower(d))
		}

		if err != nil {
			log.Printf("Error retrieving data for VT hash output: %v", err)
			break
		}

		csvWriter.Write([]string{
			temp.Md5,
			temp.Sha256,
			temp.Permalink,
			strconv.Itoa(int(temp.Positives)),
			strconv.Itoa(int(temp.Total)),
			util.ConvertInt64ToRfc3339String(temp.ScanDate),
			temp.Scans})
	}

	csvWriter.Flush()
}

// Creates a CSV results file for VT URL
func (j *Job) OutputVtUrls(outputDir string) {

	w := Work{}
	data := w.GetAllWork()

	file, err := os.Create(path.Join(outputDir, "lookuper-vt-url.csv"));
	defer file.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, "lookuper-vt-url.csv"))
	}

	csvWriter := csv.NewWriter(file)
	csvWriter.Write([]string{"URL", "Permalink", "Positives", "Total", "ScanDate", "Scans"})

	var temp VtUrl
	var md5 string
	for _, d := range data {

		md5 = util.Md5HashString(d)
		err = dbMap.SelectOne(&temp, "SELECT * FROM vt_url WHERE url_md5 = $1", md5)

		if err != nil {
			log.Printf("Error retrieving data for VT URL output: %v", err)
			break
		}

		csvWriter.Write([]string{
			temp.Url,
			temp.Permalink,
			strconv.Itoa(int(temp.Positives)),
			strconv.Itoa(int(temp.Total)),
			util.ConvertInt64ToRfc3339String(temp.ScanDate),
			temp.Scans})
	}

	csvWriter.Flush()
}

// Creates a CSV results file for VT IP
func (j *Job) OutputVtIps(outputDir string) {

	w := Work{}
	data := w.GetAllWork()

	file1, err := os.Create(path.Join(outputDir, "lookuper-vt-ip-resolution.csv"));
	defer file1.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, "lookuper-vt-ip-resolution.csv"))
	}

	csvWriter := csv.NewWriter(file1)
	csvWriter.Write([]string{"HostName", "LastResolved"})

	var ip uint32
	var tempRes []VtIpResolution

	for _, d1 := range data {

		ip, _ = util.InetAton(d1)
		_, err = dbMap.Select(&tempRes, "SELECT * FROM vt_ip_resolution WHERE ip = $1", ip)
		if err != nil {
			log.Printf("Error retrieving data for VT IP resolution output: %v", err)
			continue
		}

		for _, r := range tempRes {

			csvWriter.Write([]string{
				r.HostName,
				util.ConvertInt64ToRfc3339String(r.LastResolved)})
		}

		tempRes = nil
	}
	csvWriter.Flush()

	file2, err := os.Create(path.Join(outputDir, "lookuper-vt-ip-detected-url.csv"));
	defer file2.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, "lookuper-vt-ip-detected-url.csv"))
	}

	csvWriter = csv.NewWriter(file2)
	csvWriter.Write([]string{"URL", "Positives", "Total", "ScanDate"})

	var tempUrls []VtIpDetectedUrl
	for _, d2 := range data {

		ip, _ := util.InetAton(d2)
		_, err = dbMap.Select(&tempUrls, "SELECT * FROM vt_ip_detected_url WHERE ip = $1", ip)
		if err != nil {
			log.Printf("Error retrieving data for VT IP detected URL output: %v", err)
			continue
		}

		for _, u := range tempUrls {

			csvWriter.Write([]string{
				u.Url,
				strconv.Itoa(int(u.Positives)),
				strconv.Itoa(int(u.Total)),
				util.ConvertInt64ToRfc3339String(u.ScanDate)})
		}

		tempUrls = nil
	}
	csvWriter.Flush()
}

// Creates a CSV results file for VT IP
func (j *Job) OutputVtDomains(outputDir string) {

	w := Work{}
	data := w.GetAllWork()

	file1, err := os.Create(path.Join(outputDir, "lookuper-vt-domain-resolution.csv"));
	defer file1.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, "lookuper-vt-domain-resolution.csv"))
	}

	csvWriter := csv.NewWriter(file1)
	csvWriter.Write([]string{"Domain", "IPAddress", "LastResolved"})

	var tempRes []VtDomainResolution
	var md5 string

	for _, d1 := range data {

		md5 = util.Md5HashString(d1)
		_, err = dbMap.Select(&tempRes, "SELECT * FROM vt_domain_resolution WHERE domain_md5 = $1", md5)
		if err != nil {
			log.Printf("Error retrieving data for VT domain resolution output: %v", err)
			continue
		}

		for _, resolution := range tempRes {
			csvWriter.Write([]string{
				d1,
				util.InetNtoa(resolution.IpAddress),
				util.ConvertInt64ToRfc3339String(resolution.LastResolved)})
		}

		tempRes = nil
	}
	csvWriter.Flush()

	file2, err := os.Create(path.Join(outputDir, "lookuper-vt-domain-detected-url.csv"));
	defer file2.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, "lookuper-vt-domain-detected-url.csv"))
	}

	csvWriter = csv.NewWriter(file2)
	csvWriter.Write([]string{"Domain", "IPAddress", "LastResolved"})

	var tempUrls []VtDomainDetectedUrl
	for _, d2 := range data {

		md5 = util.Md5HashString(d2)
		_, err = dbMap.Select(&tempUrls, "SELECT * FROM vt_domain_detected_url WHERE domain_md5 = $1", md5)
		if err != nil {
			log.Printf("Error retrieving data for VT domain detected URL output: %v", err)
			continue
		}

		for _, url := range tempUrls {
			csvWriter.Write([]string{
				url.Url,
				strconv.Itoa(int(url.Positives)),
				strconv.Itoa(int(url.Total)),
				util.ConvertInt64ToRfc3339String(url.ScanDate)})
		}

		tempUrls = nil
	}
	csvWriter.Flush()
}

// Creates a CSV results file for hash jobs
func (j *Job) OutputTeHashes(outputDir string) {

	w := Work{}
	data := w.GetAllWork()

	file, err := os.Create(path.Join(outputDir, "lookuper-te-md5.csv"));
	defer file.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, "lookuper-te-md5.csv"))
	}

	csvWriter := csv.NewWriter(file)
	csvWriter.Write([]string{"MD5", "Name", "Severities", "ScanDate"})

	var temp TeHash
	for _, d := range data {

		err = dbMap.SelectOne(&temp, "SELECT * FROM te_hash WHERE md5 = $1", strings.ToLower(d))
		if err != nil {
			log.Printf("Error retrieving data for TE hash output: %v", err)
			break
		}

		csvWriter.Write([]string{
			temp.Md5,
			temp.Name,
			temp.Severities,
			util.ConvertInt64ToRfc3339String(temp.ScanDate)})
	}

	csvWriter.Flush()
}

// Creates a CSV results file for TE string jobs
func (j *Job) OutputTeStrings(outputDir string) {

	w := Work{}
	data := w.GetAllWork()

	file, err := os.Create(path.Join(outputDir, "lookuper-te-string.csv"));
	defer file.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, "lookuper-te-string.csv"))
	}

	csvWriter := csv.NewWriter(file)
	csvWriter.Write([]string{"String", "Count", "UpdateDate"})

	var temp TeString
	for _, d := range data {

		err = dbMap.SelectOne(&temp, "SELECT * FROM te_string WHERE LOWER(string) = $1", strings.ToLower(d))
		if err != nil {
			log.Printf("Error retrieving data for TE string output: %v", err)
			break
		}

		csvWriter.Write([]string{
			temp.String,
			strconv.Itoa(int(temp.Count)),
			util.ConvertInt64ToRfc3339String(temp.UpdateDate)})
	}

	csvWriter.Flush()
}

// Creates a CSV results file for TE string jobs
func (j *Job) OutputGsb(outputDir string) {

	w := Work{}
	data := w.GetAllWork()

	file, err := os.Create(path.Join(outputDir, "lookuper-gsb.csv"));
	defer file.Close()
	if err != nil {
		log.Fatalf("Error opening output file: %v (%s)", err, path.Join(outputDir, "lookuper-gsb.csv"))
	}

	csvWriter := csv.NewWriter(file)
	csvWriter.Write([]string{"URL", "Data"})

	var gsb GoogleSafeBrowsing
	var md5 string

	for _, d := range data {

		md5 = util.Md5HashString(d)
		err = dbMap.SelectOne(&gsb, "SELECT * FROM google_safe_browsing WHERE url_md5 = $1", md5)
		if err != nil {
			continue
		}

		csvWriter.Write([]string{
			gsb.Url,
			gsb.Data})
	}

	csvWriter.Flush()
}