package main

import (
	"log"
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

//// Creates a zip file containing the results CSV files for a job
//func (j *Job) GenerateCsv(outputFilePath string) {
//	//buf := new(bytes.Buffer)
//
//	var tempCsv []byte
//	switch j.Type {
//	case dataTypeMd5Vt:
//		tempCsv = j.GenerateJobCsvForVtHashes(false)
		//err := createAndWriteZipFile(zipWriter, FILE_NAME_HASHES, j.Id, tempCsv, true)
		//if err != nil {
		//	//return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
		//}

	//case dataTypeSha256Vt:
	//	_,_, tempCsv := j.GenerateJobCsvForHashesVt(config.DataFolder, true)
	//	err := createAndWriteZipFile(zipWriter, FILE_NAME_HASHES, j.Id, tempCsv, true)
	//	if err != nil {
	//		//return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
	//	}
	//
	//case dataTypeUrlVt:
	//	_,_, tempCsv := j.GenerateJobCsvForUrls(config.DataFolder)
	//	err := createAndWriteZipFile(zipWriter, FILE_NAME_URLS, j.Id, tempCsv, true)
	//	if err != nil {
	//		//return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
	//	}
	//
	//case dataTypeUrlG:
	//	_,_, tempCsv := j.GenerateJobCsvForUrlsG(config.DataFolder)
	//	err := createAndWriteZipFile(zipWriter, FILE_NAME_URLS, j.Id, tempCsv, true)
	//	if err != nil {
	//		//return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
	//	}
	//	return nil, buf.Bytes()
	//
	//case dataTypeIpVt:
	//	_,_, tempCsvRes, tempCsvDu := j.GenerateJobCsvForIps(config.DataFolder)
	//	err := createAndWriteZipFile(zipWriter, FILE_NAME_IP_RESOLUTIONS, j.Id, tempCsvRes, false)
	//	if err != nil {
	//		//return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
	//	}
	//
	//	err = createAndWriteZipFile(zipWriter, FILE_NAME_IP_DETECTED_URLS, j.Id, tempCsvDu, true)
	//	if err != nil {
	//		//return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
	//	}
	//
	//case dataTypeDomainVt:
	//	_,_, tempCsvRes, tempCsvDu := j.GenerateJobCsvForDomains(config.DataFolder)
	//	err := createAndWriteZipFile(zipWriter, FILE_NAME_DOMAIN_RESOLUTIONS, j.Id, tempCsvRes, false)
	//	if err != nil {
	//		//return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
	//	}
	//
	//	err = createAndWriteZipFile(zipWriter, FILE_NAME_DOMAIN_DETECTED_URLS, j.Id, tempCsvDu, true)
	//	if err != nil {
	//		return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
	//	}
	//	return nil, buf.Bytes()
	//
	//case dataTypeMd5Te:
	//	_, tempCsv := j.GenerateJobCsvForHashesTe(config.DataFolder)
	//	err := createAndWriteZipFile(zipWriter, FILE_NAME_HASHES, j.Id, tempCsv, true)
	//	if err != nil {
	//		//return fmt.Errorf("Error creating CSV results zip file (%d): %v", j.Id, err), []byte{}
	//	}
//	}
//}

//// Creates a CSV results file for hash jobs, also returns the total number and number of positive hashes
//func (j *Job) GenerateJobCsvForVtHashes(dataFolder string, isSha256 bool) (csvData []byte) {
//
//	data, err := loadJobData(j.Id, dataFolder)
//	if err != nil {
//		log.Errorf("Error loading job data: %v", err)
//		return 0, 0, []byte{}
//	}
//
//	file, err := ioutil.TempFile(os.TempDir(), "vtportal." + convertInt64ToString(j.Id) + ".csv")
//	defer os.Remove(file.Name())
//	csvWriter := csv.NewWriter(file)
//	csvWriter.Write([]string{"MD5", "SHA256", "Permalink", "Positives", "Total", "ScanDate", "Scans"})
//
//	scanner := bufio.NewScanner(bytes.NewBuffer(data))
//	var temp VtHash
//	for scanner.Scan() {
//		if isSha256 == true {
//			err = dbMap.SelectOne(&temp, "SELECT * FROM hash_vt WHERE sha256 = $1", strings.ToLower(scanner.Text()))
//		} else {
//			err = dbMap.SelectOne(&temp, "SELECT * FROM hash_vt WHERE md5 = $1", strings.ToLower(scanner.Text()))
//		}
//
//		if err != nil {
//			continue
//		}
//
//		if temp.Positives > 0 {
//			positives += 1
//		}
//
//		total += 1
//
//		csvWriter.Write([]string{
//			temp.Md5,
//			temp.Sha256,
//			temp.Permalink,
//			strconv.Itoa(int(temp.Positives)),
//			strconv.Itoa(int(temp.Total)),
//			convertUnixTimeToString(temp.ScanDate),
//			temp.Scans})
//	}
//
//	csvWriter.Flush()
//	bytes, err := readFile(file.Name())
//	if err != nil {
//		log.Errorf("Error reading temp CSV file: %v", err)
//		return 0, 0, []byte{}
//	}
//
//	return bytes
//}

//// Creates a CSV results file for hash jobs, also returns the total number
//func (j *Job) GenerateJobCsvForHashesTe(dataFolder string) (total int, csvData []byte) {
//
//	data, err := loadJobData(j.Id, dataFolder)
//	if err != nil {
//		log.Errorf("Error loading job data: %v", err)
//		return 0, []byte{}
//	}
//
//	file, err := ioutil.TempFile(os.TempDir(), "vtportal." + convertInt64ToString(j.Id) + ".csv")
//	defer os.Remove(file.Name())
//	csvWriter := csv.NewWriter(file)
//	csvWriter.Write([]string{"MD5", "Name", "Severities", "ScanDate"})
//
//	scanner := bufio.NewScanner(bytes.NewBuffer(data))
//	total = 0
//	var temp HashTe
//	for scanner.Scan() {
//		err = dbMap.SelectOne(&temp, "SELECT * FROM hash_te WHERE md5 = $1", strings.ToLower(scanner.Text()))
//		if err != nil {
//			continue
//		}
//
//		total += 1
//
//		csvWriter.Write([]string{
//			temp.Md5,
//			temp.Name,
//			temp.Severities,
//			convertUnixTimeToString(temp.ScanDate)})
//	}
//
//	csvWriter.Flush()
//	bytes, err := readFile(file.Name())
//	if err != nil {
//		log.Errorf("Error reading temp CSV file: %v", err)
//		return 0, []byte{}
//	}
//
//	return total, bytes
//}
//
//// Creates a CSV results file for URL jobs, also returns the total number and number of positive hashes
//func (j *Job) GenerateJobCsvForUrls(dataFolder string) (total int,
//positives int,
//csvData []byte) {
//	var temp Url
//
//	data, err := loadJobData(j.Id, dataFolder)
//	if err != nil {
//		log.Errorf("Error loading job data: %v", err)
//		return 0, 0, []byte{}
//	}
//
//	file, err := ioutil.TempFile(os.TempDir(), "vtportal." + convertInt64ToString(j.Id) + ".csv")
//	defer os.Remove(file.Name())
//	csvWriter := csv.NewWriter(file)
//	csvWriter.Write([]string{"URL", "Permalink", "Positives", "Total", "ScanDate", "Scans"})
//
//	scanner := bufio.NewScanner(bytes.NewBuffer(data))
//	var md5 string
//	for scanner.Scan() {
//		md5 = Md5EncodeString(scanner.Text())
//		err = dbMap.SelectOne(&temp, "SELECT * FROM url WHERE url_md5 = $1", md5)
//		if err != nil {
//			continue
//		}
//
//		total += 1
//
//		if temp.Positives > 1 {
//			positives += 1
//		}
//
//		csvWriter.Write([]string{
//			temp.Url,
//			temp.Permalink,
//			strconv.Itoa(int(temp.Positives)),
//			strconv.Itoa(int(temp.Total)),
//			convertUnixTimeToString(temp.ScanDate),
//			temp.Scans})
//	}
//
//	csvWriter.Flush()
//	bytes, _ := readFile(file.Name())
//	if err != nil {
//		return 0, 0, []byte{}
//	}
//
//	return total, positives, bytes
//}
//
//// Creates a CSV results file for URL jobs, also returns the total number and number of positive hashes
//func (j *Job) GenerateJobCsvForUrlsG(dataFolder string) (total int, positives int, csvData []byte) {
//	var temp UrlG
//
//	data, err := loadJobData(j.Id, dataFolder)
//	if err != nil {
//		log.Errorf("Error loading job data: %v", err)
//		return 0, 0, []byte{}
//	}
//
//	file, err := ioutil.TempFile(os.TempDir(), "vtportal." + convertInt64ToString(j.Id) + ".csv")
//	defer os.Remove(file.Name())
//	csvWriter := csv.NewWriter(file)
//	csvWriter.Write([]string{"URL", "List"})
//
//	scanner := bufio.NewScanner(bytes.NewBuffer(data))
//	var md5 string
//	for scanner.Scan() {
//		md5 = Md5EncodeString(scanner.Text())
//		err = dbMap.SelectOne(&temp, "SELECT * FROM url_g WHERE url_md5 = $1", md5)
//		if err != nil {
//			continue
//		}
//
//		total += 1
//
//		if len(temp.List) > 0 {
//			positives += 1
//		}
//
//		csvWriter.Write([]string{
//			temp.Url,
//			temp.List})
//	}
//
//	csvWriter.Flush()
//	bytes, _ := readFile(file.Name())
//	if err != nil {
//		return 0, 0, []byte{}
//	}
//
//	return total, positives, bytes
//}
//
//// Creates a CSV results file for IP jobs (Resolutions and Detected URL's), also returns the number resolved and number of detected URL's
//func (j *Job) GenerateJobCsvForIps(dataFolder string) (numResolved int,
//numDetectedUrls int,
//csvDataResolutions []byte,
//csvDataDetectedUrls []byte) {
//
//	data, err := loadJobData(j.Id, dataFolder)
//	if err != nil {
//		log.Errorf("Error loading job data: %v", err)
//		return 0, 0, []byte{}, []byte{}
//	}
//
//	file1, err := ioutil.TempFile(os.TempDir(), "vtportal." + convertInt64ToString(j.Id) + ".csv")
//	defer os.Remove(file1.Name())
//	csvWriter := csv.NewWriter(file1)
//	csvWriter.Write([]string{"HostName", "LastResolved"})
//
//	scanner := bufio.NewScanner(bytes.NewBuffer(data))
//	var tempRes []IpResolution
//	for scanner.Scan() {
//		ip, _ := InetAton(scanner.Text())
//		err = dbMap.Select(&tempRes, "SELECT * FROM ip_resolution WHERE ip = $1", ip)
//		if err != nil {
//			continue
//		}
//
//		for _, r := range tempRes {
//			numResolved += 1
//
//			csvWriter.Write([]string{
//				r.HostName,
//				convertUnixTimeToString(r.LastResolved)})
//		}
//
//		tempRes = nil
//	}
//	csvWriter.Flush()
//
//	file2, err := ioutil.TempFile(os.TempDir(), "vtportal." + convertInt64ToString(j.Id))
//	defer os.Remove(file2.Name())
//	csvWriter = csv.NewWriter(file2)
//	csvWriter.Write([]string{"URL", "Positives", "Total", "ScanDate"})
//
//	scanner = bufio.NewScanner(bytes.NewBuffer(data))
//	var tempUrls []IpDetectedUrl
//	for scanner.Scan() {
//		ip, _ := InetAton(scanner.Text())
//		err = dbMap.Select(&tempUrls, "SELECT * FROM ip_detected_url WHERE ip = $1", ip)
//		if err != nil {
//			continue
//		}
//
//		for _, u := range tempUrls {
//			numDetectedUrls += 1
//
//			csvWriter.Write([]string{
//				u.Url,
//				strconv.Itoa(int(u.Positives)),
//				strconv.Itoa(int(u.Total)),
//				convertUnixTimeToString(u.ScanDate)})
//		}
//
//		tempUrls = nil
//	}
//	csvWriter.Flush()
//
//	bytes1, _ := readFile(file1.Name())
//	if err != nil {
//		return  0, 0, []byte{}, []byte{}
//	}
//
//	bytes2, _ := readFile(file2.Name())
//	if err != nil {
//		return  0, 0, []byte{}, []byte{}
//	}
//
//	return numResolved, numDetectedUrls, bytes1, bytes2
//}
//
//// Creates a CSV results file for IP jobs (Resolutions and Detected URL's), also returns the number resolved and number of detected URL's
//func (j *Job) GenerateJobCsvForDomains(dataFolder string) (numResolved int,
//numDetectedUrls int,
//csvDataResolutions []byte,
//csvDataDetectedUrls []byte) {
//
//	data, err := loadJobData(j.Id, dataFolder)
//	if err != nil {
//		log.Errorf("Error loading job data: %v", err)
//		return 0, 0, []byte{}, []byte{}
//	}
//
//	// Create the resolved CSV for the domains
//	file1, err := ioutil.TempFile(os.TempDir(), "vtportal." + convertInt64ToString(j.Id) + ".csv")
//	defer os.Remove(file1.Name())
//	csvWriter := csv.NewWriter(file1)
//	csvWriter.Write([]string{"Domain", "IPAddress", "LastResolved"})
//
//	scanner := bufio.NewScanner(bytes.NewBuffer(data))
//	var tempRes []DomainResolution
//	var md5 string
//	var resolution DomainResolution
//	for scanner.Scan() {
//		md5 = Md5EncodeString(scanner.Text())
//		err = dbMap.Select(&tempRes, "SELECT * FROM domain_resolution WHERE domain_md5 = $1", md5)
//		if err != nil {
//			fmt.Println(err.Error())
//			continue
//		}
//
//		for _, resolution = range tempRes {
//			numResolved += 1
//
//			csvWriter.Write([]string{
//				scanner.Text(),
//				InetNtoa(resolution.IpAddress),
//				convertUnixTimeToString(resolution.LastResolved)})
//		}
//
//		tempRes = nil
//	}
//	csvWriter.Flush()
//
//	data, err = loadJobData(j.Id, dataFolder)
//	if err != nil {
//		log.Errorf("Error loading job data: %v", err)
//		return 0, 0, []byte{}, []byte{}
//	}
//
//	// Create the Detected URL's CSV for the domains
//	file2, err := ioutil.TempFile(os.TempDir(), "vtportal." + convertInt64ToString(j.Id) + ".csv")
//	defer os.Remove(file2.Name())
//	csvWriter = csv.NewWriter(file2)
//	csvWriter.Write([]string{"URL", "Positives", "Total", "ScanDate"})
//
//	scanner = bufio.NewScanner(bytes.NewBuffer(data))
//	var tempUrls []DomainDetectedUrl
//	var url DomainDetectedUrl
//	for scanner.Scan() {
//		md5 = Md5EncodeString(scanner.Text())
//		err = dbMap.Select(&tempUrls, "SELECT * FROM domain_detected_url WHERE domain_md5 = $1", md5)
//		if err != nil {
//			continue
//		}
//
//		for _, url = range tempUrls {
//			numDetectedUrls += 1
//
//			csvWriter.Write([]string{
//				url.Url,
//				strconv.Itoa(int(url.Positives)),
//				strconv.Itoa(int(url.Total)),
//				convertUnixTimeToString(url.ScanDate)})
//		}
//
//		tempUrls = nil
//	}
//	csvWriter.Flush()
//
//	bytes1, _ := readFile(file1.Name())
//	if err != nil {
//		return  0, 0, []byte{}, []byte{}
//	}
//
//	bytes2, _ := readFile(file2.Name())
//	if err != nil {
//		return  0, 0, []byte{}, []byte{}
//	}
//
//	return numResolved, numDetectedUrls, bytes1, bytes2
//}
