package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/williballenthin/govt"
	util "github.com/woanware/goutil"
	"log"
	"bytes"
	"bufio"
	"strings"
	"io/ioutil"
	"time"
	"fmt"
	"encoding/csv"
)

// ##### Structs #######################################################################################################

type Worker struct {
	db 					*sql.DB
	dataType 			int
	govtc 				govt.Client
	csvWriter			*csv.Writer
	privateApiKeys		bool
	numberTotal    		int
	numberComplete 		int
	numberCacheHits		int
}

// ##### Methods #######################################################################################################

func NewWorker() *Worker {

	w := Worker{}

	var err error
	w.db, err = sql.Open("sqlite3", DB_FILE_NAME)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	return &w
}

//
func (w *Worker) Run(
	inputFile string,
	outputDir string,
	dataType int,
	apiKeys []string,
	privateApiKeys bool) {

	count, err := w.getWorkTableRecordCount()
	if err != nil {
		log.Printf("Error checking for existing work: %v", err)
		return
	}

	j := new(Job)

	if len(inputFile) > 0 {
		if count > 0 {
			fmt.Println("There is existing data in the work queue. Use the 'resume' command to continue or the 'clear' command to clear the queue")
			return
		} else {
			j.Type = dataType
			j.ApiKeys = strings.Join(apiKeys, "#")
			j.AreApiKeysPrivate = privateApiKeys
			j.Save()

			w.loadData(inputFile)
		}
	} else {
		if count == 0 {
			fmt.Println("No existing work to continue")
			return
		}

		j.Type, apiKeys, privateApiKeys = w.loadJob()
	}

	w.dataType = j.Type
	w.privateApiKeys = privateApiKeys

	log.Printf("Data type: %s", dataTypes[w.dataType])

	for {
		w.govtc = govt.Client{}
		w.govtc.UseDefaultUrl()

		var response_code int8
		loopCounter := 0

		// Loop through the keys until either the whole set of hashes are complete. We may need to swap to the next
		for _, apiKey := range apiKeys {
			log.Printf("API key: %s", apiKey)
			w.govtc.Apikey = apiKey

			response_code = w.process(apiKey)
			if response_code == WORK_RESPONSE_KEY_FAILED {
				log.Printf("Problem with API key: %s", apiKey)
				continue
			} else if response_code == WORK_RESPONSE_ERROR {
				log.Printf("Stopped due to an error whilst loading the work batch data")
				return
			}

			j.GenerateCsv(outputDir)
			resetTables(false)
			log.Println("Complete")
			log.Printf("Cache hits: %d", w.numberCacheHits)
			return
		}

		log.Printf("Exhausted keys, pausing processing")

		// If we have done a complete cycle of the keys, then it means
		// that they are exhausted so we will sleep for an hour each loop
		loopCounter += 1
		if loopCounter > 25 {
			log.Printf("Processing stopped due to key exhaustion over 24 hour period")
			return
		}

		// Create a ticker that elapses every seconds, so we can stop the worker, since time.sleep cannot be interrupted
		tickerCounter := 0
		ticker := time.NewTicker(time.Duration(1) * time.Second)
		for range ticker.C {
			tickerCounter += 1
			if tickerCounter == 3600 {
				log.Printf("Unpausing processing")
				break
			}
		}
	}
}

//
func (w *Worker) loadJob() (int, []string, bool) {

	j := Job{}
	j.Load()

	var total int
	total, err := w.getWorkTableRecordCount()
	if err != nil {
		log.Fatalf("Error retrieving work count: %v ", err)
	}
	w.numberTotal = total
	log.Printf("Loaded No. items: %d", w.numberTotal)

	return j.Type, strings.Split(j.ApiKeys, "#"), j.AreApiKeysPrivate
}

//
func (w *Worker) loadData(inputFile string) {

	log.Println("Loading data")

	data, err := ioutil.ReadFile(inputFile)

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	var md5 string
	var val string
	var work *Work

	uniquedList := make(map[string]bool)

	transaction, err := dbMap.Begin()
	if err != nil {
		log.Printf("Error creating transaction for data load: %v", err)
		return
	}
	for scanner.Scan() {
		val = scanner.Text()
		val = strings.TrimSpace(val)

		if len(val) == 0 {
			continue
		}

		if w.dataType == dataTypeMd5Vt || w.dataType == dataTypeMd5Te {
			if len(val) != 32 {
				log.Printf("Invalid MD5 hash data: %s", val)
				continue
			}
		} else if w.dataType == dataTypeSha256Vt  {
			if len(val) != 64 {
				log.Printf("Invalid SHA256 hash data: %s", val)
				continue
			}
		}

		// Use a map to identify unique values
		md5 = strings.ToLower(util.Md5HashString(val))
		if uniquedList[md5] == true {
			continue
		}

		uniquedList[md5] = true

		work = new(Work)
		work.Md5 = md5
		work.Data = val
		work.ResponseCode = WORK_RESPONSE_NOT_PERFORMED

		err = transaction.Insert(work)
		if err != nil {
			log.Printf("Error inserting work record: %v", err)
		}
	}
	transaction.Commit()

	w.numberTotal = (len(uniquedList))

	log.Printf("Loaded No. items: %d", len(uniquedList))
}

//
func (w *Worker) getWorkTableRecordCount() (int, error) {

	var count int
	err := dbMap.SelectOne(&count, "SELECT COUNT(1) as val FROM work")
	if err != nil {
		return 0, err
	}

	return count, nil
}

// Performs the actually processing of the user supplied data. The method opens the input file and reads the data line
// by line. The line data is then validated against the "work" table and then the actual data specific table, only then
// is an actual batch request performed against the target service
func (w *Worker) process(apiKey string) int8 {

	batchSize := 4
	if w.privateApiKeys == true {
		batchSize = 25
	}

	// IP and domain look-ups cannot be performed in batch mode, so we default
	// the batch size to 1, regardless of what kind of API key is used. Also
	// all TE lookups need to be performed one at a time
	if w.dataType != dataTypeMd5Vt &&
		w.dataType != dataTypeUrlVt &&
		w.dataType != dataTypeSha256Vt ||
		w.dataType == dataTypeMd5Te ||
		w.dataType == dataTypeStringTe ||
		w.dataType == dataTypeGsb ||
		w.dataType == dataTypeHibp {

		batchSize = 1
	}

	log.Printf("Batch size: %d", batchSize)

	var responseCode int8
	var batchData BatchData
	var percent float64
	for  {
		batchData = w.loadBatch(batchSize)
		if len(batchData.Items) == 0 {
			break	
		}

		if w.numberComplete % 5 == 0 {		
		 	percent = float64(w.numberComplete) * float64(100)  / float64(w.numberTotal)
			if percent != 0 {
				log.Printf("Percent Complete: %d", int(percent))
			}
		}

		responseCode =  w.processBatch(apiKey, batchData)
		if responseCode != WORK_RESPONSE_OK {
			return responseCode
		}
	}

	return WORK_RESPONSE_OK
}

//
func (w *Worker) loadBatch(batchSize int) (BatchData) {

	batchData := BatchData{}
	var data string
	var ret bool

	staleTimestamp := time.Now().UTC().Add(-time.Duration(24*config.MaxDataAge) * time.Hour)

	workData := make(map[string]int8)

	rows, err := w.db.Query("SELECT data FROM work WHERE response_code = $1", util.ConvertInt8ToString(WORK_RESPONSE_NOT_PERFORMED))
	if err != nil {
		log.Printf("Error retrieving data from work queue: %v", err)
		return batchData
	}

	for rows.Next() {
		err = rows.Scan(&data)
		if len(data) == 0 {
			continue
		}

		err, ret = w.doesDataExistInDb(staleTimestamp, data)
		if err != nil {
			log.Printf("Error determining if data exists in database: %v (%s)", err, data)
			workData[data] = WORK_RESPONSE_ERROR
			w.numberComplete += 1
			continue
		}

		if ret == true {
			w.numberCacheHits += 1
			w.numberComplete += 1
			workData[data] = WORK_RESPONSE_OK
			continue
		}

		batchData.AddData(data)

		if len(batchData.Items) >= batchSize {
			break
		}
	}
	rows.Close()

	// We update after, due to locking
	for k, v := range workData {
		w.setWorkRecord(k, v)
	}

	return batchData
}

// Generic method to determine if the data exists within the cached data
func (w *Worker) doesDataExistInDb(staleTimestamp time.Time, data string) (error, bool) {

	switch w.dataType {
	case dataTypeMd5Vt:
		vtHash := VtHash{govtc: w.govtc}
		return vtHash.DoesDataExist(true, data, staleTimestamp)
	case dataTypeSha256Vt:
		vtHash := VtHash{govtc: w.govtc}
		return vtHash.DoesDataExist(false, data, staleTimestamp)
	case dataTypeIpVt:
		vtIpRes := VtIpResolution{govtc: w.govtc}
		return vtIpRes.DoesDataExist(data, staleTimestamp)
	case dataTypeDomainVt:
		vtDomain := VtDomainResolution{govtc: w.govtc}
		return vtDomain.DoesDataExist(data, staleTimestamp)
	case dataTypeUrlVt:
		vtUrl := VtUrl{govtc: w.govtc}
		return vtUrl.DoesDataExist(data, staleTimestamp)
	case dataTypeMd5Te:
		teHash := TeHash{}
		return teHash.DoesDataExist(data, staleTimestamp)
	case dataTypeStringTe:
		teString := TeString{}
		return teString.DoesDataExist(data, staleTimestamp)
	case dataTypeGsb:
		gsb := GoogleSafeBrowsing{}
		return gsb.DoesDataExist(data, staleTimestamp)
	case dataTypeHibp:
		hibp := HaveIBeenPwned{}
		return hibp.DoesDataExist(data, staleTimestamp)
	}

	return nil, false
}

// Determines if a "work" record exists for the data and the status is set to WORK_RESPONSE_NOT_PERFORMED
func (w *Worker) hasWorkBeenCompleted(md5 string) (error, bool) {

	var temp Work
	err := dbMap.SelectOne(&temp, "SELECT * FROM work WHERE md5 = $1 and response_code = $2", md5, WORK_RESPONSE_NOT_PERFORMED)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows in result set") == true {
			return nil, false
		} else {
			return err, false
		}
	}

	return nil, true
}

// Determines if a "work" record exists for the data and the status is set to WORK_RESPONSE_NOT_PERFORMED
func (w *Worker) doesWorkExist(md5 string) (error, bool) {

	var id int
	_, err := dbMap.Select(&id, "SELECT COUNT(1) FROM work WHERE md5 = $1", md5)
	if err != nil {
		return err, false
	}

	if id == 0 {
		return nil, false
	}

	return nil, true
}

// Helper method to check the return values from the "doesDataExistInDb". The aim is to reduce repeated code
func (w *Worker) validateDbData(updateDate int64, staleTimestamp int64, err error) (error, bool) {

	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows in result set") == true {
			return nil, false
		} else {
			return err, false
		}
	} else {
		if updateDate < staleTimestamp {
			return nil, false
		} else {
			return nil, true
		}
	}
}

// Controller method to perform the batches of data. The method calls the
// appropriate method depending on the data type and the number in the batch
func (w *Worker) processBatch(apiKey string, batch BatchData) int8 {

	var response_code int8

	attempts := 0
	for attempts < 3 {
		if len(batch.Items) == 1 {
			switch w.dataType {
			case dataTypeMd5Vt:
				vtHash := VtHash{govtc: w.govtc}
				response_code = vtHash.Process([]string{batch.Items[0]})
			case dataTypeSha256Vt:
				vtHash := VtHash{govtc: w.govtc}
				response_code = vtHash.Process([]string{batch.Items[0]})
			case dataTypeIpVt:
				ipResolution := VtIpResolution{govtc: w.govtc}
				response_code = ipResolution.Process(batch.Items[0])
			case dataTypeDomainVt:
				domainResolution := VtDomainResolution{govtc: w.govtc}
				response_code = domainResolution.Process(batch.Items[0])
			case dataTypeUrlVt:
				vtUrl := VtUrl{govtc: w.govtc}
				response_code = vtUrl.Process([]string{batch.Items[0]})
			case dataTypeMd5Te:
				teHash := TeHash{}
				response_code = teHash.Process(batch.Items[0])
			case dataTypeStringTe:
				teString := TeString{}
				response_code = teString.Process(batch.Items[0])
			case dataTypeGsb:
				gsb := GoogleSafeBrowsing{}
				response_code = gsb.Process(batch.Items[0])
			case dataTypeHibp:
				hibp := HaveIBeenPwned{}
				response_code = hibp.Process(batch.Items[0])
			}
		} else {
			switch w.dataType {
			case dataTypeMd5Vt:
				vtHash := VtHash{govtc: w.govtc}
				response_code = vtHash.Process(batch.Items)
			case dataTypeSha256Vt:
				vtHash := VtHash{govtc: w.govtc}
				response_code = vtHash.Process(batch.Items)
			case dataTypeUrlVt:
				vtUrl := VtUrl{govtc: w.govtc}
				response_code = vtUrl.Process(batch.Items)
			// The other data types cannot be performed in multiple batch mode
			}
		}

		w.doPause(apiKey)

		// If we get a valid OK response then don't try again
		if response_code == WORK_RESPONSE_OK {
			break
		}

		attempts += 1
		log.Printf("Retrying batch: Attempts: %d Response Code: %d", attempts, response_code)
	}

	if response_code == WORK_RESPONSE_ERROR || response_code == WORK_RESPONSE_KEY_FAILED {
		for _, b := range batch.Items {
			w.setWorkRecord(b, WORK_RESPONSE_ERROR)
		}

		if response_code == WORK_RESPONSE_KEY_FAILED {
			return WORK_RESPONSE_KEY_FAILED
		}
	} else {
		for _, b := range batch.Items {
			w.setWorkRecord(b, WORK_RESPONSE_OK)
		}
	}

	w.numberComplete += len(batch.Items)

	return WORK_RESPONSE_OK
}

// If the job is using a public API key then we must pause between each HTTP request. Provides
// a generic method and reduces the need for repeated logic checking in the other methods
func (w *Worker) doPause(apiKey string) {

	if w.privateApiKeys == false {
		if apiKey == FAKE_API_KEY {
			// This is a fake API key set for TE requests. Technically we
			// don't need to pause but to be nice we pause for 500 milliseconds
			time.Sleep(500 * time.Millisecond)
		} else if apiKey == FAKE_API_KEY2 {
			// This is a fake API key set for Google SB requests.
		} else if apiKey == FAKE_API_KEY3 {
			// This is a fake API key set for HIBP requests.
			time.Sleep(1600 * time.Millisecond)
		} else {
			// VT pause is about 15 seconds so we give a pause of 17 to be on the safe side
			time.Sleep(17 * time.Second)
		}
	}
}

// Retrieve a work record and updates the ResponseCode
func (w *Worker) setWorkRecord(data string, responseCode int8) int8 {

	work := new(Work)
	md5 := util.Md5HashString(data)

	err := dbMap.SelectOne(work, "SELECT * FROM work WHERE md5 = $1", strings.ToLower(md5))
	if err != nil {
		log.Printf("Error retrieving work record: %v (MD5:%s)", err, strings.ToLower(md5))
		return WORK_RESPONSE_ERROR
	}

	work.ResponseCode = responseCode
	_, err = dbMap.Update(work)
	if err != nil {
		log.Printf("Error updating work record: %v", err)
		return WORK_RESPONSE_ERROR
	}

	return WORK_RESPONSE_OK
}

