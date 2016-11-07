package main

import (
	hibp "github.com/infoassure/go-haveibeenpwned"
	"log"
	"time"
	"strings"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "hibp" table
type HaveIBeenPwned struct {
	Id         	int64	`db:"id"`
	Email      	string	`db:"email"`
	Breaches	string	`db:"breaches"`
}

// ##### Public Methods ################################################################################################

// Processes a TE request for a single string
func (h *HaveIBeenPwned) Process(data string) int8 {

	var c hibp.HibpClient

	log.Printf("%v", data)

	err, resp, breaches := c.BreachesForAccount(data, "", true)
	if err != nil {
		if err.Error() == "EOF" {
			return WORK_RESPONSE_OK
		}

		log.Printf("HIBP response status1: %v (%s)", err, data)
		return WORK_RESPONSE_ERROR
	}

	if len(resp) > 0 {
		log.Printf("HIBP response status2: %v (%s)", resp, data)
		return WORK_RESPONSE_ERROR
	}

	if len(*breaches) == 0 {
		return WORK_RESPONSE_OK
	}

	temp := make([]string, 0)
	for _, b := range *breaches {
		log.Printf("N: %v", b.Name)
		temp = append(temp, strings.TrimSpace(b.Name))
	}

	log.Printf("%v", temp)

	return h.setRecord(data, strings.Join(temp, ","))
}

//
func (h *HaveIBeenPwned) DoesDataExist(data string, staleTimestamp time.Time) (error, bool) {
	return nil, false
}

// ##### Private Methods ###############################################################################################

// Inserts a new TE string record, if that fails due to it already existing, then retrieve details and update
func (h *HaveIBeenPwned) setRecord(email string, breaches string) int8 {

	hibp := new(HaveIBeenPwned)
	h.updateObject(hibp, email, breaches)

	err := dbMap.SelectOne(hibp, "SELECT * FROM hibp WHERE email = $1", hibp.Email)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows in result set") == false {
			log.Printf("Error inserting HIBP record: %v", err)
			return WORK_RESPONSE_ERROR
		}

		err := dbMap.Insert(hibp)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate key value violates") == false {
				log.Printf("Error inserting HIBP record: %v", err)
				return WORK_RESPONSE_ERROR
			}
		}

		return WORK_RESPONSE_OK
	}

	h.updateObject(hibp, email, breaches)
	_, err = dbMap.Update(hibp)
	if err != nil {
		log.Printf("Error updating HIBP record: %v", err)
		return WORK_RESPONSE_ERROR
	}

	return WORK_RESPONSE_OK
}

// Generic method to copy the data into the HIBP object
func (h *HaveIBeenPwned) updateObject(

	hibp *HaveIBeenPwned,
	email string,
	breaches string) {

	hibp.Email = strings.ToLower(email)
	hibp.Breaches = breaches
}



