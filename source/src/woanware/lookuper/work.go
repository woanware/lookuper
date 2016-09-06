package main

import (
	"log"
)

// ##### Structs #######################################################################################################

// Encapsulates the data from the "work" table
type Work struct {
	Md5        		string	`db:"md5"`
	Data        	string	`db:"data"`
	ResponseCode	int8	`db:"response_code"`
}

// ##### Methods #######################################################################################################

func (w *Work) GetAllWork() []string {
	rows, err := dbMap.Db.Query("SELECT data FROM work")
	if err != nil {
		log.Printf("Error retrieving all work: %v", err)
		return []string{}
	}
	defer rows.Close()

	temp := make([]string, 0)

	var data string
	for rows.Next() {
		err = rows.Scan(&data)
		if len(data) == 0 {
			continue
		}

		temp = append(temp, data)
	}
	rows.Close()

	return temp
}

