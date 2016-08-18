package goutil

import (
	"time"
)

//
func ParseTimestampWithFormat(data string, layout string) time.Time {
	parsedTimestamp, err := time.Parse(layout, data)
	if err != nil {
		var temp time.Time
		return temp
	}

	return parsedTimestamp
}

// Determines the number of days between two dates
func DiffDays(date1 time.Time, date2 time.Time) int {
	return int(date2.Sub(date1) / (24 * time.Hour))
}

// Converts go Time var to an RFC3339 compliant string
func ConvertInt64ToRfc3339String(data int64) string {
	var temp time.Time
	if data == 0 {
		temp = time.Date(0, 0, 0, 0, 0, 0, 0, time.UTC)
	} else {
		temp = time.Unix(int64(data), 0)
	}
	return temp.Format(time.RFC3339)
}

//
func InTimeSpan(start, end, check time.Time) bool {
	return check.After(start) && check.Before(end)
}
