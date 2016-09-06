package main

// Constants for the job data types
const (
	dataTypeMd5Vt 		= 1
	dataTypeSha256Vt 	= 2
	dataTypeIpVt 		= 3
	dataTypeDomainVt 	= 4
	dataTypeUrlVt 		= 5
	dataTypeMd5Te 		= 6
	dataTypeStringTe 	= 7
	dataTypeGsb 		= 8 // Google SafeBrowsing
)

// String values for the job data types
var dataTypes = []string{
	dataTypeMd5Vt: "MD5 (VT)",
	dataTypeSha256Vt: "SHA256 (VT)",
	dataTypeIpVt: "IP (VT)",
	dataTypeDomainVt: "Domain (VT)",
	dataTypeUrlVt: "URL (VT)",
	dataTypeMd5Te: "MD5 (TE)",
	dataTypeStringTe: "String (TE)",
	dataTypeGsb: "Google Safe Browsing",
}

// Response codes for use in the "work" table
const (
	WORK_RESPONSE_NOT_PERFORMED int8 = 100
 	WORK_RESPONSE_ERROR 		int8 = 99
	WORK_RESPONSE_OK 			int8 = 1
	WORK_RESPONSE_KEY_FAILED 	int8 = -128
)

// The reference standard time in golang is: Mon Jan 2 15:04:05 MST 2006 (MST is GMT-0700)
const DATE_TIME_LAYOUT string = "2006-01-02 15:04:05"
const DATE_TIME_LAYOUT_TE string = "2 January 2006, 15:04:05"

// Used for TE lookups
const FAKE_API_KEY string = "AAAABBBBCCCCEEEEFFFF0000111122223333444455556666777788889999AAAA"

// Used for Google SafeBrowsing
const FAKE_API_KEY2 string = "AAAABBBBCCCCEEEEFFFF0000111122223333444455556666777788889999AAAB"
