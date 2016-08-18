package main

// Stores the yaml config file data
type Config struct {
	MaxHashAge 				uint16  	`yaml:"max_hash_age"`
	Retries 				uint8   	`yaml:"retries"`
	VtApiKeys				[]string	`yaml:"virus_total_api_keys"`
	SafeBrowsingApiKey 		string 		`yaml:"safe_browsing_api_key"`
	ThresholdPercentage		float32		`yaml:"threshold_percentage"`
	IgnoreKeywords			string  	`yaml:"ignored_keywords"`
	IgnoreKeywordsArray		[]string	`yaml:"-"`
}

// Encapsulates the data from the "work" table
type Work struct {
	Md5        		string	`db:"md5"`
	Data        	string	`db:"data"`
	ResponseCode	int8	`db:"response_code"`
}

