package main

// Stores the yaml config file data
type Config struct {
	MaxDataAge 				uint16  	`yaml:"max_data_age"`
	Retries 				uint8   	`yaml:"retries"`
	VtApiKeys				[]string	`yaml:"virus_total_api_keys"`
	SafeBrowsingApiKey 		string 		`yaml:"safe_browsing_api_key"`
	ThresholdPercentage		float32		`yaml:"threshold_percentage"`
	IgnoreKeywords			string  	`yaml:"ignored_keywords"`
	IgnoreKeywordsArray		[]string	`yaml:"-"`
}