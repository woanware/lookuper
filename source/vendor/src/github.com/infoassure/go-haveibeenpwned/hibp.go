package hibp

import (
	"net/http"
	"time"
	"encoding/json"
	"fmt"
	"net/url"
)

const API_URL = "https://haveibeenpwned.com/api/v2/%s"

// Struct that represents our HIBP client
type HibpClient struct {
}

// Parameters for the HTTP requests
type Parameters map[string]string

type Breaches []Breach

type Breach struct {
	Name      	string		`json:"Name"`
	Title       string   	`json:"Title"`
	Domain      string    	`json:"Domain"`
	BreachDate  string    	`json:"BreachDate"`
	AddedDate   time.Time 	`json:"AddedDate"`
	PwnCount    int       	`json:"PwnCount"`
	DataClasses []string  	`json:"DataClasses"`
	Description string    	`json:"Description"`
	IsVerified  bool      	`json:"IsVerified"`
	IsSensitive bool      	`json:"IsSensitive"`
	IsRetired   bool      	`json:"IsRetired"`
}

// ***** Private Methods ***********************************************************************************************

func (h *HibpClient) getApiJson(actionUrl string, parameters Parameters, result interface{}) (err error, resp string) {

	values := url.Values{}
	for k, v := range parameters {
		values.Add(k, v)
	}

	client := new(http.Client)

	req, err := http.NewRequest("GET", fmt.Sprintf(API_URL, actionUrl) + "?" + values.Encode(), nil)
	if err != nil {
		return err, ""
	}

	req.Header.Add("Accept", "application/vnd.haveibeenpwned.v2+json")
	req.Header.Add("User-Agent", "go-haveibeenpwned (HIBP golang API client) - https://github.com/infoassure/go-haveibeenpwned")

	res, err := client.Do(req)
	if err != nil {
		return err, ""
	}

	if err != nil {
		return err, ""
	}
	defer res.Body.Close()

	dec := json.NewDecoder(res.Body)
	if err = dec.Decode(result); err != nil {
		return err, ""
	}

	return nil, h.getResponseString(res.StatusCode, res.Status)
}

// Returns the API specific HTTP response descriptions
func (h *HibpClient) getResponseString(code int, desc string) string {
	switch (code) {
	case 400:
		return "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)"
	case 403:
		return "Forbidden — no user agent has been specified in the request"
	case 404:
		return "Not found — the account could not be found and has therefore not been pwned"
	case 429:
		return "Too many requests — the rate limit has been exceeded"
	default:
		return ""
	}
}

// ***** Public Methods ***********************************************************************************************+

func (h *HibpClient) BreachesForAccount(email string, domain string, truncateResponse bool) (err error, resp string, breaches *Breaches) {

	var p Parameters

	if  len(domain) > 0 {
		if len(p) == 0 {
			p = make(map[string]string)
		}
		p["domain"] = domain
	}

	if truncateResponse == true {
		if len(p) == 0 {
			p = make(map[string]string)
		}
		p["truncateResponse"] = "true"
	}

	breaches = &Breaches{}
	err, resp = h.getApiJson("breachedaccount/" + email, p, breaches)
	if err != nil {
		return err, resp, nil
	}

	return nil, resp, breaches
}

