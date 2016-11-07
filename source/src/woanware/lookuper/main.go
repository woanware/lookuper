package main

import (
	"github.com/urfave/cli"
	"github.com/google/safebrowsing"
	util "github.com/woanware/goutil"
	_ "github.com/mattn/go-sqlite3"
	"github.com/go-gorp/gorp"
	"gopkg.in/yaml.v2"
	"database/sql"
	"os"
	"log"
	"strings"
	"regexp"
)

// ##### Variables ############################################################

var (
	dbMap 					*gorp.DbMap
	config  				*Config
	safeBrowsing			*safebrowsing.SafeBrowser
	regexTeStringMatch		*regexp.Regexp
	regexTeTitle			*regexp.Regexp
	regexTeSubmissionDate	*regexp.Regexp
	regexTeSeverity			*regexp.Regexp
)

// ##### Constants ############################################################

const APP_NAME string = "lookuper"
const APP_VERSION string = "0.0.7"
const DB_FILE_NAME string = "./lookuper.db"
const CONFIG_FILE_NAME string = "./lookuper.config"

// ##### Methods ##############################################################

// Entry point
func main() {

	app := cli.NewApp()
	app.Name = APP_NAME
	app.Usage = "Looks stuff up..."
	app.Version = APP_VERSION
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Mark Woan",
			Email: "markwoan@gmail.com",
		},
	}

	if util.DoesFileExist(DB_FILE_NAME) == false {
		if createDb() == false {
			return
		}
	}

	config = loadConfig()
	dbMap = initialiseDb()
	initialiseRegexes()
	setupCli(app)

	app.Run(os.Args)
}

// Main method for starting the work object
func run(dataType int, inputFile string, outputFile string, apiKeys []string) {
	w := NewWorker()
	w.Run(inputFile, outputFile, dataType, apiKeys, false)
}

// Creates the SQLite database
func createDb() bool {

	db, err := sql.Open("sqlite3", DB_FILE_NAME)
	if err != nil {
		log.Fatalf("Error opening database for schema creation: %v", err)
	}
	defer db.Close()

	for _, sql := range DATABASE_SQL_CREATES {
		_, err = db.Exec(sql)
		if err != nil {
			log.Printf("Error creating database table: %v (%s)", err, sql)
			return false
		}
	}

	for _, sql := range DATABASE_SQL_INDEXES {
		_, err = db.Exec(sql)
		if err != nil {
			log.Printf("Error creating database index: %v (%s)", err, sql)
			return false
		}
	}

	return true
}

// Initialises the database connection and the database table mappings for gorp
func initialiseDb() (*gorp.DbMap) {

	// Open the database connection and configure the "gorp" objects
	db, err := sql.Open("sqlite3", DB_FILE_NAME)
	if err != nil {
		log.Fatalf("Error opening database for initialisation: %v", err)
	}

	dbMap := &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	dbMap.AddTableWithName(Job{}, "job").SetKeys(true, "id")
	dbMap.AddTableWithName(Work{}, "work").SetKeys(false, "md5")
	dbMap.AddTableWithName(VtHash{}, "vt_hash").SetKeys(true, "id")
	dbMap.AddTableWithName(TeHash{}, "te_hash").SetKeys(true, "id")
	dbMap.AddTableWithName(TeString{}, "te_string").SetKeys(true, "id")
	dbMap.AddTableWithName(VtUrl{}, "vt_url").SetKeys(true, "id")
	dbMap.AddTableWithName(VtUrl{}, "vt_url").SetKeys(true, "id")
	dbMap.AddTableWithName(HaveIBeenPwned{}, "hibp").SetKeys(true, "id")
	dbMap.AddTableWithName(GoogleSafeBrowsing{}, "google_safe_browsing").SetKeys(true, "id")
	dbMap.AddTableWithName(VtIpResolution{}, "vt_ip_resolution").SetKeys(true, "id")
	dbMap.AddTableWithName(VtIpDetectedUrl{}, "vt_ip_detected_url").SetKeys(true, "id")
	dbMap.AddTableWithName(VtDomainResolution{}, "vt_domain_resolution").SetKeys(true, "id")
	dbMap.AddTableWithName(VtDomainDetectedUrl{}, "vt_domain_detected_url").SetKeys(true, "id")

	return dbMap
}

func initialiseRegexes() {
	// Define the regex to extract data from TE reports, which will aid performance when performing regexs later
	//w.regexTeStringMatch, _ = regexp.Compile(`a href="report.aspx\?md5=.*" target="_blank">`)
	regexTeStringMatch, _ = regexp.Compile(`Results\s.*?\sof\s([\d]*)`)
	regexTeTitle, _ = regexp.Compile(`<meta name="description" content="ThreatExpert Report: (.*)">`)
	regexTeSubmissionDate, _ = regexp.Compile(`<li>Submission received:\s(.*)</li>`)
	regexTeSeverity, _ = regexp.Compile(`<tr><td class="cell_1">(.*?)</td><td class="cell_2"><img src="./resources/level(.*?).gif"></td></tr>`)
}

// Initialises the safe browsing object and reloads the data
func initialiseSafeBrowsing(apiKey string) {
	var err error
	safeBrowsing, err = safebrowsing.NewSafeBrowser(safebrowsing.Config{
		APIKey: apiKey,
	})

	if err != nil {
		log.Fatalf("Error configuring Google Safe Browsing object: %v", err)
	}
}

// Loads the config file contents (yaml) and marshals to a struct
func loadConfig() (*Config) {
	c := new(Config)
	data, err := util.ReadTextFromFile(CONFIG_FILE_NAME)
	if err != nil {
		log.Fatalf("Error reading the config file: %v", err)
	}

	err = yaml.Unmarshal([]byte(data), &c)
	if err != nil {
		log.Fatalf("Error unmarshalling the config file: %v", err)
	}

	if c.MaxHashAge == 0 {
		c.MaxHashAge = 30
	}

	if c.Retries == 0 {
		c.Retries = 30
	}

	// The keywords are stored in a comma delimited string
	keywords := strings.Split(c.IgnoreKeywords, ",")
	for _, k := range keywords {
		temp := strings.TrimSpace(k)
		if len(temp) == 0 {
			continue
		}
		c.IgnoreKeywordsArray = append(c.IgnoreKeywordsArray, strings.ToLower(temp))
	}

	return c
}