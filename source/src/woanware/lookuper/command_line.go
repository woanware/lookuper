package main

import (
	"github.com/urfave/cli"
	"errors"
)

// ##### Methods #######################################################################################################

//
func setupCli(app *cli.App) {

	apiFlag := cli.StringFlag{
		Name: "api, a",
		Value: "",
		Usage: "API keys (VT orGoogle Safe Browsing). Multiple can be supplied e.g. comma separated",
	}

	inputFileFlag := cli.StringFlag{
		Name: "input, i",
		Value: "",
		Usage: "Input file containing data to be looked up",
	}

	outputDirFlag := cli.StringFlag{
		Name: "output, o",
		Value: "",
		Usage: "Output directory for the results",
	}

	privateKeyFlag := cli.BoolFlag{
		Name: "privatekey, p",
		Usage: "Are the API key(s) private?",
	}

	app.Commands = []cli.Command{
		{
			Name:    "resume",
			Usage:   "Resumes an existing process",
			Action:  func(c *cli.Context) error {

				err := checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				run(0, "", c.String("output"), []string{})
				return nil
			},
			Flags: []cli.Flag{
				outputDirFlag,
			},
		},
		{
			Name:    "clear",
			Usage:   "Clears the work queue",
			Action:  func(c *cli.Context) error {
				resetTables(true)
				return nil
			},
		},
		{
			Name:    "md5vt",
			Usage:   "Check MD5 hashes via VirusTotal",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return nil
				}

				err = checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				if len(config.VtApiKeys) > 0 {
					run(dataTypeMd5Vt, c.String("input"), c.String("output"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeMd5Vt, c.String("input"), c.String("output"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				outputDirFlag,
				apiFlag,
				privateKeyFlag,
			},
		},
		{
			Name:    "md5te",
			Usage:   "Check MD5 hashes via ThreatExpert",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return err
				}

				err = checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				run(dataTypeMd5Te, c.String("input"), c.String("output"), []string{FAKE_API_KEY})
				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				outputDirFlag,
			},
		},
		{
			Name:    "sha256vt",
			Usage:   "Check SHA256 hashes via VirusTotal",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return err
				}

				err = checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				if len(config.VtApiKeys) > 0 {
					run(dataTypeSha256Vt, c.String("input"), c.String("output"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeSha256Vt, c.String("input"), c.String("output"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				outputDirFlag,
				apiFlag,
				privateKeyFlag,
			},
		},
		{
			Name:    "ipvt",
			Usage:   "Check IP addresses via VirusTotal",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return err
				}

				err = checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				if len(config.VtApiKeys) > 0 {
					run(dataTypeIpVt, c.String("input"), c.String("output"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeIpVt, c.String("input"), c.String("output"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				outputDirFlag,
				apiFlag,
				privateKeyFlag,
			},
		},
		{
			Name:    "domainvt",
			Usage:   "Check domains via VirusTotal",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return err
				}

				err = checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				if len(config.VtApiKeys) > 0 {
					run(dataTypeDomainVt, c.String("input"), c.String("output"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeDomainVt, c.String("input"), c.String("output"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				outputDirFlag,
				apiFlag,
				privateKeyFlag,
			},
		},
		{
			Name:    "urlvt",
			Usage:   "Check URL's via VirusTotal",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return err
				}

				err = checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				if len(config.VtApiKeys) > 0 {
					run(dataTypeUrlVt, c.String("input"), c.String("output"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeUrlVt, c.String("input"), c.String("output"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				outputDirFlag,
				apiFlag,
				privateKeyFlag,
			},
		},
		{
			Name:    "stringte",
			Usage:   "Check strings via ThreatExpert",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return err
				}

				err = checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				run(dataTypeStringTe, c.String("input"), c.String("output"), []string{FAKE_API_KEY})
				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				outputDirFlag,
			},
		},
		{
			Name:    "gsb",
			Usage:   "Check Url's/Domains via Google Safe Browsing",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return err
				}

				err = checkOutputDirectory(c.String("output"))
				if err != nil {
					return err
				}

				if len(config.SafeBrowsingApiKey) > 0 {
					initialiseSafeBrowsing(config.SafeBrowsingApiKey)
					run(dataTypeGsb, c.String("input"), c.String("output"), []string{})
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}

					initialiseSafeBrowsing(apiKeys[0])
					run(dataTypeGsb, c.String("input"), c.String("output"), apiKeys)
				}
				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				outputDirFlag,
				apiFlag,
			},
		},
	}
}