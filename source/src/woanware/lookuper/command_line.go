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

	privateKeyFlag := cli.BoolFlag{
		Name: "privatekey, p",
		Usage: "Are the API key(s) private?",
	}

	//app.Action = func(c *cli.Context) error {
	//	err := checkInputFile(c.String("input"))
	//	if err != nil {
	//		return err
	//	}
	//
	//	inputFile = c.String("input")
	//
	//	return nil
	//}

	app.Commands = []cli.Command{
		{
			Name:    "clear",
			Usage:   "Clears the work queue",
			Action:  func(c *cli.Context) error {
				clearWorkTable()
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

				if len(config.VtApiKeys) > 0 {
					run(dataTypeMd5Vt, c.String("input"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeMd5Vt, c.String("input"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
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

				run(dataTypeMd5Te, c.String("api"), []string{})
				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
			},
		},
		{
			Name:    "md5all",
			Usage:   "Check MD5 hashes via ThreatExpert and VirusTotal",
			Action:  func(c *cli.Context) error {

				err := checkInputFile(c.String("input"))
				if err != nil {
					return err
				}

				if len(config.VtApiKeys) > 0 {
					run(dataTypeMd5Vt, c.String("api"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeMd5All, c.String("api"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				apiFlag,
				privateKeyFlag,
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

				if len(config.VtApiKeys) > 0 {
					run(dataTypeMd5Vt, c.String("api"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeSha256Vt, c.String("api"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
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

				if len(config.VtApiKeys) > 0 {
					run(dataTypeMd5Vt, c.String("api"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeIpVt, c.String("api"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
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

				if len(config.VtApiKeys) > 0 {
					run(dataTypeMd5Vt, c.String("api"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeDomainVt, c.String("api"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
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

				if len(config.VtApiKeys) > 0 {
					run(dataTypeMd5Vt, c.String("api"), config.VtApiKeys)
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}
					run(dataTypeUrlVt, c.String("api"), apiKeys)
				}

				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
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

				run(dataTypeStringTe, c.String("api"), []string{})
				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
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

				if len(config.SafeBrowsingApiKey) > 0 {
					initialiseSafeBrowsing(config.SafeBrowsingApiKey)
					run(dataTypeGsb, c.String("api"), []string{})
				} else {
					success, apiKeys := getApiKeys(c.String("api"))
					if success == false {
						return errors.New("No API keys supplied")
					}

					initialiseSafeBrowsing(apiKeys[0])
					run(dataTypeGsb, c.String("api"), apiKeys)
				}
				return nil
			},
			Flags: []cli.Flag{
				inputFileFlag,
				apiFlag,
			},
		},
	}
}