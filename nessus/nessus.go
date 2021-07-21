package nessus

import (
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/antchfx/xmlquery"
	"github.com/patrickhener/gonh/logger"
	"github.com/patrickhener/gonh/utils"
)

// Collection is a map which maps an IP to an associated Report host.
type Collection struct {
	Hosts                map[string]ReportHost
	CountMatchedHosts    int
	CountMatchedPorts    int
	CountMatchedFindings int
	AllPlugins           []Plugin
}

// ReportHost represents a single scanned IP with FQDN
// It has a map which associates a Port (tcp/445) to a slice of findings.
type ReportHost struct {
	IP       string
	FQDN     string
	Findings map[string][]Finding
}

// Port represents a port.
type Port struct {
	Number   string
	Protocol string
}

// Finding represents a finding
type Finding struct {
	PluginID    string
	PluginName  string
	Severity    string
	Description string
	Output      string
}

// Plugin will hold data of a single plugin
type Plugin struct {
	ID       string
	Name     string
	Severity string
}

// Parse will walk through a dir or a file and process (dir: all .nessus files)
// ReportHosts with their associated data will be assigned to a collections map
// The Collection will be returned so it can be worked on
func Parse(in string) (*Collection, error) {
	c := Collection{
		Hosts: make(map[string]ReportHost),
	}

	// Check Directory exists
	info, err := os.Stat(in)

	if os.IsNotExist(err) {
		message := fmt.Sprintf("Directory '%s' does not exist. Exiting ...", in)

		return &Collection{}, errors.New(message)
	}

	// Treat as dir
	if info.IsDir() {
		// Walk through and parse every .nessus file
		absPath, err := filepath.Abs(in)
		if err != nil {
			return nil, err
		}
		logger.Debugf("Absolute path to walk is: %s", absPath)
		err = filepath.WalkDir(absPath, func(path string, d fs.DirEntry, err error) error {
			// Parse every file to NessusData and add it to the NessusDataCollection
			// But only if item is not a directory and has extension 'nessus'
			if !d.IsDir() && d.Name()[len(d.Name())-6:] == "nessus" {
				file := filepath.Join(absPath, d.Name())

				if err := processFile(file, &c); err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil {
			return nil, err
		}
	} else {
		// Process single file
		absPath, err := filepath.Abs(in)
		if err != nil {
			return nil, err
		}

		logger.Debugf("File to process is: %s", absPath)

		if err := processFile(in, &c); err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// processFile handles a single file processing and is used by Parse
func processFile(processFile string, c *Collection) error {
	logger.Debugf("Processing file: %s", processFile)

	// read in the nessus file as string
	b, _ := ioutil.ReadFile(processFile)
	content := string(b)

	// Parse the nessus file
	doc, err := xmlquery.Parse(strings.NewReader(content))
	if err != nil {
		return err
	}

	// Base of the nessus file
	root := xmlquery.FindOne(doc, "//NessusClientData_v2")

	// All report hosts within the nessus file
	reportHosts := xmlquery.Find(root, "//ReportHost")
	// Count parsed report hosts and items
	rhCount := 0
	riCount := 0
	ufCount := 0

	// Iterate over all available hosts
	for _, r := range reportHosts {
		var reporthost ReportHost
		// Check map by ip
		ip := r.SelectAttr("name")

		if _, ok := c.Hosts[ip]; ok {
			// Assign existing report host
			reporthost = c.Hosts[ip]
		} else {
			// Craft report host
			reporthost = ReportHost{
				IP:       r.SelectAttr("name"),
				Findings: make(map[string][]Finding),
			}
		}

		for _, i := range xmlquery.Find(r, "//ReportItem") {
			port := Port{
				Number:   i.SelectAttr("port"),
				Protocol: i.SelectAttr("protocol"),
			}
			finding := Finding{
				PluginID:    i.SelectAttr("pluginID"),
				PluginName:  i.SelectAttr("pluginName"),
				Severity:    i.SelectAttr("severity"),
				Description: xmlquery.FindOne(i, "//description").InnerText(),
			}

			if output := i.SelectElement("//plugin_output"); output != nil {
				finding.Output = output.InnerText()
			}

			// Keep track of all seen plugins (uniquely)
			added := false

			if c.AllPlugins, added = checkAndAddPlugin(c.AllPlugins, Plugin{
				ID:       i.SelectAttr("pluginID"),
				Name:     i.SelectAttr("pluginName"),
				Severity: i.SelectAttr("severity"),
			}); added {
				ufCount++
			}

			// construct key of findings map to be 80/tcp for example
			key := fmt.Sprintf("%s/%s", port.Number, port.Protocol)
			// Add finding to map
			reporthost.Findings[key] = append(reporthost.Findings[key], finding)
			riCount++
		}

		// try resolving the FQDN and add it
		reporthost.FQDN = resolveNameFromItem(reporthost)

		// Assign reporthost to collections map
		c.Hosts[reporthost.IP] = reporthost
		rhCount++
	}

	logger.Infof("Parsed %d report hosts in file %s\n", rhCount, processFile)
	logger.Infof("Parsed %d report items\n", riCount)
	logger.Infof("%d unique plugins has been parsed\n", ufCount)

	return nil
}

// checkAndAddPlugin will add plugins to a list (uniquely) to be referenced as all seen plugins throughout scan
func checkAndAddPlugin(plugins []Plugin, pluginToAdd Plugin) ([]Plugin, bool) {
	for _, p := range plugins {
		if p.ID == pluginToAdd.ID {
			return plugins, false
		}
	}

	plugins = append(plugins, Plugin{
		ID:       pluginToAdd.ID,
		Name:     pluginToAdd.Name,
		Severity: utils.SevSItoa(pluginToAdd.Severity),
	})

	return plugins, true
}

// Collection will hold a preprocessed collection of all findings with associated data
// ResolveNameFromItem will try and lookup the name of the system by plugin ids:
// 12053 (Host Fully Qualified Domain Name (FQDN) Resolution)
// 10150 (Windows NetBIOS / SMB Remote Host Information Disclosure)
// 42410 (Microsoft Windows NTLMSSP Authentication Request Remote Network Name Disclosure)
// 53513 (Link-Local Multicast Name Resolution (LLMNR) Detection)
// 55472 (Device Hostname)
func resolveNameFromItem(host ReportHost) string {
	// Prefer 12053 before all other pluginIDs
	if hostHasPluginID("12053", host) {
		// Handle FQDN here
		for _, findings := range host.Findings {
			for _, f := range findings {
				if f.PluginID == "12053" {
					return parse12053(f.Output)
				}
			}
		}
	}

	// Otherwise switch over the left plugin IDs
	for _, findings := range host.Findings {
		for _, f := range findings {
			switch f.PluginID {
			case "10150":
				return parse10150(f.Output)
			case "42410":
				return parse42410(f.Output)
			case "53513":
				return parse53513(f.Output)
			case "55472":
				return parse55472(f.Output)
			default:
			}
		}
	}

	return ""
}

// hostHasPluginID checks in the collection if a host has a specific id
// It is used by resolveNameFromItem to prefer ID 12053 for fqdn resolution of hosts ip
func hostHasPluginID(id string, host ReportHost) bool {
	for _, findings := range host.Findings {
		for _, f := range findings {
			if f.PluginID == id {
				return true
			}
		}
	}

	return false
}

/* Different ip to name resolution functions based on pluginid */
func parse12053(output string) string {
	desc := strings.TrimSuffix(output, "\n")
	// Regex the last word, which is actually the fqdn
	// Example: 10.0.16.20 resolves as SOMEBACKUPSERVER.contoso.com.
	re := regexp.MustCompile(`(?m)\S+(?:\s+\S+){0}$`)
	tempName := re.FindString(desc)

	// omit last . in resolution
	return tempName[:len(tempName)-1]
}

func parse10150(output string) string {
	desc := strings.TrimSuffix(output, "\n")
	// Regex to find lines with = in the middle and grab all before and 2 words after
	/* Example:
	The following 3 NetBIOS names have been gathered :

	HOSTNAME         = Computer name
	CONTOSO          = Workgroup / Domain name
	HOSTNAME         = File Server Service*/
	re := regexp.MustCompile(`\S*[ ]*=\S*(?:\s\S+){2}`)
	match := re.FindString(desc)
	// match will be line: 	`HOSTNAME         = Computer name`
	tempName := strings.Split(match, " ")

	// First Split item will be bare hostname
	return tempName[0]
}

func parse42410(output string) string {
	desc := strings.TrimSuffix(output, "\n")
	// Regex to find lines with = in the middle and grab all before and 2 words after
	// Example:
	/* Zhe following 2 NetBIOS names have been gathered :

	HOSTNAME         = Computer name
	CONTOSO          = Workgroup / Domain name*/
	re := regexp.MustCompile(`\S*[ ]*=\S*(?:\s\S+){2}`)
	match := re.FindString(desc)
	// match will be line: 	`HOSTNAME         = Computer name`
	tempName := strings.Split(match, " ")

	// First Split item will be bare hostname
	return tempName[0]
}

func parse55472(output string) string {
	desc := strings.TrimSuffix(output, "\n")
	// Remove all whitespaces to make regex easier
	desc = strings.ReplaceAll(desc, " ", "")
	// Regex to find line with hostname:HOSTNAME
	/* Example:
	Hostname:HOSTNAME
	HOSTNAME(WMI)*/
	re := regexp.MustCompile(`\W*\w*:(\W*\w*).*`)
	match := re.FindString(desc)
	// Split by : and return second index
	split := strings.Split(match, ":")

	return split[1]
}

func parse53513(output string) string {
	desc := strings.TrimSuffix(output, "\n")
	fmt.Println(desc)
	// Regex will find anything between ' ... '
	// Example: According to LLMNR, the name of the remote host is 'Hostname'.
	re := regexp.MustCompile(`'(.*)'`)
	match := re.FindString(desc)

	return strings.ReplaceAll(match, "'", "")
}

/* END: Different ip to name resolution functions based on pluginid */
