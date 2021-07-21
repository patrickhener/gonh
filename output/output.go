package output

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/patrickhener/gonh/logger"
	"github.com/patrickhener/gonh/match"
)

const (
	elist  = "embeddedlist"
	etable = "embeddedtable"
)

//go:embed *.tmpl
var embeddedTemplates embed.FS

type TemplateInput struct {
	Header         match.Header
	MatchedPlugins []match.MatchedPlugin
	AllSamePorts   string
	FindingLines   []FindingLine
}

type FindingLine struct {
	Host          string
	AffectedPorts string
	Comment       string
}

func Print(matches match.Matches, template string) (string, error) {
	if matches.Collection.CountMatchedHosts > 0 {
		// Sort things
		matches.SortMatchedPlugins()
		// Fill the SortedKeys slice of matches
		matches.SortByIP()

		switch {
		case template != "":
			absPath, err := filepath.Abs(template)
			if err != nil {
				return "", err
			}
			if _, err := os.Stat(absPath); os.IsNotExist(err) {
				return "", fmt.Errorf("the requested template %s cannot be found: %w", template, err)
			}
			if _, err := printTemplate(matches, template, true); err != nil {
				return "", err
			}
		default:
			// "Content-Sensitive" Printing
			var temp string

			if matches.CheckAllSamePorts() {
				temp = elist
			} else {
				temp = etable
			}

			if _, err := printTemplate(matches, temp, true); err != nil {
				return "", err
			}
		}
	} else {
		logger.Warn("No Hosts matched the query")
	}

	return "", nil
}

func Fetch(matches match.Matches, template string) (string, error) {
	if matches.Collection.CountMatchedHosts > 0 {
		// Sort things
		matches.SortMatchedPlugins()
		// Fill the SortedKeys slice of matches
		matches.SortByIP()

		switch {
		case template != "":
			// This happens when write module hands in the template in form
			// list=/path/to/list.tmpl,table=/path/to/table.tmpl
			// Extract the paths to the custom templates
			var customlist, customtable string
			customtemp := strings.Split(template, ",")
			for _, t := range customtemp {
				switch {
				case strings.Split(t, "=")[0] == "list":
					customlist = strings.Split(t, "=")[1]
				case strings.Split(t, "=")[0] == "table":
					customtable = strings.Split(t, "=")[1]
				default:
				}
			}

			// check if both file exist
			listAbsPath, err := filepath.Abs(customlist)
			if err != nil {
				return "", err
			}

			tableAbsPath, err := filepath.Abs(customtable)
			if err != nil {
				return "", err
			}

			if _, err := os.Stat(listAbsPath); os.IsNotExist(err) {
				return "", fmt.Errorf("template %s does not exist: %w", customlist, err)
			}

			if _, err := os.Stat(tableAbsPath); os.IsNotExist(err) {
				return "", fmt.Errorf("template %s does not exist: %w", customlist, err)
			}

			if matches.CheckAllSamePorts() {
				template = listAbsPath
			} else {
				template = tableAbsPath
			}
		default:
			if matches.CheckAllSamePorts() {
				template = elist
			} else {
				template = etable
			}
		}

		rstring, err := printTemplate(matches, template, false)
		if err != nil {
			return "", err
		}

		return rstring, nil
	}

	return "%%%GONH: no hosts matched!!", nil
}

func printTemplate(matches match.Matches, temp string, stdout bool) (string, error) {
	var tpl bytes.Buffer

	input := TemplateInput{
		Header:         matches.Header,
		MatchedPlugins: matches.MatchedPlugins,
		FindingLines:   make([]FindingLine, 0),
	}

	if len(matches.AllSamePorts) > 0 {
		// Sort list of affected Ports
		for _, p := range matches.AllSamePorts {
			input.AllSamePorts += p + ", "
		}
		input.AllSamePorts = input.AllSamePorts[:len(input.AllSamePorts)-2]
	}

	for _, k := range matches.SortedKeys {
		var line FindingLine
		var ap []string

		// Conditional host string
		hostInMap := matches.Collection.Hosts[k.String()]
		var host string
		var comment string

		if hostInMap.FQDN != "" {
			host = fmt.Sprintf("%s (%s)", hostInMap.IP, hostInMap.FQDN)
		} else {
			host = hostInMap.IP
		}

		line.Host = host

		for i := range hostInMap.Findings {
			ap = append(ap, i)

			comment += i + ":"

			for _, fi := range hostInMap.Findings[i] {
				comment += fi.PluginID + ","
			}

			comment = comment[:len(comment)-1]
			comment += "|"
		}

		// Cut last character
		comment = comment[:len(comment)-1]
		line.Comment = comment

		// Sort list of affected Ports
		sort.Slice(ap, func(i, j int) bool {
			iPort, _ := strconv.Atoi(strings.Split(ap[i], "/")[0])
			jPort, _ := strconv.Atoi(strings.Split(ap[j], "/")[0])

			return iPort < jPort
		})

		for _, p := range ap {
			line.AffectedPorts += p + ", "
		}

		line.AffectedPorts = line.AffectedPorts[:len(line.AffectedPorts)-2]

		input.FindingLines = append(input.FindingLines, line)
	}

	var t *template.Template
	var err error

	switch temp {
	case elist:
		t, err = template.ParseFS(embeddedTemplates, "list.tmpl")
	case etable:
		t, err = template.ParseFS(embeddedTemplates, "table.tmpl")
	default:
		t, err = template.ParseFiles(temp)
	}
	if err != nil {
		return "", err
	}

	if err := t.Execute(&tpl, input); err != nil {
		return "", err
	}

	if stdout {
		_, err := fmt.Print(tpl.String())

		return "", err
	}

	return tpl.String(), nil
}
