package write

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/patrickhener/gonh/logger"
	"github.com/patrickhener/gonh/match"
	"github.com/patrickhener/gonh/nessus"
	"github.com/patrickhener/gonh/portscan"
	"github.com/patrickhener/gonh/query"
	"github.com/patrickhener/gonh/utils"
)

// Do will do it
func Do(temp string, outfilepath string, c *nessus.Collection) error {
	logger.Debugf("Template file: %s", temp)
	logger.Debugf("Outputfile: %s", outfilepath)
	template := ""

	// Vars
	matchedPlugins := make([]match.MatchedPlugin, 0)

	// Read in template file
	if _, err := os.Stat(temp); os.IsNotExist(err) {
		message := fmt.Sprintf("Template file '%s' does not exist. Exiting ...", temp)

		return errors.New(message)
	}

	absPath, err := filepath.Abs(temp)
	if err != nil {
		return err
	}

	// Define custom formatting
	inputHeaderHandle, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer inputHeaderHandle.Close()
	inputHeaderScanner := bufio.NewScanner(inputHeaderHandle)
	count := 0
	for count <= 0 {
		inputHeaderScanner.Scan()
		firstLine := inputHeaderScanner.Text()
		if strings.HasPrefix(firstLine, "%%%GONH:") {
			q := strings.TrimPrefix(firstLine, "%%%GONH:")
			switch {
			case strings.Contains(q, "list=") && !strings.Contains(q, "table="):
				// missing table
				return fmt.Errorf("%s", "You set the custom format header and missed to have table= in it")
			case !strings.Contains(q, "list=") && strings.Contains(q, "table="):
				// missing table
				return fmt.Errorf("%s", "You set the custom format header and missed to have list= in it")
			case strings.Contains(q, "list=") && strings.Contains(q, "table="):
				// both set
				template = q
			default:
			}
		}
		count++
	}
	inputHeaderHandle.Close()

	// Define input handler
	inputHandle, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer inputHandle.Close()
	inputScanner := bufio.NewScanner(inputHandle)

	// Define output handler
	outputHandle, err := os.Create(outfilepath)
	if err != nil {
		return err
	}
	defer outputHandle.Close()
	outputWriter := bufio.NewWriter(outputHandle)

	// Scan over line by line
	for inputScanner.Scan() {
		// Match the magic comment
		line := inputScanner.Text()
		// If match do query
		if strings.HasPrefix(line, "%%%GONH:") {
			// Substitute line with returned output
			q := strings.TrimPrefix(line, "%%%GONH:")
			var out string
			var mp []match.MatchedPlugin

			switch {
			case strings.Contains(q, "portscan"):
				out, err = portscan.Do(c, template, false)
				if err != nil {
					return err
				}
			default:
				mp, out, err = query.Do(q, c, template, false)
				if err != nil {
					return err
				}
				matchedPlugins = append(matchedPlugins, mp...)
			}

			line = out
		}

		// Write content
		_, err := outputWriter.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	// Flush writer
	if err := outputWriter.Flush(); err != nil {
		return err
	}

	logger.Infof("File %s has been written successfully", outfilepath)

	unmatched := pluginDiff(matchedPlugins, c.AllPlugins)

	if len(unmatched) > 0 {
		logger.Warn("Unmatched Plugins are:")
		for _, p := range unmatched {
			if p.Severity != "Non" && p.Severity != "Low" {
				fmt.Printf("%s:\t(%s)\t%s\n", p.ID, p.Severity, p.Name)
			}
		}
	}

	return nil
}

// pluginDiff will be used by write to make a diff of all plugins and the matched ones
// it will then return the sorted(sev) unmatched plugins to be rendered
func pluginDiff(matched []match.MatchedPlugin, all []nessus.Plugin) []nessus.Plugin {
	var unmatched []nessus.Plugin

	// Loop through all plugins
	for _, a := range all {
		found := false

		// Loop through matched once
		for _, m := range matched {
			if m.ID == a.ID {
				found = true

				break
			}
		}

		// If not found in matched a is unmatched and thus added to unmatched
		if !found {
			unmatched = append(unmatched, a)
		}
	}

	// Sort unmatched by severity
	sort.Slice(unmatched, func(i, j int) bool {
		iSev := utils.SevAtoi(unmatched[i].Severity)
		jSev := utils.SevAtoi(unmatched[j].Severity)

		return iSev > jSev
	})

	return unmatched
}
