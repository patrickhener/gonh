package query

import (
	"strings"
	"time"

	"github.com/patrickhener/gonh/logger"
	"github.com/patrickhener/gonh/match"
	"github.com/patrickhener/gonh/nessus"
	"github.com/patrickhener/gonh/output"
)

// Do will do it
func Do(searchquery string, c *nessus.Collection, template string, stdout bool) ([]match.MatchedPlugin, string, error) {
	var matches match.Matches = match.Matches{
		MatchedPlugins: make([]match.MatchedPlugin, 0),
		Header: match.Header{
			Calltime: time.Now().Format("2006-01-02 15:04:05"),
			Query:    searchquery,
		},
		Collection: nessus.Collection{
			Hosts: make(map[string]nessus.ReportHost),
		},
		AllSamePorts: make([]string, 0),
	}

	var orSplit []string
	andSplit := make(map[int][]string)

	orSplit = strings.Split(searchquery, " or ")

	for i, or := range orSplit {
		logger.Debugf("OR-Condition #%d: %s", i+1, or)

		split := []string{}

		for j, and := range strings.Split(or, " and ") {
			split = append(split, and)
			logger.Debugf("AND-Condition #%d: %s", j+1, and)
		}

		andSplit[i] = split
		logger.Debugf("AND-Slice: %+v", andSplit[i])
	}

	for _, host := range c.Hosts {
		for portIndex, p := range host.Findings {
			for _, f := range p {
				// One "or" statement needs to be true to add the match to the result list
				orResult := false

				for i := range orSplit {
					andResult := true

					// Loop over single condition and see if it is true
					for _, cond := range andSplit[i] {
						// Only when every condition matches the 'and'-statement
						// it will be true

						// Check if the condition starts with not_
						switch {
						case strings.HasPrefix(cond, "not "):
							// strip not_ from condition to make matchers work again
							cond = strings.TrimPrefix(cond, "not ")
							// if it matches its a negative (cause of not_)
							if match.Process(cond, f, portIndex, host.IP) {
								andResult = false

								break
							}
						default:
							// if it not matches its a negative (no not_)
							if !match.Process(cond, f, portIndex, host.IP) {
								andResult = false

								break
							}
						}
					}

					if andResult {
						orResult = true

						break
					}
				}

				// Only if one or statement (with or without inner and matches it will be added to matched)
				if orResult {
					// Add Host and Finding
					matches.AddHostAndFinding(host, portIndex, f)

					// Add Plugin to matched plugins if not exist
					matches.AddToMatchedPlugins(f)
				}
			}
		}
	}

	hostCount := 0
	portCount := 0
	findingCount := 0

	for _, h := range matches.Collection.Hosts {
		hostCount++

		for p := range h.Findings {
			portCount++
			findingCount += len(h.Findings[p])
		}
	}

	matches.Collection.CountMatchedHosts = hostCount
	matches.Collection.CountMatchedPorts = portCount
	matches.Collection.CountMatchedFindings = findingCount

	logger.Debugf("There has been %d matched hosts", hostCount)
	logger.Debugf("There has been %d matched ports", portCount)
	logger.Debugf("These ports findings sum up to a total of %d", findingCount)

	if stdout {
		rstring, err := output.Print(matches, template)

		return matches.MatchedPlugins, rstring, err
	}

	rstring, err := output.Fetch(matches, template)

	return matches.MatchedPlugins, rstring, err
}
