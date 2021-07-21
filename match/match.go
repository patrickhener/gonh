package match

import (
	"bytes"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/patrickhener/gonh/nessus"
	"github.com/patrickhener/gonh/utils"
)

// Matches will hold different matches when a query has ran
type Matches struct {
	Header         Header
	MatchedPlugins []MatchedPlugin
	Collection     nessus.Collection
	SortedKeys     []net.IP
	AllSamePorts   []string
}

// MatchedPlugin will hold a single matched plugins information
// This is for formated output later on
type MatchedPlugin struct {
	ID       string
	Name     string
	Severity string
}

type Header struct {
	Calltime string
	Query    string
}

// AddToMatchedPlugins will add up matched plugins through out a query run
func (m *Matches) AddToMatchedPlugins(f nessus.Finding) {
	for _, p := range m.MatchedPlugins {
		if f.PluginID == p.ID {
			return
		}
	}

	m.MatchedPlugins = append(m.MatchedPlugins, MatchedPlugin{
		ID:       f.PluginID,
		Name:     f.PluginName,
		Severity: utils.SevSItoa(f.Severity),
	})
}

// SortMatchedPlugins will sort by Severity
func (m *Matches) SortMatchedPlugins() {
	sort.Slice(m.MatchedPlugins, func(i, j int) bool {
		iSev := utils.SevAtoi(m.MatchedPlugins[i].Severity)
		jSev := utils.SevAtoi(m.MatchedPlugins[j].Severity)

		return iSev > jSev
	})
}

// SortByIP will sort the collections map[string(ip)]ReportHost by key, thus by IP
// This function should be used before outputting (Writing/Printing) the collection
// The function adds to Matches the sorted keys as []net.IP slice to iterate over
func (m *Matches) SortByIP() {
	realIPs := make([]net.IP, 0, len(m.Collection.Hosts))

	for ip := range m.Collection.Hosts {
		realIPs = append(realIPs, net.ParseIP(ip))
	}

	sort.Slice(realIPs, func(i, j int) bool {
		return bytes.Compare(realIPs[i], realIPs[j]) < 0
	})

	m.SortedKeys = realIPs
}

// AddHostAndFinding will create host if not there and then add the finding, otherwise find host and add finding
func (m *Matches) AddHostAndFinding(h nessus.ReportHost, p string, f nessus.Finding) {
	var reporthost nessus.ReportHost

	// Check map by ip
	if _, ok := m.Collection.Hosts[h.IP]; ok {
		// Assign existing report host
		reporthost = m.Collection.Hosts[h.IP]
	} else {
		// Craft report host
		reporthost = nessus.ReportHost{
			IP:       h.IP,
			FQDN:     h.FQDN,
			Findings: make(map[string][]nessus.Finding),
		}
	}

	if _, ok := reporthost.Findings[p]; !ok {
		reporthost.Findings[p] = make([]nessus.Finding, 0)
		reporthost.Findings[p] = append(reporthost.Findings[p], f)
	} else {
		reporthost.Findings[p] = append(reporthost.Findings[p], f)
	}

	// Assign reporthost to collections map
	m.Collection.Hosts[reporthost.IP] = reporthost
}

// CheckAllSamePorts will return true if all matched hosts have the same affected Ports
func (m *Matches) CheckAllSamePorts() bool {
	// First define a reference from first item of Collection.Hosts
	referenceHost := m.Collection.Hosts[m.SortedKeys[0].String()]
	var referenceAffectedPorts []string

	for p := range referenceHost.Findings {
		referenceAffectedPorts = append(referenceAffectedPorts, p)
	}

	// Sort list of affected Ports
	sort.Slice(referenceAffectedPorts, func(i, j int) bool {
		iPort, _ := strconv.Atoi(strings.Split(referenceAffectedPorts[i], "/")[0])
		jPort, _ := strconv.Atoi(strings.Split(referenceAffectedPorts[j], "/")[0])

		return iPort < jPort
	})

	var referenceAffectedPortsString string

	for _, p := range referenceAffectedPorts {
		referenceAffectedPortsString += p
	}

	// Now that we have a reference string we need to do the above transformation to every host
	// Then compare if it is the same, if not return false, otherwise return true
	for _, k := range m.SortedKeys {
		var ap []string
		hostInMap := m.Collection.Hosts[k.String()]

		for i := range hostInMap.Findings {
			ap = append(ap, i)
		}

		// Sort list of affected Ports
		sort.Slice(ap, func(i, j int) bool {
			iPort, _ := strconv.Atoi(strings.Split(ap[i], "/")[0])
			jPort, _ := strconv.Atoi(strings.Split(ap[j], "/")[0])

			return iPort < jPort
		})

		var compareAP string

		for _, p := range ap {
			compareAP += p
		}

		if referenceAffectedPortsString != compareAP {
			return false
		}
	}

	m.AllSamePorts = referenceAffectedPorts

	return true
}

// Process will dispatch the condition to its corresponding method
// It will also finally return the result
func Process(cond string, item nessus.Finding, portkey string, ip string) bool {
	// First check if >= or <= in cond string
	// For now only sev uses those, could be cvss base score in future
	// Then there would be the need to implement a switch case in every
	// inner if statement as well
	switch {
	case strings.Contains(cond, "<="):
		selector := strings.ToLower(strings.Split(cond, "<=")[1])

		return SevIsLessEqual(selector, item)
	case strings.Contains(cond, ">="):
		selector := strings.ToLower(strings.Split(cond, ">=")[1])

		return SevIsGreaterEqual(selector, item)
	case strings.Contains(cond, "<"):
		selector := strings.ToLower(strings.Split(cond, "<")[1])

		return SevIsLessThan(selector, item)
	case strings.Contains(cond, ">"):
		selector := strings.ToLower(strings.Split(cond, ">")[1])

		return SevIsGreaterThan(selector, item)
	default:
	}
	// Split by =
	querystring := strings.ToLower(strings.Split(cond, "=")[0])
	selector := strings.ToLower(strings.Split(cond, "=")[1])

	switch querystring {
	case "pluginid":
		return HasPluginID(strings.Split(selector, ","), item)
	case "pluginname":
		return HasPluginName(strings.Split(selector, ","), item)
	case "sev":
		return SevIsExactly(selector, item)
	case "port":
		return IsPort(strings.Split(selector, ","), strings.Split(portkey, "/")[0])
	case "ip":
		return IsIP(strings.Split(selector, ","), ip)
	default:
		return false
	}
}

// IsIP will return true if the items host matches the given IP
func IsIP(ips []string, ip string) bool {
	for _, i := range ips {
		if i == ip {
			return true
		}
	}

	return false
}

// IsPort will return true if the item matches the given port
func IsPort(ports []string, port string) bool {
	for _, p := range ports {
		if port == p {
			return true
		}
	}

	return false
}

// HasPluginID will return true if it matches a pluginID
func HasPluginID(ids []string, item nessus.Finding) bool {
	for _, i := range ids {
		if item.PluginID == i {
			return true
		}
	}

	return false
}

// HasPluginName will return true if it matches a pluginName
func HasPluginName(names []string, item nessus.Finding) bool {
	for _, n := range names {
		if strings.Contains(strings.ToLower(item.PluginName), strings.ToLower(n)) {
			return true
		}
	}

	return false
}

// SevIsLessEqual will return true if the severity is less or equal to provided
func SevIsLessEqual(sev string, item nessus.Finding) bool {
	isev, _ := strconv.Atoi(item.Severity)

	return isev <= utils.SevAtoi(sev)
}

// SevIsLessThan will return true if the severity is less than provided
func SevIsLessThan(sev string, item nessus.Finding) bool {
	isev, _ := strconv.Atoi(item.Severity)

	return isev < utils.SevAtoi(sev)
}

// SevIsGreaterEqual will return true if the severity is greater or equal to provided
func SevIsGreaterEqual(sev string, item nessus.Finding) bool {
	isev, _ := strconv.Atoi(item.Severity)

	return isev >= utils.SevAtoi(sev)
}

// SevIsGreaterThan will return true if the severity is greater than provided
func SevIsGreaterThan(sev string, item nessus.Finding) bool {
	isev, _ := strconv.Atoi(item.Severity)

	return isev > utils.SevAtoi(sev)
}

// SevIsExactly will return true if the severity is exactly the provided
func SevIsExactly(sev string, item nessus.Finding) bool {
	isev, _ := strconv.Atoi(item.Severity)

	return isev == utils.SevAtoi(sev)
}
