package list

import (
	"fmt"
	"sort"

	"github.com/patrickhener/gonh/nessus"
	"github.com/patrickhener/gonh/utils"
)

func Do(c *nessus.Collection) {
	// make the collection Plugins unmatched
	var unmatched []nessus.Plugin

	unmatched = append(unmatched, c.AllPlugins...)
	// Sort unmatched by severity
	sort.Slice(unmatched, func(i, j int) bool {
		iSev := utils.SevAtoi(unmatched[i].Severity)
		jSev := utils.SevAtoi(unmatched[j].Severity)

		return iSev > jSev
	})

	// Just print them
	for _, p := range unmatched {
		fmt.Printf("%s:\t(%s)\t%s\n", p.ID, p.Severity, p.Name)
	}
}
