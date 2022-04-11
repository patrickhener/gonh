package portscan

import (
	"github.com/patrickhener/gonh/nessus"
	"github.com/patrickhener/gonh/query"
)

/*
Nessus SYN scanner (ID: 11219)
Nessus UDP scanner (ID: 34277)
*/

// Do will do it
func Do(c *nessus.Collection, template string, stdout bool) (string, error) {
	q := "pluginid=11219,34277,10335"
	_, rstring, err := query.Do(q, c, template, stdout)

	return rstring, err
}
