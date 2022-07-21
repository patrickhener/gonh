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
	// added 'and not port=0 to prevent from 0/udp in list'
	q := "pluginid=11219,34277,10335 and not port=0"
	_, rstring, err := query.Do(q, c, template, stdout)

	return rstring, err
}
