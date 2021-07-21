package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/patrickhener/gonh/logger"
	"github.com/patrickhener/gonh/nessus"
	"github.com/patrickhener/gonh/portscan"
	"github.com/patrickhener/gonh/query"
	"github.com/patrickhener/gonh/write"
)

var (
	indir       string
	temp        string
	outfilepath string
	quer        string
	mode        string
	version     bool
)

const gonhVersion = "v0.0.1"

func Usage() {
	fmt.Printf(`
GoNessusHelper version: %s

Usage: gonh -mode [query|portscan|write] -in /path/to/nessus-files/(file.nessus)

There are 3 valid modes, which are query, portscan and write.

Query
=====
This mode will let you query different things in a collection of .nessus files and give you output like a table or a list.
It will print the results to standard out.

Use -q for a querystring like: -q pluginid=18763,19928,29931

Valid query words are:
  - ip
  - port
  - pluginid
  - pluginname
  - sev (non, low, med, hig, cri)

Those query words can also be combined with 'and' and 'or'. Also it can be negated by using 'not'. In addition severity can be used like: sev>=med.

Output Format:

The output format is somewhat content sensitive. So if ports of the matched hosts are not all the same, gonh will output a table. Otherwise it will output a list. For example if you query ssl and it matches hosts on port 443 and 8443 this will be a table.

If you want to overwrite what output format to use, you can do -t /path/to/template.file to use a custom template. For templating reference see README.md.
If you do not provide a custom template gonh will use an embedded one.

Examples:

gonh -mode query -in /my/project/nessus-files/specific-file.nessus -q "pluginname=ssl and port=443"
gonh -mode query -in /my/project/nessus-files -q "pluginid=15985,25216,100464 or pluginname="samba" and sev>=hig or pluginname=samba and not sev=non"
gonh -mode query -in /my/project/nessus-files -q "pluginid=12345" -t mycustom.tmpl


Portscan
========
Portscan will display all scanned and identified ports as table. It is more or less a shortcut to '-mode query -q "pluginid=11219,34277"'. It can also take a custom table template via -t /path/to/custom/table.file.

Examples:

gonh -mode portscan -in /my/project/nessus-files

Write
=====
Write will take in a predefined template file and will substitute special 'markers' with the output of the corresponding query.

Use -t to define a /path/to/template.file and -out /path/to/output.file as an output file.
This module will also show you which plugins are not matched (processed) by your template. It will only show everything with the severity of Medium to Critical.
None and Low will be omitted.

The template has to have a 'marker' following a query in it to be able to substitute with content. This marker looks like this:

%%%%%%GONH:<query>

Valid marker:

%%%%%%GONH:pluginid=97994

You can use those marker like in the query function above:

%%%%%%GONH:pluginname=PHP and sev>=med

You can also include the module portscan into the module write by using:

%%%%%%GONH:portscan

Output Format:

Again you can define custom templates to be used as list and table if you provide a specific marker at the very first line of your template input file.

%%%%%%GONH:list=/path/to/list.tmpl,table=/path/to/table.tmpl

You will need to provide both, as the write module will substitute the content using the content-sensitive output.

Example:

gonh -mode write -in /my/project/nessus-files -t /my/project/template-file.md -out /my/outdir/output-file.md

`, gonhVersion)
}

func fetchNDC(indir string) *nessus.Collection {
	logger.Infof("Parsing nessus file(s) in %s", indir)
	ndc, err := nessus.Parse(indir)
	if err != nil {
		logger.Panicf("There was an error parsing the nessus file(s): %s", err)
	}

	return ndc
}

func main() {
	flag.StringVar(&indir, "in", indir, "")
	flag.StringVar(&temp, "t", temp, "")
	flag.StringVar(&outfilepath, "out", outfilepath, "")
	flag.StringVar(&quer, "q", quer, "")
	flag.StringVar(&mode, "mode", mode, "")
	flag.BoolVar(&version, "version", false, "")

	flag.Usage = Usage

	flag.Parse()

	if version {
		fmt.Printf("GoNessusHelper version: %s\n", gonhVersion)
		os.Exit(0)
	}

	if mode == "" || indir == "" {
		fmt.Println("ERROR: You need to choose <mode> and <in>")
		Usage()
		os.Exit(0)
	}

	// Convert to lowercase, just in case
	mode = strings.ToLower(mode)

	switch mode {
	case "query":
		if quer == "" {
			fmt.Println("ERROR: When using query mode you need to provide a search query with -q \"<some-query>\"")
			Usage()
			os.Exit(1)
		}
		c := fetchNDC(indir)

		if _, _, err := query.Do(quer, c, temp, true); err != nil {
			logger.Panicf("There was an error running the query: %s", err)
		}
	case "write":
		if temp == "" || outfilepath == "" {
			fmt.Println("ERROR: When using write mode you need to provide a template file to read (-t) and an output file to write to (-out)")
			Usage()
			os.Exit(1)
		}
		c := fetchNDC(indir)

		if err := write.Do(temp, outfilepath, c); err != nil {
			logger.Panicf("There was an error running the write module: %s", err)
		}
	case "portscan":
		c := fetchNDC(indir)

		if _, err := portscan.Do(c, temp, true); err != nil {
			logger.Panicf("There was an error running the portscan module: %s", err)
		}
	default:
		Usage()
	}
}
