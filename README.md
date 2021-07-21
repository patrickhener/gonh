Go Nessus Helper

# Motivation

This tool was motivated by a tool I know and I used to use within my daily routine as a pentester. I reimplemented this tool using go as a coding language and tweaked it to my liking.

# Installation

All you need to do is either build it and use `gonh` from the root directory

```bash
git clone https://github.com/patrickhener/gonh
go build .
```

or you install it to your gopath like

```bash
go install .
```

Instead of cloning the repo you could also just do

```bash
go get -u github.com/patrickhener/gonh
go install github.com/patrickhener/gonh@latest
```
# Usage

Basically the usage page says it all

```bash
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

%%%GONH:<query>

Valid marker:

%%%GONH:pluginid=97994

You can use those marker like in the query function above:

%%%GONH:pluginname=PHP and sev>=med

You can also include the module portscan into the module write by using:

%%%GONH:portscan

Output Format:

Again you can define custom templates to be used as list and table if you provide a specific marker at the very first line of your template input file.

%%%%GONH:list=/path/to/list.tmpl,table=/path/to/table.tmpl

You will need to provide both, as the write module will substitute the content using the content-sensitive output.

Example:

gonh -mode write -in /my/project/nessus-files -t /my/project/template-file.md -out /my/outdir/output-file.md
```

# Templating

As described in the usage page you can provide custom templates to be used. `gonh` uses the go templating engine. As an example here are the two embedded templates.

**list.tmpl**
```go
{{ range .FindingLines }}- {{ .Host }}
{{ end }}
```

**table.tmpl**
```go
| Host | Port |
| --- | --- |
{{ range .FindingLines }}| {{ .Host }} | {{ .AffectedPorts }} |
{{ end }}
```

So as you can see it just loops over the input `FindingLines` and displays it either as a Markdown formatted list or table.

The input struct which is handed to the template looks like this:

```go
type TemplateInput struct {
	Header         match.Header
	MatchedPlugins []match.MatchedPlugin
	AllSamePorts   string
	FindingLines   []FindingLine
}
```

Header itself is

```go
type Header struct {
	Calltime string
	Query    string
}
```

Matched plugins is a slice containing the queries matched plugins in this format:

```go
type MatchedPlugin struct {
	ID       string
	Name     string
	Severity string
}
```

AllSamePorts will have a string like `80/tcp,443/tcp,8443/tcp` if the query results in all hosts having the same port(s).

FindingLines is of type:

```go
type FindingLine struct {
	Host          string
	AffectedPorts string
	Comment       string
}
```

Host is in format `ip (fqdn if resolved)`, AffectedPorts is in format `80/tcp, 443/tcp, 8443/tcp` and Comment will be in format `80/tcp:<pluginid>,<another-pluginid>|443/tcp:<pluginid>` for you to know where the finding came from.

This is an example for a more advanced template to be processed and output a table in LaTeX format:

```go
% All matched plugins
% ==================={{ range .MatchedPlugins }}
% {{ .ID }}: ({{ .Severity }}) {{ .Name }}{{ end }}
% {{ if eq .AllSamePorts ""}}{{ else }}
% Same Port(s) for all Systems:
% {{ .AllSamePorts }}{{ end }}
%
% Metadata
% ========
% Calltime: {{ .Header.Calltime }}
% Search: {{ .Header.Query }}

\begin{center}
 \begin{tabularx}{\linewidth{}}{ll}
 \textbf{IP-Address} & \textbf{Port} \\ \toprule
 \endhead
 \bottomrule
 \endfoot
 \bottomrule
 \endlastfoot
{{ range .FindingLines }}
{{ .Host }} & {{ .AffectedPorts }} \\ % {{ .Comment }}{{ end }}
 \end{tabularx}
\end{center}
```
