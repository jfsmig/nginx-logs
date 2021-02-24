// Copyright (C) 2020-2021 nlogx's AUTHORS
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
)

const (
	MinColumns     = 145
	DefaultColumns = 200
)

const (
	stepBegin   = iota
	stepBare    = iota
	stepQuote   = iota
	stepBracket = iota
)

type RawRecord struct {
	ip       string
	when     string
	req      string
	code     string
	referrer string
	agent    string
}

type Record struct {
	Ip   string `json:"src"`
	When int64  `json:"t"`

	Method  string `json:"method"`
	Path    string `json:"path"`
	Version int    `json:"version"`

	Code     int    `json:"status"`
	Referrer string `json:"referrer"`
	Agent    string `json:"agent"`
}

var Logger = zerolog.
	New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
	With().Timestamp().Logger()

var avoidedAgents = []string{
	"^Apache-HttpClient",
	"Analyzer",
	"Bing",
	"Bot",
	"Crawler",
	"^Embarcadero",
	"Go",
	"Google Favicon",
	"HeadlessChrome",
	"IDBTE4M",
	"^Java",
	"Jigsaw",
	"NetSystemsResearch",
	"NetcraftSurveyAgent",
	"^Nuclei",
	"Python",
	"Qwant",
	"RestSharp",
	"Scanner",
	"^SMRF",
	"Screaming",
	"^Scrapy",
	"Spider",
	"^TBI-HttpOpenPlugi",
	"Twingly",
	"Validator",
	"^W3C_Unicorn",
	"^adreview",
	"^axios",
	"baidu",
	"bot",
	"^colly",
	"cortex",
	"crawler",
	"curl",
	"evc-batch",
	"facebookextern",
	"^http",
	"^github-camo",
	"jsonws",
	"lighthouse",
	"phpmyadmin",
	"phpunit",
	"python-requests",
	"solr",
	"spider",
	"webtech",
	"xpanse",
}

var avoidedAddresses = []string{
	// Whitelist
	"127.0.0.1",      // localhost for testing purposes
	"91.173.184.121", // jfs adsl free
	"92.158.80.82",   // jfs fibre orange
	// Blacklist
}

var avoidedReferrer = []string{
	"51.38.234.78",
}

var versionToCode = map[string]int{
	"HTTP/0.9": 0,
	"HTTP/1.0": 0,
	"HTTP/1.1": 1,
	"HTTP/2.0": 2,
}

var errMalformedQuery = errors.New("Invalid query")

type SieveFilter func(r Record) bool

func expandRecords(src <-chan RawRecord) <-chan Record {
	out := make(chan Record, 64)
	go func() {
		defer close(out)
		for r0 := range src {
			c64, err := strconv.ParseInt(r0.code, 10, 32)
			if err != nil {
				Logger.Debug().Str("code", r0.code).Err(err).Msg("Invalid status")
				continue
			}
			method, selector, version, err := parseQuery(r0.req)
			if err != nil {
				Logger.Debug().Str("query", r0.req).Err(err).Msg("Invalid query")
				continue
			}
			when, err := parseDate(r0.when)
			if err != nil {
				Logger.Debug().Str("date", r0.when).Err(err).Msg("Invalid date")
				continue
			}
			out <- Record{
				Ip:       r0.ip,
				When:     when,
				Method:   method,
				Path:     selector,
				Version:  version,
				Code:     int(c64),
				Referrer: r0.referrer,
				Agent:    r0.agent,
			}
		}
	}()
	return out
}

func parseRecords(src io.Reader) <-chan RawRecord {
	out := make(chan RawRecord, 64)
	go func() {
		defer close(out)
		in := bufio.NewReader(src)
		step := stepBegin
		token := strings.Builder{}
		line := make([]string, 0)

		_eol := func() {
			if len(line) != 9 {
				return
			}
			ip := line[0]
			agent := line[8]
			out <- RawRecord{
				ip:       ip,
				when:     line[3],
				req:      line[4],
				code:     line[5],
				referrer: line[7],
				agent:    agent,
			}
		}
		endOfLine := func() {
			// jfs: using "defer" has a cost that I would avoid if called as often as
			// each line of input flowing through the process
			_eol()
			line = line[:0]
		}
		endOfToken := func() {
			line = append(line, token.String())
			token.Reset()
		}

		for {
			r, _, err := in.ReadRune()
			if err != nil {
				if token.Len() > 0 {
					endOfToken()
				}
				endOfLine()
				if err == io.EOF {
					return
				} else {
					Logger.Fatal().Err(err).Msg("Read error")
					return
				}
			}
			switch step {
			case stepBegin:
				switch r {
				case ' ': // Nothing
				case '[':
					step = stepBracket
				case '"':
					step = stepQuote
				case '\n':
					endOfLine()
				default:
					token.WriteRune(r)
					step = stepBare
				}
			case stepBare:
				switch r {
				case ' ':
					endOfToken()
					step = stepBegin
				case '\n':
					endOfToken()
					endOfLine()
					step = stepBegin
				default:
					token.WriteRune(r)
				}
			case stepQuote:
				switch r {
				case '"':
					endOfToken()
					step = stepBegin
				case '\n':
					endOfToken()
					endOfLine()
					step = stepBegin
				default:
					token.WriteRune(r)
				}
			case stepBracket:
				switch r {
				case ']':
					endOfToken()
					step = stepBegin
				case '\n':
					endOfToken()
					endOfLine()
					step = stepBegin
				default:
					token.WriteRune(r)
				}
			}
		}
	}()
	return out
}

func parseQuery(query string) (method, path string, version int, err error) {
	tokens := strings.SplitN(query, " ", 3)
	if len(tokens) != 3 {
		err = errMalformedQuery
	} else {
		method = tokens[0]
		path = tokens[1]
		version = versionToCode[tokens[2]]
	}
	return
}

func parseDate(s string) (int64, error) {
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", s)
	return t.Unix(), err
}

func makeOrRegex(tags []string) (string, *regexp.Regexp, error) {
	expr := strings.Join(tags, "|")
	re, err := regexp.Compile(expr)
	return expr, re, err
}

func fmtTime(epoch int64) string {
	return time.Unix(epoch, 0).Format("2006-01-02 15:04:05")
}

func filter(in <-chan Record, ko func(Record) bool) <-chan Record {
	out := make(chan Record, 32)
	go func() {
		defer close(out)
		for r := range in {
			if !ko(r) {
				out <- r
			}
		}
	}()
	return out
}

func main() {
	var flagVerbose bool
	var flagFilterAgent, flagFilterSource bool
	var flagJson, flagHuman bool
	var filteredDays int
	var nbColumns int64 = DefaultColumns
	var thisAddr []string

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	strCols := os.Getenv("COLUMNS")
	if strCols != "" {
		var err error
		nbColumns, err = strconv.ParseInt(strCols, 10, 32)
		if err != nil {
			Logger.Warn().Err(err).Msg("Invalid line length (env: COLUMNS)")
			nbColumns = DefaultColumns
		}
	}
	if nbColumns < MinColumns {
		nbColumns = MinColumns
	}

	pflag.BoolVarP(&flagVerbose, "verbose", "v", false, "Increase the verbosity level")
	pflag.BoolVarP(&flagHuman, "human", "H", false, "Display a human-readable output")
	pflag.BoolVarP(&flagJson, "json", "j", false, "Dump JSON records at the output")
	pflag.BoolVarP(&flagFilterAgent, "agent", "A", false, "Hide suspicious User-Agent")
	pflag.BoolVarP(&flagFilterSource, "source", "s", false, "Hide well-known sources")
	pflag.IntVarP(&filteredDays, "days", "d", 0, "Restrict to a time window (in days)")
	pflag.Int64VarP(&nbColumns, "columns", "c", nbColumns, "Max line length for the human-readable display")
	pflag.StringSliceVarP(&thisAddr, "addr", "x", make([]string, 0), "Only display record from specific and explicit sources")
	pflag.Parse()

	// By default, our 4 filters are just passthrough, they accept everything
	addrSieve := func(Record) bool { return false }
	agentSieve := func(Record) bool { return false }
	dateSieve := func(Record) bool { return false }
	referrerSieve := func(Record) bool { return false }

	if flagFilterAgent {
		expr, agentRegex, err := makeOrRegex(avoidedAgents)
		if err != nil {
			Logger.Fatal().Str("expr", expr).Err(err).Msg("Failed to build the rege matching the agents")
		} else {
			Logger.Info().Str("expr", expr).Msg("agents")
		}
		agentSieve = func(r Record) bool { return r.Agent == "-" || agentRegex.MatchString(r.Agent) }
	}

	if len(thisAddr) > 0 {
		addrSieve = func(r Record) bool {
			for _, s := range thisAddr {
				if s == r.Ip {
					return false
				}
			}
			return true
		}
	} else if flagFilterSource {
		addrSieve = func() SieveFilter {
			mySet := make(map[string]bool)
			for _, s := range avoidedAddresses {
				mySet[s] = true
			}
			return func(r Record) bool { return mySet[r.Ip] }
		}()
	}

	if filteredDays > 0 {
		oldest := time.Now().AddDate(0, 0, -filteredDays).Unix()
		dateSieve = func(r Record) bool { return r.When < oldest }
	}

	if len(avoidedReferrer) > 0 {
		expr, refRegex, err := makeOrRegex(avoidedReferrer)
		if err != nil {
			Logger.Fatal().Str("expr", expr).Err(err).Msg("Failed to build the regex matching the referrers")
		}
		referrerSieve = func(r Record) bool { return refRegex.MatchString(r.Referrer) }
	}

	// Create a source of information
	r0 := parseRecords(os.Stdin)

	// Pack a pipeline of filters to trim unwanted records
	r1 := expandRecords(r0)
	r1 = filter(r1, dateSieve)
	r1 = filter(r1, addrSieve)
	r1 = filter(r1, agentSieve)
	r1 = filter(r1, referrerSieve)

	// Dump the expected output
	if flagJson {
		encoder := json.NewEncoder(os.Stdout)
		for r := range r1 {
			encoder.Encode(&r)
		}
	} else {
		if flagHuman {
			format := fmt.Sprintf("%s %%-15s %%-3d %%-60.60s  %%-40.40s  %%.%ds\n", nbColumns-145)
			for r := range r1 {
				fmt.Printf(format, fmtTime(r.When), r.Ip, r.Code, r.Path, r.Referrer, r.Agent)
			}
		} else {
			for r := range r1 {
				fmt.Printf("%s %-15s %d %s %s %q\n", fmtTime(r.When), r.Ip, r.Code, r.Path, r.Referrer, r.Agent)
			}
		}
	}
}
