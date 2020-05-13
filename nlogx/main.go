// Copyright (C) 2020 nlogx's AUTHORS
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
	stepBegin   = iota
	stepBare    = iota
	stepQuote   = iota
	stepBracket = iota
)

type record0 struct {
	ip       string
	when     string
	req      string
	code     string
	referrer string
	agent    string
}

type Record1 struct {
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
	"^curl",
	"^Java",
	"^Python",
	"^Go",
	"^Twingly",
	"^Qwant",
	"^Validator",
	"^Screaming",
	"bot", "Bot",
	"crawler", "Crawler",
	"screamingfrog",
	"Google Favicon",
	"python-requests",
	"phpunit",
	"phpmyadmin",
	"jsonws",
	"solr",
	"spider",
	"lighthouse",
	"HeadlessChrome",
	"BingPreview",
	"NetcraftSurveyAgent",
}

var avoidedAddresses = map[string]bool{
	// Whitelist
	"127.0.0.1":      true, // localhost for testing purposes
	"91.173.184.121": true, // jfs
	"185.75.141.25":  true, // scalair, openio
	"93.70.13.60":    true, // Ruben
	// Blacklist
}

var errMalformedQuery = errors.New("Invalid query")

var versionToCode = map[string]int{
	"HTTP/0.9": 0,
	"HTTP/1.0": 0,
	"HTTP/1.1": 1,
	"HTTP/2.0": 2,
}

type StringPredicateFunc func(string) bool
type TimePredicateFunc func(int64) bool

func expandRecords(src <-chan record0, dateKo TimePredicateFunc) <-chan Record1 {
	out := make(chan Record1, 64)
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
			if dateKo(when) {
				continue
			}
			out <- Record1{
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

func parseRecords(src io.Reader, addrKo, agentKo StringPredicateFunc) <-chan record0 {
	out := make(chan record0, 64)
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
			if addrKo(ip) {
				return
			}
			if agentKo(agent) {
				return
			}
			out <- record0{
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

func main() {
	var flagVerbose bool
	var flagFilterAgent, flagFilterSource bool
	var flagJson, flagHuman bool
	var filteredDays int
	var thisAddr []string

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	pflag.BoolVarP(&flagVerbose, "verbose", "v", false, "Increase the verbosity level")
	pflag.BoolVarP(&flagHuman, "human", "H", false, "Display a human-readable output")
	pflag.BoolVarP(&flagJson, "json", "j", false, "Dump JSON records at the output")
	pflag.BoolVarP(&flagFilterAgent, "agent", "A", false, "Filter on User-Agent")
	pflag.BoolVarP(&flagFilterSource, "source", "s", false, "Filter well-known sources")
	pflag.IntVarP(&filteredDays, "days", "d", 0, "Restrict to a time window (in days)")
	pflag.StringSliceVarP(&thisAddr, "addr", "x", make([]string, 0), "Only display record from specific and explicit sources")
	pflag.Parse()

	addrSieve := func(addr string) bool { return false }
	agentSieve := func(agent string) bool { return false }
	dateSieve := func(epoch int64) bool { return false }

	if flagFilterAgent {
		expr, agentRegex, err := makeOrRegex(avoidedAgents)
		if err != nil {
			Logger.Fatal().Str("expr", expr).Err(err).Msg("Failed to build the rege matching the agents")
		}
		agentSieve = func(agent string) bool {
			return agent == "-" || agentRegex.MatchString(agent)
		}
	}
	if len(thisAddr) > 0 {
		addrSieve = func(addr string) bool {
			for _, s := range thisAddr {
				if s == addr {
					return false
				}
			}
			return true
		}
	} else if flagFilterSource {
		addrSieve = func(addr string) bool {
			return avoidedAddresses[addr]
		}
	}
	if filteredDays > 0 {
		oldest := time.Now().AddDate(0, 0, -filteredDays).Unix()
		dateSieve = func(epoch int64) bool {
			return epoch < oldest
		}
	}

	r0 := parseRecords(os.Stdin, addrSieve, agentSieve)
	r1 := expandRecords(r0, dateSieve)
	if flagJson {
		encoder := json.NewEncoder(os.Stdout)
		for r := range r1 {
			encoder.Encode(&r)
		}
	} else {
		if flagHuman {
			const cols = 200
			format := fmt.Sprintf("%%-15s %%-19s %%-3d %%-60.60s  %%-40.40s  %%.%ds\n", cols-145)
			for r := range r1 {
				fmt.Printf(format, r.Ip, fmtTime(r.When), r.Code, r.Path, r.Referrer, r.Agent)
			}
		} else {
			for r := range r1 {
				fmt.Printf("%s %s %d %s %s %q\n", r.Ip, fmtTime(r.When), r.Code, r.Path, r.Referrer, r.Agent)
			}
		}
	}
}
