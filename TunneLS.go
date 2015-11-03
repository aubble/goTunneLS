package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

// TunneLS represents the the settings for the nodes and the logFile
type TunneLS struct {
	// slice of the configured nodes to launch
	Nodes []*node

	// path to the logFile
	LogPath string

	// controls whether or not to log to stderr
	StderrLogging bool

	// controls whether or not to have timestamps/prefix on the stderr logging
	StderrPrefix bool
}

// read config file into tls
func (tls *TunneLS) parseFile(path string) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalln("--> global -/", err)
	}
	if err = json.Unmarshal(raw, tls); err != nil {
		log.Fatalln("--> global -/", err)
	}
}

// logln logs to the global fileLogger as global
// arguements are handled same as fmt.Println
func (tls *TunneLS) logln(v ...interface{}) {
	l.println(append([]interface{}{"--> global -/"}, v...)...)
}

// logf logs to the global fileLogger as global
// arguements are handled same as fmt.Printf
func (tls *TunneLS) logf(format string, v ...interface{}) {
	l.printf("--> global -/ "+format, v...)
}
