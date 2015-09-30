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

	// controls whether or not to have timestamps/prefix on the stderr logging
	StdErrPrefixLogging bool
}

// read config file into gTLS
func (gTLS *TunneLS) parseFile(path string) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalln("--> global -/", err)
	}
	if err = json.Unmarshal(raw, gTLS); err != nil {
		log.Fatalln("--> global -/", err)
	}
}

// logln logs to the global fileLogger as global
// arguements are handled same as fmt.Println
func (gTLS *TunneLS) logln(v ...interface{}) {
	logger.println(append([]interface{}{"--> global -/"}, v...)...)
}

// logf logs to the global fileLogger as global
// arguements are handled same as fmt.Printf
func (gTLS *TunneLS) logf(format string, v ...interface{}) {
	logger.printf("--> global -/ "+format, v...)
}
