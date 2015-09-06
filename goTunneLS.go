package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

// goTunneLS represents the the settings for the nodes and the logFile
type goTunneLS struct {
	// slice of the configured nodes to launch
	Nodes []*node

	// path to the logFile
	LogPath string

	// controls whether or not to have timestamps/prefix on the stderr logging
	StdErrPrefixLogging bool
}

// read config file into gTLS
func (gTLS *goTunneLS) parseFile(path string) {
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
func (gTLS *goTunneLS) logln(v ...interface{}) {
	logger.println(append([]interface{}{"--> global -/"}, v...)...)
}

// logf logs to the global fileLogger as global
// arguements are handled same as fmt.Printf
func (gTLS *goTunneLS) logf(format string, v ...interface{}) {
	logger.printf("--> global -/ "+format, v...)
}
