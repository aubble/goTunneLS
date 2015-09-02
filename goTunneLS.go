package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

type goTunneLS struct {
	Nodes   []*node // slice of nodes to run
	LogPath string  // path to logfile, use /dev/stdout for standard output and /dev/stderr for standard error
}

// read json file into gTLS
func (gTLS *goTunneLS) parseFile(path string) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalln("--> global -/", err)
	}
	if err = json.Unmarshal(raw, gTLS); err != nil {
		log.Fatalln("--> global -/", err)
	}
}

func (gTLS *goTunneLS) logln(v ...interface{}) {
	if logger.Logger != nil {
		logger.println(append([]interface{}{"--> global -/"}, v...)...)
	}
}

func (gTLS *goTunneLS) logf(format string, v ...interface{}) {
	if logger.Logger != nil {
		logger.printf("--> global -/ " + format, v...)
	}
}
