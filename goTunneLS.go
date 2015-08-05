package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type goTunneLS struct {
	Nodes   []*node            // slice of nodes to run/configure
	LogFile string             // path to logfile, use /dev/stdout for standard output and /dev/stderr for standard error
	log     chan []interface{} // log channel
}

// read json file from path into goTunneLS
func (gTLS *goTunneLS) parseFile(path string) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	if err = json.Unmarshal(raw, gTLS); err != nil {
		log.Fatal(err)
	}
}

// receive on log channel and append received to logfile
func (gTLS *goTunneLS) logLoop() {
	if gTLS.LogFile != "" {
		logFile, err := os.OpenFile(gTLS.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()
		logger := log.New(logFile, "goTunneLS: ", 3)
		for {
			v := <-gTLS.log
			logger.Println(v...)
		}
	}
}
