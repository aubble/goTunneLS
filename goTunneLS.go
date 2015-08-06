package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type goTunneLS struct {
	Nodes   []*node            // slice of nodes to run
	LogFile string             // path to logfile, use /dev/stdout for standard output and /dev/stderr for standard error
	log     chan []interface{} // log channel
}

// read json file into goTunneLS
func (gTLS *goTunneLS) parseFile(path string) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	if err = json.Unmarshal(raw, gTLS); err != nil {
		log.Fatal(err)
	}
}

// listen on log channel and append received to logfile
// if logfile doesn't exist, create it, and check continuously
// if it doesn't exist and if so create
func (gTLS *goTunneLS) listenLogs() {
	if gTLS.LogFile != "" {
		for {
			logFile, err := os.OpenFile(gTLS.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
			if err != nil {
				log.Fatal(err)
			}
			defer logFile.Close()
			logger := log.New(logFile, "goTunneLS: ", 3)
			logger.Println("--> global -/ beginning logging")
			for {
				v := <-gTLS.log
				logger.Println(v...)
				if _, err = os.Stat(gTLS.LogFile); os.IsNotExist(err) {
					break
				}
			}
		}
	}
}

// todo logging creation of file when deleted and what not, also log end of methods/actions
