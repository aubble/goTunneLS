package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

type goTunneLS struct {
	Nodes   []*node
	LogFile string
	log     chan []interface{}
}

// read json file from path into goTunneLS
func (gTLS *goTunneLS) parseFile(path string) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(raw, gTLS)
	if err != nil {
		log.Fatal(err)
	}
}

// listen on goTunneLS.log and append whatever is received to logfile
func (gTLS *goTunneLS) logLoop() {
	if gTLS.LogFile != "" {
		logFile, err := os.OpenFile(gTLS.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatal(err)
			return
		}
		defer logFile.Close()
		logger := log.New(logFile, "goTunneLS: ", 3)
		for {
			v := <-gTLS.log
			logger.Println(v...)
		}
	}
}
