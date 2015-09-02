package main

import (
	"log"
	"os"
	"sync"
)

//global logger for the log file
var logger fileLogger

//
func main() {
	log.SetPrefix("goTunneLS: ")
	gTLS := new(goTunneLS)
	if err := os.Chdir("/etc/goTunneLS"); err != nil {
		log.Fatalln("--> global -/", err)
	}
	gTLS.parseFile("nodes.json")
	if gTLS.LogPath != "" {
		logger.logPath = gTLS.LogPath
		logFile, err := os.OpenFile(gTLS.LogPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalln("--> global -/", err)
		}
		logger.Logger = log.New(logFile, "goTunneLS: ", 3)
		logger.logFile = &logFile
		defer logger.close()
		gTLS.log("beginning logging")
		defer gTLS.log("exiting")
	}
	var nodeWG sync.WaitGroup
	nodeWG.Add(len(gTLS.Nodes))
	for _, n := range gTLS.Nodes {
		gTLS.log("initalizing", n.Mode, "node", n.Name)
		// prepend space to name in named nodes to separate mode in logging
		if n.Name != "" {
			n.Name = " " + n.Name
		}
		n.nodeWG = nodeWG
		gTLS.log("starting", n.Mode, "node"+n.Name)
		go n.run()
	}
	nodeWG.Wait()
	gTLS.log("exiting")
}
