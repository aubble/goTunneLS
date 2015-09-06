package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

// logger is the global fileLogger
var logger fileLogger

// main does initialization and launches all the nodes
// first it reads the config file into a goTunneLS struct
// next if a LogPath is provided it sets up logging
// finally it launches all the nodes and waits for them to end
func main() {
	log.SetPrefix("goTunneLS: ")
	// read and parse config file
	var path string
	flag.StringVar(&path, "c", "/usr/local/etc/goTunneLS/config.json", "path to configuration file")
	flag.Parse()
	gTLS := new(goTunneLS)
	gTLS.parseFile(path)
	dir, _ := filepath.Split(path)
	if dir != "" {
		if err := os.Chdir(dir); err != nil {
			log.Fatalln("--> global -/", err)
		}
	}
	// setup file logging
	if gTLS.LogPath != "" {
		logger.logPath = gTLS.LogPath
		logFile, err := os.OpenFile(gTLS.LogPath, os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalln("--> global -/", err)
		}
		logger.Logger = log.New(logFile, "goTunneLS: ", 3)
		logger.logFile = &logFile
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		gTLS.logln("beginning logging")
		go func() {
			sig := <-sigs
			gTLS.logln("got signal", sig)
			gTLS.logln("now exiting")
			logger.close()
			os.Exit(1)
		}()
	}
	// set stderr prefix/timestamps
	if gTLS.StdErrPrefixLogging == false {
		log.SetFlags(0)
		log.SetPrefix("")
	}
	// launch nodes and wait for their return
	var nodeWG sync.WaitGroup
	nodeWG.Add(len(gTLS.Nodes))
	for _, n := range gTLS.Nodes {
		// empty names don't have a odd space
		if n.Name != "" {
			n.Name = " " + n.Name
		}
		gTLS.logf("initalizing %s node%s", n.Mode, n.Name)
		n.nodeWG = nodeWG
		gTLS.logf("starting %s node%s", n.Mode, n.Name)
		go n.run()
	}
	nodeWG.Wait()
}
