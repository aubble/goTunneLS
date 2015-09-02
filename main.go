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

//global logger for the log file
var logger fileLogger

func main() {
	log.SetPrefix("goTunneLS: ")
	var path string
	flag.StringVar(&path, "c", "/etc/goTunneLS/config.json", "path to configuration file")
	flag.Parse()
	gTLS := new(goTunneLS)
	gTLS.parseFile(path)
	dir, _ := filepath.Split(path)
	if dir != "" {
		if err := os.Chdir(dir); err != nil {
			log.Fatalln("--> global -/", err)
		}
	}
	if gTLS.LogPath != "" {
		logger.logPath = gTLS.LogPath
		logFile, err := os.OpenFile(gTLS.LogPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
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
	var nodeWG sync.WaitGroup
	nodeWG.Add(len(gTLS.Nodes))
	for _, n := range gTLS.Nodes {
		gTLS.logf("initalizing %s node %s", n.Mode, n.Name)
		n.nodeWG = nodeWG
		gTLS.logf("starting %s node %s", n.Mode, n.Name)
		go n.run()
	}
	nodeWG.Wait()
}
