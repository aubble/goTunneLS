package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// logger is the global fileLogger
var l *fileLogger

const globalPrefix = "--> global -/"

var maxLength string

// main does initialization and launches all the nodes
// first it reads the config file into a TunneLS struct
// next if a LogPath is provided it sets up logging
// finally it launches all the nodes and waits for them to end
func main() {
	log.SetPrefix("")
	log.SetFlags(0)
	// read and parse config file
	var path string
	flag.StringVar(&path, "c", "/usr/local/etc/TunneLS/config.json", "path to configuration file")
	flag.Parse()
	tls := new(TunneLS)
	tls.parseFile(path)
	dir, _ := filepath.Split(path)
	if dir != "" {
		if err := os.Chdir(dir); err != nil {
			log.Fatalf("%s %s", globalPrefix, err)
		}
	}
	l = newFileLogger(tls.StderrPrefix, tls.StderrLogging, tls.LogPath)
	l.printf("%s initialized logging", globalPrefix)
	// get the maximum size of name in logging
	var ml int
	for _, n := range tls.Nodes {
		// add space to non empty names
		if n.Name != "" {
			n.Name = " " + n.Name
		}
		if s := len(n.Name); s > ml {
			ml = s
		}
	}
	maxLength = strconv.Itoa(ml)
	var wg sync.WaitGroup
	wg.Add(len(tls.Nodes))
	// launch nodes and wait for their return
	for _, n := range tls.Nodes {
		go n.run(&wg)
	}
	wg.Wait()
	l.printf("%s terminated", globalPrefix)
}
