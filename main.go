package main

import (
	"strings"
	"sync"
)

var nodeWG sync.WaitGroup
var gTLS *goTunneLS

// read nodes.json file into the global variable gTLS
// then begin logging on gTLS.log channel
// then start each node and wait until they all exit
func main() {
	gTLS = new(goTunneLS)
	gTLS.log = make(chan []interface{})
	gTLS.parseFile("/etc/goTunneLS/nodes.json")
	go gTLS.listenLogs()
	nodeWG.Add(len(gTLS.Nodes))
	for _, n := range gTLS.Nodes {
		// prepend space to name in named nodes to separate mode in logging
		if n.Name != "" {
			n.Name = " " + n.Name
		}
		// you can use 5000 as a port instead of :5000
		if !strings.Contains(n.Accept, ":") {
			n.Accept = ":" + n.Accept
		}
		if !strings.Contains(n.Connect, ":") {
			n.Connect = ":" + n.Connect
		}
		n.log("starting up")
		go n.run()
	}
	nodeWG.Wait()
}
