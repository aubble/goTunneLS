package main

import (
	"sync"
	"strings"
)

var nodeWG sync.WaitGroup
var gTLS *goTunneLS

// creates an array of nodes,
// which it reads the json file into
// and then starts up each node after setting the logger and name
// then waits until each node exits
func main() {
	gTLS = new(goTunneLS)
	gTLS.log = make(chan []interface{})
	go gTLS.logLoop()
	gTLS.parseFile("nodes.json")
	nodeWG.Add(len(gTLS.Nodes))
	// start each tunnel
	for _, n := range gTLS.Nodes {
		if n.Name != "" {
			n.Name = " " + n.Name
		}
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
