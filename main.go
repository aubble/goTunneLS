package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"
	"sync"
)

var nodeWG sync.WaitGroup

// creates an array of nodes,
// which it reads the json file into
// and then starts up each tunnel
// then waits until each tunnel exits
func main() {
	log.SetPrefix("goTunneLS: ")
	var nodes []*node
	parseFile("nodes.json", &nodes)
	nodeWG.Add(len(nodes))
	// start each tunnel
	for _, n := range nodes {
		if n.Name != "" {
			n.Name = " " + n.Name
		}
		n.log("starting up")
		go n.run()
	}
	nodeWG.Wait()
}

func parseFile(path string, nodes *[]*node) {
	log.Println("global reading", path)
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("global read", path)
	log.Println("global parsing", path)
	err = json.Unmarshal(raw, nodes)
	if err != nil {
		log.Fatal(err)
	}
	for _, n := range *nodes {
		if !strings.Contains(n.Accept, ":") {
			n.Accept = ":" + n.Accept
		}
		if !strings.Contains(n.Connect, ":") {
			n.Connect = ":" + n.Connect
		}
	}
	log.Println("global parsed", path)
}
