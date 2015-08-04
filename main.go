package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"
	"sync"
)

var tunnelWG sync.WaitGroup

// creates an array of tunnels,
// which it reads the json file into
// and then starts up each tunnel
// then waits until each tunnel exits
func main() {
	log.SetPrefix("goTunneLS: ")
	var tuns []*tunnel
	parseFile("tunnels.json", &tuns)
	tunnelWG.Add(len(tuns))
	// start each tunnel
	for _, tun := range tuns {
		if tun.Name != "" {
			tun.Name = " " + tun.Name
		}
		tun.log("starting up")
		go tun.run()
	}
	tunnelWG.Wait()
}

func parseFile(path string, tuns *[]*tunnel) {
	log.Println("global reading", path)
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("global read", path)
	log.Println("global parsing", path)
	err = json.Unmarshal(raw, tuns)
	if err != nil {
		log.Fatal(err)
	}
	for _, tun := range *tuns {
		if !strings.Contains(tun.Accept, ":") {
			tun.Accept = ":" + tun.Accept
		}
		if !strings.Contains(tun.Connect, ":") {
			tun.Connect = ":" + tun.Connect
		}
	}
	log.Println("global parsed", path)
}
