package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// node represents the proxy for goTunneLS
// can be in server or client mode
// server mode listens on the Accept address for tls
// connections to tunnel to the Connect address with plain tcp
// client mode listens on the Accept address for plain tcp
// connections to tunnel to the Connect address with tls
// X509Paths is an array of paths to pem formatted files containing x509 certs/keys/keypairs
// the x509 key pairs are taken in server mode, they must be corresponding to be paired
// basically the n cert extracted must also be the n key extracted. any extra keys are ignored
// as the array implies you can put multiple files but ensure that the certs/keys are found in the order you want
// aka first cert matches up with first key and so on
// you can have multiple certs for different host names
// if more certs are found then keys, we use the last key
// only the x509 certificates are taken in client mode, any private keys are ignored
// they are used as root CAs
type node struct {
	Name      string         // name for logging
	Connect   string         // connect address
	Accept    string         // listen address
	Mode      string         // tunnel mode
	X509Paths []string       // array of paths to pem formatted x509 certs/keys/keypairs
	Timeout   time.Duration  // timeout for sleep after network error in seconds
	copyWG    sync.WaitGroup // waitgroup for the copy goroutines, to log after they exit
}

// extract data from the array of paths to certs/keys/keypairs
// then start the node in server/client mode with the data
func (n *node) run() {
	defer n.log("exiting")
	defer nodeWG.Done()
	var raw []byte
	n.log("extracting raw data from", n.X509Paths)
	if n.X509Paths != nil {
		for _, f := range n.X509Paths {
			tmp, err := ioutil.ReadFile(f)
			if err != nil {
				n.log(err)
				return
			}
			raw = append(raw, tmp...)
		}
	} else {
		n.log("no paths")
		if strings.ToLower(n.Mode) == "server" {
			return
		}
	}
	switch strings.ToLower(n.Mode) {
	case "server":
		n.log(n.server(raw))
	case "client":
		n.client(raw)
	}
}

var gettingInput sync.Mutex // when getting input lock so that the other node server goroutines do not ask for input until unlocked

// run node as server
func (n *node) server(raw []byte) error {
	n.log("parsing raw data from", n.X509Paths)
	var (
		rawCerts  [][]byte
		rawKeys   [][]byte
		x509Pairs []tls.Certificate
	)
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if strings.Contains(strings.ToLower(block.Type), "private key") {
			if x509.IsEncryptedPEMBlock(block) {
				gettingInput.Lock()
				n.log(fmt.Sprintf("getting passphrase for key #%d of type %s", len(rawKeys)+1, block.Type))
				fmt.Printf("%s -/ passphrase for key #%d of type %s: ", n.Mode+n.Name, len(rawKeys)+1, block.Type)
				stty := func(args []string) {
					stty := exec.Command("stty", args...)
					stty.Stdin = os.Stdin
					if err := stty.Run(); err != nil {
						n.log(err)
					}
				}
				stty([]string{"-echo", "echonl"})
				passphrase, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil {
					return err
				}
				stty([]string{"echo", "-echonl"})
				gettingInput.Unlock()
				passphrase = passphrase[:len(passphrase)-1]
				key, err := x509.DecryptPEMBlock(block, []byte(passphrase))
				if err != nil {
					return err
				}
				block.Bytes = key
				delete(block.Headers, "Proc-Type")
				delete(block.Headers, "DEK-Info")
			}
			rawKeys = append(rawKeys, pem.EncodeToMemory(block))
		} else if strings.Contains(strings.ToLower(block.Type), "certificate") {
			rawCerts = append(rawCerts, pem.EncodeToMemory(block))
		}
	}
	for i, _ := range rawCerts {
		j := i
		if i >= len(rawKeys) {
			j = len(rawKeys) - 1
		}
		x509Pair, err := tls.X509KeyPair(rawCerts[i], rawKeys[j])
		if err != nil {
			return err
		}
		x509Pairs = append(x509Pairs, x509Pair)
	}
	cs := []uint16{
		tls.TLS_FALLBACK_SCSV,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		//tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		//tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
	//tls.TLS_RSA_WITH_RC4_128_SHA}
	conf := tls.Config{Certificates: x509Pairs, CipherSuites: cs, MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS12,
		/*MaxVersion needed because of bug in TLS_FALLBACK_SCSV gonna fixed in go 1.5*/
		PreferServerCipherSuites: true}
	conf.BuildNameToCertificate()
	for {
		ln, err := tls.Listen("tcp", n.Accept, &conf)
		if err != nil {
			n.log(err)
			n.log("sleeping for", int64(n.Timeout))
			time.Sleep(time.Second * n.Timeout)
			continue
		}
		n.log("listening on", n.Accept)
		for {
			TLS, err := ln.Accept()
			if err != nil {
				n.log(err)
				n.log("sleeping for", int64(n.Timeout))
				time.Sleep(time.Second * n.Timeout)
				ln.Close()
				break
			}
			n.log("connection from", TLS.RemoteAddr().String())
			go func() {
				n.log("connecting to", n.Connect)
				c, err := net.Dial("tcp", n.Connect)
				if err != nil {
					n.log(err)
					TLS.Close()
					return
				}
				n.tunnel(TLS, c)
			}()
		}
	}
}

// run node as client
func (n *node) client(raw []byte) {
	certPool := x509.NewCertPool()
	if n.X509Paths != nil {
		n.log("adding", n.X509Paths, "to pool")
		certPool.AppendCertsFromPEM(raw)
	}
	for {
		ln, err := net.Listen("tcp", n.Accept)
		if err != nil {
			n.log(err)
			n.log("sleeping for", int64(n.Timeout))
			time.Sleep(time.Second * n.Timeout)
			continue
		}
		n.log("listening on", n.Accept)
		for {
			c, err := ln.Accept()
			if err != nil {
				n.log(err)
				n.log("sleeping for", int64(n.Timeout))
				time.Sleep(time.Second * n.Timeout)
				ln.Close()
				break
			}
			n.log("connection from", c.RemoteAddr().String())
			go func() {
				host, _, err := net.SplitHostPort(n.Connect)
				if err != nil {
					n.log(err)
					c.Close()
					return
				}
				if host == "" {
					host = "localhost"
				}
				n.log("connecting to", n.Connect)
				TLS, err := tls.Dial("tcp", n.Connect, &tls.Config{ServerName: host, RootCAs: certPool})
				if err != nil {
					c.Close()
					n.log(err)
					return
				}
				n.tunnel(c, TLS)
			}()
		}
	}
}

// create a bidirectional tunnel from c1 to c2
func (n *node) tunnel(c1 net.Conn, c2 net.Conn) {
	n.log("beginning tunnel from", c1.RemoteAddr().String(),
		"to", c1.LocalAddr().String(),
		"to", c2.LocalAddr().String(),
		"to", c2.RemoteAddr().String())
	n.copyWG.Add(2)
	go n.copy(c1, c2)
	go n.copy(c2, c1)
	n.copyWG.Wait()
	n.log("closing tunnel from", c1.RemoteAddr().String(),
		"to", c1.LocalAddr().String(),
		"to", c2.LocalAddr().String(),
		"to", c2.RemoteAddr().String())
}

// copy all data from src to dst
func (n *node) copy(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	defer n.copyWG.Done()
	if _, err := io.Copy(dst, src); err != nil {
		n.log(err)
	}
}

// append node info to arguments and send to logging channel
func (n *node) log(v ...interface{}) {
	gTLS.log <- append([]interface{}{n.Mode + n.Name}, v...)
}

//TODO renaming variables, CODE REVIEW, syslog and compression, EAT GARLIC
