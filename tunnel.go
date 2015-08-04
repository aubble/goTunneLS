package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// node represents the reverse proxy for goTunneLS
// can be in server or client mode
// server mode listens on the Accept address for tls
// connections to tunnel to the Connect address with plain tcp
// client mode listens on the Accept address for plain tcp
// connections to tunnel to the Connect address with tls
// x509Paths is an array of paths to pem formatted files containing x509 certs/keys/keypairs
// the x509 key pairs are taken in server mode, they must be one after another to be paired.
// so first the cert then its corresponding priv key, or the other way around. any extra private keys are ignored
// as the array implies you can put multiple files but ensure the order of the certs/keys matches up properly, aka one after another
// only the x509 certificates are taken in client mode, any private keys are ignored
type node struct {
	Name    string         // name for logging
	Connect string         // connect address
	Accept  string         // listen address
	Mode    string         // tunnel mode
	PEM     []string       // array of paths to pem formatted x509 certs/keys/keypairs
	Timeout time.Duration  // timeout for sleep after network error in seconds
	copyWG  sync.WaitGroup // waitgroup for the second copy goroutine, to log after it exits
}

func (n *node) run() {
	defer n.log("exiting")
	defer nodeWG.Done()
	var raw []byte
	n.log("extracting raw data from", n.PEM)
	if n.PEM != nil {
		for _, f := range n.PEM {
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
	n.log("extracted raw data from", n.PEM)
	switch strings.ToLower(n.Mode) {
	case "server":
		n.log(n.server(raw))
	case "client":
		n.client(raw)
	}
}

func (n *node) server(raw []byte) error {
	n.log("parsing raw data from", n.PEM)
	var (
		rawCerts    [][]byte
		rawKeys     [][]byte
		x509Certs   []tls.Certificate
		phraseIndex int // index for the passphrase from array
	)
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if strings.Contains(strings.ToLower(block.Type), "private key") {
			if x509.IsEncryptedPEMBlock(block) {
				fmt.Printf("please enter the passphrase for key #%d type %s: ", phraseIndex, block.Type)
				passphrase, err := bufio.NewReader(os.Stdin).ReadString('\n')
				passphrase = passphrase[:len(passphrase)-1]
				key, err := x509.DecryptPEMBlock(block, []byte(passphrase))
				if err != nil {
					return err
				}
				phraseIndex++
				block = &pem.Block{Type: block.Type, Bytes: key}
			}
			rawKeys = append(rawKeys, pem.EncodeToMemory(block))
		} else if strings.Contains(strings.ToLower(block.Type), "certificate") {
			rawCerts = append(rawCerts, pem.EncodeToMemory(block))
		}
	}
	for i, _ := range rawCerts {
		tmp, err := tls.X509KeyPair(rawCerts[i], rawKeys[i])
		if err != nil {
			return err
		}
		x509Certs = append(x509Certs, tmp)
	}
	n.log("parsed raw data from", n.PEM)
	conf := tls.Config{Certificates: x509Certs}
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
					return
				}
				n.tunnel(TLS, c)
			}()
		}
	}
}

func (n *node) client(raw []byte) {
	certPool := x509.NewCertPool()
	n.log("adding", n.PEM, "to pool")
	certPool.AppendCertsFromPEM(raw)
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
					return
				}
				if host == "" {
					host = "localhost"
				}
				n.log("connecting to", n.Connect)
				TLS, err := tls.Dial("tcp", n.Connect, &tls.Config{ServerName: host, RootCAs: certPool})
				if err != nil {
					n.log(err)
					return
				}
				n.tunnel(c, TLS)
			}()
		}
	}
}

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

func (n *node) copy(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	defer n.copyWG.Done()
	_, err := io.Copy(dst, src)
	if err != nil {
		n.log(err)
	}
}

func (n *node) log(v ...interface{}) {
	v = append([]interface{}{n.Mode + n.Name}, v...)
	log.Println(v...)
}

//TODO renaming variables, CODE REVIEW, add logging file, match unix programs,
//TODO how to handle passphrases ssh-agent, easier to configure, passphrases as files, if file no work ask
