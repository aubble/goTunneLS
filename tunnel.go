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

// tunnel represents a goTunneLS tunnel
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
type tunnel struct {
	Name    string         // name for logging
	Connect string         // connect address
	Accept  string         // listen address
	Mode    string         // tunnel mode
	PEM     []string       // array of paths to pem formatted x509 certs/keys/keypairs
	Timeout time.Duration  // timeout for sleep after network error in seconds
	copyWG  sync.WaitGroup // waitgroup for the second copy goroutine, to log after it exits
}

func (tun *tunnel) run() {
	defer tun.log("exiting")
	defer tunnelWG.Done()
	var raw []byte
	tun.log("extracting raw data from", tun.PEM)
	if tun.PEM != nil {
		for _, f := range tun.PEM {
			tmp, err := ioutil.ReadFile(f)
			if err != nil {
				tun.log(err)
				return
			}
			raw = append(raw, tmp...)
		}
	} else {
		tun.log("no paths")
		if strings.ToLower(tun.Mode) == "server" {
			return
		}
	}
	tun.log("extracted raw data from", tun.PEM)
	switch strings.ToLower(tun.Mode) {
	case "server":
		tun.server(raw)
	case "client":
		tun.client(raw)
	}
}

func (tun *tunnel) server(raw []byte) {
	tun.log("parsing raw data from", tun.PEM)
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
				fmt.Printf("please enter the passphrase for key #%d type %s: ", phraseIndex, block.Type )
				passphrase, err := bufio.NewReader(os.Stdin).ReadString('\n')
				passphrase = passphrase[:len(passphrase)-1]
				key, err := x509.DecryptPEMBlock(block, []byte(passphrase))
				phraseIndex++
				if err != nil {
					tun.log(err)
					return
				}
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
			tun.log(err)
			return
		}
		x509Certs = append(x509Certs, tmp)
	}
	tun.log("parsed raw data from", tun.PEM)
	conf := tls.Config{Certificates: x509Certs}
	conf.BuildNameToCertificate()
	for {
		ln, err := tls.Listen("tcp", tun.Accept, &conf)
		if err != nil {
			tun.log(err)
			tun.log("sleeping for", int64(tun.Timeout))
			time.Sleep(time.Second * tun.Timeout)
			continue
		}
		tun.log("listening on", tun.Accept)
		for {
			TLS, err := ln.Accept()
			if err != nil {
				tun.log(err)
				tun.log("sleeping for", int64(tun.Timeout))
				time.Sleep(time.Second * tun.Timeout)
				continue
			}
			tun.log("connection from", TLS.RemoteAddr().String())
			go func() {
				tun.log("connecting to", tun.Connect)
				c, err := net.Dial("tcp", tun.Connect)
				if err != nil {
					tun.log(err)
					return
				}
				tun.log("beginning tunnel from", TLS.RemoteAddr().String(),
					"to", TLS.LocalAddr().String(),
					"to", c.LocalAddr().String(),
					"to", c.RemoteAddr().String())
				tun.copyWG.Add(2)
				go tun.copy(TLS, c)
				go tun.copy(c, TLS)
				tun.copyWG.Wait()
				tun.log("closing tunnel from", TLS.RemoteAddr().String(),
					"to", TLS.LocalAddr().String(),
					"to", c.LocalAddr().String(),
					"to", c.RemoteAddr().String())
			}()
		}
	}
}

func (tun *tunnel) client(raw []byte) {
	certPool := x509.NewCertPool()
	tun.log("adding", tun.PEM, "to pool")
	certPool.AppendCertsFromPEM(raw)
	for {
		ln, err := net.Listen("tcp", tun.Accept)
		if err != nil {
			tun.log(err)
			tun.log("sleeping for", int64(tun.Timeout))
			time.Sleep(time.Second * tun.Timeout)
			continue
		}
		tun.log("listening on", tun.Accept)
		for {
			c, err := ln.Accept()
			if err != nil {
				tun.log(err)
				tun.log("sleeping for", int64(tun.Timeout))
				ln.Close()
				time.Sleep(time.Second * tun.Timeout)
				break
			}
			tun.log("connection from", c.RemoteAddr().String())
			go func() {
				host, _, err := net.SplitHostPort(tun.Connect)
				if err != nil {
					tun.log(err)
					tun.log("disconnecting from", c.RemoteAddr().String())
					return
				}
				if host == "" {
					host = "localhost"
				}
				tun.log("connecting to", tun.Connect)
				TLS, err := tls.Dial("tcp", tun.Connect, &tls.Config{ServerName: host, RootCAs: certPool})
				if err != nil {
					tun.log(err)
					tun.log("disconnecting from", tun.Connect)
					return
				}
				tun.log("beginning tunnel from", c.RemoteAddr().String(),
					"to", c.LocalAddr().String(),
					"to", TLS.LocalAddr().String(),
					"to", TLS.RemoteAddr().String())
				tun.copyWG.Add(2)
				go tun.copy(TLS, c)
				go tun.copy(c, TLS)
				tun.copyWG.Wait()
				tun.log("closing tunnel from", c.RemoteAddr().String(),
					"to", c.LocalAddr().String(),
					"to", TLS.LocalAddr().String(),
					"to", TLS.RemoteAddr().String())
			}()
		}
	}
}

func (tun *tunnel) copy(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	defer tun.copyWG.Done()
	_, err := io.Copy(dst, src)
	if err != nil {
		tun.log(err)
	}
}

func (tun *tunnel) log(v ...interface{}) {
	v = append([]interface{}{tun.Mode + tun.Name + " /-"}, v...)
	log.Println(v...)
}

//TODO renaming variables, check errors for return or no exit or what, CODE REVIEW, for exit errors just return error and print in run method
//TODO add logging file, match unix programs, how to handle passphrases ssh-agent
