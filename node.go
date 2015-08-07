package main

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"io/ioutil"
	"crypto/x509"
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
	Name    string         // name for logging
	Connect string         // connect address
	Accept  string         // listen address
	Mode    string         // tunnel mode
	Cert    string
	Key     string
	Timeout time.Duration  // timeout for sleep after network error in seconds
	copyWG  sync.WaitGroup // waitgroup for the copy goroutines, to log after they exit
}

// extract data from the array of paths to certs/keys/keypairs
// then start the node in server/client mode with the data
func (n *node) run() {
	defer n.log("exiting")
	defer nodeWG.Done()
	switch strings.ToLower(n.Mode) {
	case "server":
		n.log(n.server())
	case "client":
		n.log(n.client())
	}
}

// run node as server
func (n *node) server() error {
	n.log("loading cert", n.Cert, "and key", n.Key)
	cert, err := tls.LoadX509KeyPair(n.Cert, n.Key)
	if err != nil {
		return err
	}
	cs := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
	//MaxVersion needed because of bug with TLS_FALLBACK_SCSV gonna be fixed in go 1.5
	conf := tls.Config{Certificates: []tls.Certificate{cert}, CipherSuites: cs, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
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
					n.log("disconnecting from", TLS.RemoteAddr().String())
					TLS.Close()
					return
				}
				n.tunnel(TLS, c)
			}()
		}
	}
}

// run node as client
func (n *node) client() error {
	var certPool *x509.CertPool
	if n.Cert != "" {
		certPool := x509.NewCertPool()
		raw, err := ioutil.ReadFile(n.Cert)
		if err != nil {
			return err
		}
		n.log("adding", n.Cert, "to pool")
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
					n.log("disconnecting from", c.RemoteAddr().String())
					c.Close()
					return
				}
				if host == "" {
					host = "localhost"
				}
				n.log("connecting to", n.Connect)
				TLS, err := tls.Dial("tcp", n.Connect, &tls.Config{ServerName: host, RootCAs: certPool})
				if err != nil {
					n.log(err)
					n.log("disconnecting from", c.RemoteAddr().String())
					c.Close()
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
	defer n.copyWG.Done()
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		n.log(err)
	}
}

// append node info to arguments and send to logging channel
func (n *node) log(v ...interface{}) {
	gTLS.log <- append([]interface{}{"--> " + n.Mode + n.Name + " -/"}, v...)
}

//TODO renaming variables, CODE REVIEW, syslog and compression, better logging, platform independent configuration, per node logging

//TODO EAT FUCKING GARLIC
