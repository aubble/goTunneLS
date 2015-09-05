package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// node implements one end of a goTunneLS tunnel
type node struct {
	// name for logging
	Name string

	// node mode
	Mode string

	// listen address
	Accept string

	// dial address
	Connect string

	// TODO multiple certs and SNI
	// TODO also look at SignedCertificateTimestamps
	// path to cert
	Cert string

	// path to key
	Key string

	// path to issuer of cert for OCSP
	Issuer string

	// tls configuration
	tlsConfig *tls.Config

	// Duration for sleep after network error in seconds, default is 15
	Timeout time.Duration

	// interval between OCSP staple updates in seconds. Only applies when OCSP responder has most up to date information, otherwise the interval is until the next update. Default is 180
	OCSPInterval time.Duration

	// interval between session ticket key rotations in seconds, default is 28800 or 8 hours
	SessionTicketKeyRotationInterval time.Duration

	// tcp keep alive interval in seconds, default is 15
	TCPKeepAliveInterval time.Duration

	// wg for the copy goroutines, to write logs in sync after they exit
	copyWG sync.WaitGroup

	// listen on Accept address
	listen func() (net.Listener, error)

	// dials the Connect address
	dial func() (net.Conn, error)

	// wg for the main function
	nodeWG sync.WaitGroup
}

// initialize and then run the node according to its mode
// also set some mutual TLSConfig parameters
func (n *node) run() {
	n.logln("initializing")
	defer n.nodeWG.Done()
	defer n.logln("exiting")
	// you can use 5000 as a port instead of :5000
	if !strings.Contains(n.Accept, ":") {
		n.Accept = ":" + n.Accept
	}
	if !strings.Contains(n.Connect, ":") {
		n.Connect = ":" + n.Connect
	}
	// set defaults for time fields
	if n.Timeout == 0 {
		n.Timeout = 15
	}
	if n.OCSPInterval == 0 {
		n.OCSPInterval = 180
	}
	if n.SessionTicketKeyRotationInterval == 0 {
		n.SessionTicketKeyRotationInterval = 28800
	}
	if n.TCPKeepAliveInterval == 0 {
		n.TCPKeepAliveInterval = 15
	}
	// calculate real time.Duration for time fields
	n.Timeout *= time.Second
	n.OCSPInterval *= time.Second
	n.SessionTicketKeyRotationInterval *= time.Second
	n.TCPKeepAliveInterval *= time.Second
	// set mutual TLSConfig fields
	n.tlsConfig = new(tls.Config)
	n.tlsConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	n.tlsConfig.MinVersion = tls.VersionTLS11
	n.tlsConfig.NextProtos = []string{"http/1.1"}
	switch strings.ToLower(n.Mode) {
	case "server":
		n.logln(n.server())
	case "client":
		n.logln(n.client())
	default:
		n.logln("no valid mode")
	}
}

// tcpKeepAliveListener wraps a TCPListener to
// activate TCP keep alive on every accepted connection
type tcpKeepAliveListener struct {
	*net.TCPListener
	tcpKeepAliveInterval time.Duration
}

// Accept a TCP Conn and enable TCP keep alive
func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	err = tc.SetKeepAlive(true)
	if err != nil {
		return
	}
	err = tc.SetKeepAlivePeriod(ln.tcpKeepAliveInterval)
	if err != nil {
		return
	}
	return tc, nil
}

// run the node as a server
// accept TLS TCP and dial plain TCP
// then copying all data between the two connections
func (n *node) server() error {
	n.logf("loading cert %s and key %s", n.Cert, n.Key)
	cert, err := tls.LoadX509KeyPair(n.Cert, n.Key)
	if err != nil {
		return err
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return err
	}
	if cert.Leaf.OCSPServer != nil {
		n.logln("OCSP servers found", cert.Leaf.OCSPServer)
		n.logln("initalizing OCSP stapling")
		OCSPC := OCSPCert{n: n, cert: &cert}
		n.logln("reading issuer", n.Issuer)
		issuerRAW, err := ioutil.ReadFile(n.Issuer)
		if err != nil {
			return err
		}
		for {
			var issuerPEM *pem.Block
			issuerPEM, issuerRAW = pem.Decode(issuerRAW)
			if issuerPEM == nil {
				break
			}
			if issuerPEM.Type == "CERTIFICATE" {
				OCSPC.issuer, err = x509.ParseCertificate(issuerPEM.Bytes)
				if err != nil {
					return err
				}
			}
		}
		if OCSPC.issuer == nil {
			return errors.New("no issuer")
		}
		n.logln("creating the OCSP request")
		OCSPC.req, err = ocsp.CreateRequest(OCSPC.cert.Leaf, OCSPC.issuer, nil)
		if err != nil {
			return err
		}
		n.logln("starting stapleLoop")
		go OCSPC.updateStapleLoop()
		n.tlsConfig.GetCertificate = OCSPC.getCertificate
		//	} else {
		//		TLSConfig.Certificates = []tls.Certificate{cert}
		//TODO FIX THIS BUG
	}
	n.tlsConfig.Certificates = []tls.Certificate{cert}
	n.tlsConfig.PreferServerCipherSuites = true
	updateKey := func(key *[32]byte) {
		if _, err := rand.Read((*key)[:]); err != nil {
			n.logln(err)
			n.logln("cannot create new session ticket key")
		}
	}
	n.logln("initializing session ticket key rotation")
	keys := make([][32]byte, 3)
	updateKey(&keys[0])
	updateKey(&keys[1])
	updateKey(&keys[2])
	go func() {
		for {
			n.tlsConfig.SetSessionTicketKeys(keys)
			n.logf("session ticket key rotation loop sleeping for %vs", float64(n.SessionTicketKeyRotationInterval/time.Second))
			time.Sleep(n.SessionTicketKeyRotationInterval)
			n.logln("updating session ticket rotation keys")
			keys[0] = keys[1]
			keys[1] = keys[2]
			updateKey(&keys[2])
		}
	}()
	n.listen = func() (net.Listener, error) {
		ln, err := net.Listen("tcp", n.Accept)
		if err != nil {
			return nil, err
		}
		return tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener), n.TCPKeepAliveInterval}, n.tlsConfig), err
	}
	n.dial = func() (c net.Conn, err error) {
		d := &net.Dialer{KeepAlive: n.TCPKeepAliveInterval}
		return d.Dial("tcp", n.Connect)
	}
	n.listenAndServe()
	return nil
}

// runs the node as a client
// accept plain TCP and dial TLS TCP
// then copying all data between the two connections
func (n *node) client() error {
	var certPool *x509.CertPool
	if n.Cert != "" {
		certPool = x509.NewCertPool()
		raw, err := ioutil.ReadFile(n.Cert)
		if err != nil {
			return err
		}
		n.logf("adding %s to RootCAs pool", n.Cert)
		ok := certPool.AppendCertsFromPEM(raw)
		if ok == false {
			n.logln("could not append cert to RootCAs pool")
		}
	}
	host, _, err := net.SplitHostPort(n.Connect)
	if err != nil {
		return err
	}
	if host == "" {
		host = "localhost"
	}
	n.tlsConfig.ServerName = host
	n.tlsConfig.RootCAs = certPool
	n.dial = func() (net.Conn, error) {
		d := &net.Dialer{KeepAlive: n.TCPKeepAliveInterval}
		return tls.DialWithDialer(d, "tcp", n.Connect, n.tlsConfig)
	}
	n.listen = func() (net.Listener, error) {
		ln, err := net.Listen("tcp", n.Accept)
		if err != nil {
			return nil, err
		}
		return tcpKeepAliveListener{ln.(*net.TCPListener), n.TCPKeepAliveInterval}, nil
	}
	n.listenAndServe()
	return nil
}

// listenAndServe accepts connections on n.Accept
// it then dials n.Connect and copies all data between the two
// connections. Listening is done with the n.Listen function
// and dialing is done with the n.Dial function
func (n *node) listenAndServe() {
	handleError := func(err error) {
		n.logln(err)
		n.logf("sleeping for %vs", float64(n.Timeout/time.Second))
		time.Sleep(n.Timeout)
	}
	listenAndServeErr := func() error {
		ln, err := n.listen()
		if err != nil {
			return err
		}
		defer ln.Close()
		n.logln("listening on", n.Accept)
		for {
			c1, err := ln.Accept()
			if err != nil {
				return err
			}
			n.logln("connection from", c1.RemoteAddr())
			go func(c1 net.Conn) {
				n.logln("connecting to", n.Connect)
				c2, err := n.dial()
				if err != nil {
					n.logln(err)
					c1.Close()
					return
				}
				n.logf("beginning tunnel from %s to %s then %s to %s", c1.RemoteAddr(), c1.LocalAddr(), c2.LocalAddr(), c2.RemoteAddr())
				n.copyWG.Add(2)
				go n.copy(c1, c2)
				go n.copy(c2, c1)
				n.copyWG.Wait()
				n.logf("closed tunnel from %s to %s then %s to %s", c1.RemoteAddr(), c1.LocalAddr(), c2.LocalAddr(), c2.RemoteAddr())
			}(c1)
		}
	}
	for {
		err := listenAndServeErr()
		handleError(err)
	}
}

// copy copies all data from src to dst
// then calls Done() on the copyWG to allow
// the calling routine to stop waiting followed by closing dst
func (n *node) copy(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		n.logln(err)
	}
	n.copyWG.Done()
}

// logln logs to the global fileLogger as global
// arguments are handled same as fmt.Println
func (n *node) logln(v ...interface{}) {
	if logger.Logger != nil {
		logger.println(append([]interface{}{"-->", n.Mode + n.Name, "-/"}, v...)...)
	}
}

// logf logs to the global fileLogger as global
// arguments are handled same as fmt.Printf
func (n *node) logf(format string, v ...interface{}) {
	if logger.Logger != nil {
		logger.printf("--> "+n.Mode+n.Name+" -/ "+format, v...)
	}
}
