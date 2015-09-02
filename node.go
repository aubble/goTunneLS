package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// node represents the proxy for goTunneLS
// can be in server or client mode
// server mode listens on the Accept address for tls
// connections to tunnel to the Connect address with plain tcp
// client mode listens on the Accept address for plain tcp
// connections to tunnel to the Connect address with tls
type node struct {
	Name                       string                       // name for logging
	Mode                       string                       // tunnel mode
	Accept                     string                       // listen address
	Connect                    string                       // connect address
	Cert                       string                       // path to cert
	Key                        string                       // path to key
	Issuer                     string                       // issuer for OCSP
	TLSConfig                  *tls.Config                  // tls configuration
	Timeout                    time.Duration                // timeout for sleep after network error in seconds
	OCSPInterval               time.Duration                // interval between OCSP updates when OCSP responder nextupdate is nil, otherwise wait till next update
	SessionKeyRotationInterval time.Duration                // log
	TCPKeepAliveInterval       time.Duration                // tcp keep alive interval
	copyWG                     sync.WaitGroup               // waitgroup for the copy goroutines, to log in sync after they exit
	listen                     func() (net.Listener, error) // listen on accept function
	dial                       func() (net.Conn, error)     // dial on connect function
	logInterface               chan []interface{}           // logging channel
	nodeWG                     sync.WaitGroup
}

// extract data from the array of paths to certs/keys/keypairs
// then start the node in server/client mode with the data
func (n *node) run() {
	n.log("initializing")
	defer n.nodeWG.Done()
	defer n.log("exiting")
	// you can use 5000 as a port instead of :5000
	if !strings.Contains(n.Accept, ":") {
		n.Accept = ":" + n.Accept
	}
	if !strings.Contains(n.Connect, ":") {
		n.Connect = ":" + n.Connect
	}
	n.Timeout *= time.Second
	n.OCSPInterval *= time.Second
	n.SessionKeyRotationInterval *= time.Second
	n.TCPKeepAliveInterval *= time.Second
	n.TLSConfig = new(tls.Config)
	n.TLSConfig.CipherSuites = []uint16{
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
	n.TLSConfig.MinVersion = tls.VersionTLS11
	n.TLSConfig.NextProtos = []string{"http/1.1"}
	switch strings.ToLower(n.Mode) {
	case "server":
		n.log(n.server())
	case "client":
		n.log(n.client())
	default:
		n.log("no valid mode")
	}
}

type tcpKeepAliveListener struct {
	*net.TCPListener
	tcpKeepAliveInterval time.Duration
}

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

// run node as server
func (n *node) server() error {
	n.log("loading cert", n.Cert, "and key", n.Key)
	cert, err := tls.LoadX509KeyPair(n.Cert, n.Key)
	if err != nil {
		return err
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return err
	}
	if cert.Leaf.OCSPServer != nil {
		n.log("OCSP servers found", cert.Leaf.OCSPServer)
		n.log("initalizing OCSP stapling")
		OCSPC := OCSPCert{n: n, cert: &cert}
		n.log("reading issuer", n.Issuer)
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
		n.log("creating the OCSP request")
		OCSPC.req, err = ocsp.CreateRequest(OCSPC.cert.Leaf, OCSPC.issuer, nil)
		if err != nil {
			return err
		}
		n.log("starting stapleLoop")
		go OCSPC.updateStapleLoop()
		n.TLSConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			OCSPC.RLock()
			defer OCSPC.RUnlock()
			return OCSPC.cert, nil
		}
		//	} else {
		//		TLSConfig.Certificates = []tls.Certificate{cert}
		//TODO FIX THIS BUG
	}
	n.TLSConfig.Certificates = []tls.Certificate{cert}
	n.TLSConfig.PreferServerCipherSuites = true
	updateKey := func(key *[32]byte) {
		if _, err := rand.Read((*key)[:]); err != nil {
			n.log(err)
			n.log("cannot create new session ticket key")
		}
	}
	n.log("initializing session ticket key rotation")
	keys := make([][32]byte, 3)
	updateKey(&keys[0])
	updateKey(&keys[1])
	updateKey(&keys[2])
	go func() {
		for {
			n.TLSConfig.SetSessionTicketKeys(keys)
			time.Sleep(n.SessionKeyRotationInterval)
			n.log("updating session ticket rotation keys")
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
		return tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener), n.TCPKeepAliveInterval}, n.TLSConfig), err
	}
	n.dial = func() (c net.Conn, err error) {
		c, err = net.Dial("tcp", n.Connect)
		if err != nil {
			return
		}
		err = c.(*net.TCPConn).SetKeepAlive(true)
		if err != nil {
			return
		}
		err = c.(*net.TCPConn).SetKeepAlivePeriod(n.TCPKeepAliveInterval)
		return
	}
	n.listenAndServe()
	return nil
}

type OCSPCert struct {
	cert       *tls.Certificate
	req        []byte
	issuer     *x509.Certificate
	nextUpdate time.Time
	sync.RWMutex
	n *node
}

func (OCSPC *OCSPCert) updateStaple() error {
	OCSPC.n.log("sending request to OCSP servers", OCSPC.cert.Leaf.OCSPServer)
	var resp *http.Response
	for i := 0; i < len(OCSPC.cert.Leaf.OCSPServer); i++ {
		req, err := http.NewRequest("GET", OCSPC.cert.Leaf.OCSPServer[i]+"/"+base64.StdEncoding.EncodeToString(OCSPC.req), nil)
		if err != nil {
			return err
		}
		req.Header.Add("Content-Language", "application/ocsp-request")
		req.Header.Add("Accept", "application/ocsp-response")
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		OCSPC.n.log(err)
		if i+1 == len(OCSPC.cert.Leaf.OCSPServer) {
			return errors.New("could not request OCSP servers")
		}
	}
	OCSPC.n.log("reading response")
	OCSPStaple, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	OCSPC.n.log("parsing response")
	OCSPResp, err := ocsp.ParseResponse(OCSPStaple, OCSPC.issuer)
	if err != nil {
		return err
	}
	if OCSPResp.NextUpdate.IsZero() { //TODO check if this works
		OCSPC.nextUpdate = time.Now().Add(OCSPC.n.OCSPInterval)
	} else {
		OCSPC.nextUpdate = OCSPResp.NextUpdate
	}
	OCSPC.n.log("updating OCSP staple")
	OCSPC.Lock()
	OCSPC.cert.OCSPStaple = OCSPStaple
	OCSPC.Unlock()
	OCSPC.n.log("next OCSP staple at", OCSPC.nextUpdate)
	return nil
}

func (OCSPC *OCSPCert) updateStapleLoop() {
	for {
		if err := OCSPC.updateStaple(); err == nil {
			OCSPC.n.log("stapleLoop: sleeping for", OCSPC.nextUpdate.Sub(time.Now()).Seconds())
			time.Sleep(OCSPC.nextUpdate.Sub(time.Now()))
		} else {
			if time.Now().After(OCSPC.nextUpdate) {
				OCSPC.Lock()
				OCSPC.cert.OCSPStaple = nil
				OCSPC.Unlock()
			}
			OCSPC.n.log(err)
			OCSPC.n.log("stapleLoop: sleeping for", int64(OCSPC.n.Timeout))
			time.Sleep(OCSPC.n.Timeout)
		}
	}
}

// run node as client
func (n *node) client() error {
	var certPool *x509.CertPool
	if n.Cert != "" {
		certPool = x509.NewCertPool()
		raw, err := ioutil.ReadFile(n.Cert)
		if err != nil {
			return err
		}
		n.log("adding", n.Cert, "to pool")
		certPool.AppendCertsFromPEM(raw)
	}
	host, _, err := net.SplitHostPort(n.Connect)
	if err != nil {
		return err
	}
	if host == "" {
		host = "localhost"
	}
	n.TLSConfig.ServerName = host
	n.TLSConfig.RootCAs = certPool
	n.dial = func() (net.Conn, error) {
		d := &net.Dialer{KeepAlive: n.TCPKeepAliveInterval}
		return tls.DialWithDialer(d, "tcp", n.Connect, n.TLSConfig)
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

//TODO the go way with an interface as arguemen
func (n *node) listenAndServe() {
	handleError := func(err error) {
		n.log(err)
		n.log("sleeping for", int64(n.Timeout))
		time.Sleep(n.Timeout)
	}
	listenAndServeErr := func() error {
		ln, err := n.listen()
		if err != nil {
			return err
		}
		defer ln.Close()
		n.log("listening on", n.Accept)
		for {
			c1, err := ln.Accept()
			if err != nil {
				return err
			}
			n.log("connection from", c1.RemoteAddr())
			go func(c1 net.Conn) {
				n.log("connecting to", n.Connect)
				c2, err := n.dial()
				if err != nil {
					n.log(err)
					c1.Close()
					return
				}
				n.log("beginning tunnel from", c1.RemoteAddr(), "to", c1.LocalAddr(), "to", c2.LocalAddr(), "to", c2.RemoteAddr())
				n.copyWG.Add(2)
				go n.copy(c1, c2)
				go n.copy(c2, c1)
				n.copyWG.Wait()
				n.log("closed tunnel from", c1.RemoteAddr(), "to", c1.LocalAddr(), "to", c2.LocalAddr(), "to", c2.RemoteAddr())
			}(c1)
		}
	}
	for {
		err := listenAndServeErr()
		handleError(err)
	}
}

// copy all data from src to dst
func (n *node) copy(dst io.WriteCloser, src io.Reader) {
	if _, err := io.Copy(dst, src); err != nil {
		n.log(err)
	}
	n.copyWG.Done()
	dst.Close()
}

// append node info to arguments and send to logging channel
func (n *node) log(v ...interface{}) {
	n.logInterface <- append([]interface{}{"-->", n.Mode + n.Name + " -/"}, v...)
}
