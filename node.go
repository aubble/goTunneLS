package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/ocsp"
	"io"
	"io/ioutil"
	"net"
	"net/http"
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
type node struct {
	Name         string                       // name for logging
	Mode         string                       // tunnel mode
	Accept       string                       // listen address
	Connect      string                       // connect address
	Cert         string                       // path to cert
	Key          string                       // path to key
	Issuer       string                       // issuer for OCSP
	Timeout      time.Duration                // timeout for sleep after network error in seconds
	OCSPInterval time.Duration                // interval between OCSP updates when OCSP responder nextupdate is nil, otherwise wait till next update
	copyWG       sync.WaitGroup               // waitgroup for the copy goroutines, to log in sync after they exit
	listen       func() (net.Listener, error) // listen on accept function
	dial         func() (net.Conn, error)     // dial on connect function
	logInterface chan []interface{}           // logging channel
	nodeWG       sync.WaitGroup
}

// extract data from the array of paths to certs/keys/keypairs
// then start the node in server/client mode with the data
func (n *node) run() {
	n.log("starting up")
	defer n.log("exiting")
	defer n.nodeWG.Done()
	// you can use 5000 as a port instead of :5000
	if !strings.Contains(n.Accept, ":") {
		n.Accept = ":" + n.Accept
	}
	if !strings.Contains(n.Connect, ":") {
		n.Connect = ":" + n.Connect
	}
	switch strings.ToLower(n.Mode) {
	case "server":
		n.log(n.server())
	case "client":
		n.log(n.client())
	default:
		n.log("no valid mode")
	}
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
	TLSConfig := new(tls.Config)
	if cert.Leaf.OCSPServer != nil {
		n.log("OCSP servers found", cert.Leaf.OCSPServer)
		n.log("initalizing OCSP stapling")
		OCSPC := OCSPCert{n: n, cert: &cert}
		OCSPC.n.log("reading issuer", n.Issuer)
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
		OCSPC.n.log("creating OCSP request")
		OCSPC.req, err = ocsp.CreateRequest(OCSPC.cert.Leaf, OCSPC.issuer, nil)
		if err != nil {
			return err
		}
		OCSPC.n.log("requesting inital OCSP response")
		err = OCSPC.updateStaple()
		if err != nil {
			return err
		}
		OCSPC.n.log("starting stapleLoop")
		go OCSPC.updateStapleLoop()
		TLSConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			OCSPC.RLock()
			defer OCSPC.RUnlock()
			return OCSPC.cert, nil
		}
	}
	TLSConfig.Certificates = []tls.Certificate{cert}
	TLSConfig.CipherSuites = []uint16{
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
	TLSConfig.PreferServerCipherSuites = true
	TLSConfig.MinVersion = tls.VersionTLS11
	TLSConfig.NextProtos = []string{"http/1.1"}
	n.listen = func() (net.Listener, error) {
		return tls.Listen("tcp", n.Accept, TLSConfig)
	}
	n.dial = func() (net.Conn, error) {
		return net.Dial("tcp", n.Connect)
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
		if i == len(OCSPC.cert.Leaf.OCSPServer) {
			return errors.New("could not request OCSP servers")
		}
	}
	OCSPC.n.log("reading response")
	OCSPStaple, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	OCSPC.n.log("parsing response")
	OCSPResp, _ := ocsp.ParseResponse(OCSPStaple, OCSPC.issuer)
	if OCSPResp.NextUpdate != (time.Time{}) {
		OCSPC.nextUpdate = OCSPResp.NextUpdate
	} else {
		OCSPC.nextUpdate = time.Now().Add(time.Second * OCSPC.n.OCSPInterval)
	}
	OCSPC.n.log("updating OCSP staple")
	cert := *OCSPC.cert
	cert.OCSPStaple = OCSPStaple
	OCSPC.Lock()
	OCSPC.cert = &cert
	OCSPC.Unlock()
	resp.Body.Close()
	OCSPC.n.log("next OCSP update at", OCSPC.nextUpdate)
	return nil
}

func (OCSPC *OCSPCert) updateStapleLoop() {
	time.Sleep(OCSPC.nextUpdate.Sub(time.Now()))
	for {
		if err := OCSPC.updateStaple(); err == nil {
			OCSPC.n.log("stapleLoop: sleeping till", int64(OCSPC.n.Timeout))
			time.Sleep(OCSPC.nextUpdate.Sub(time.Now()))
		} else {
			OCSPC.n.log(err)
			OCSPC.n.log("stapleLoop: sleeping for", int64(OCSPC.n.Timeout))
			time.Sleep(time.Second * OCSPC.n.Timeout)
		}
	}
}

// run node as client
func (n *node) client() error {
	var certPool *x509.CertPool //todo check if even needed
	if n.Cert != "" {
		certPool = x509.NewCertPool()
		raw, err := ioutil.ReadFile(n.Cert)
		if err != nil {
			return err
		}
		n.log("adding", n.Cert, "to pool")
		certPool.AppendCertsFromPEM(raw)
	}
	n.listen = func() (net.Listener, error) {
		return net.Listen("tcp", n.Accept)
	}
	TLSConfig := new(tls.Config)
	host, _, err := net.SplitHostPort(n.Connect)
	if err != nil {
		return err
	}
	if host == "" {
		host = "localhost"
	}
	TLSConfig.ServerName = host
	TLSConfig.RootCAs = certPool
	TLSConfig.CipherSuites = []uint16{
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
	TLSConfig.MinVersion = tls.VersionTLS11
	TLSConfig.NextProtos = []string{"http/1.1"}
	n.dial = func() (net.Conn, error) {
		return tls.Dial("tcp", n.Connect, TLSConfig)
	}
	n.listenAndServe()
	return nil
}

func (n *node) listenAndServe() {
	for {
		ln, err := n.listen()
		if err != nil {
			n.log(err)
			n.log("sleeping for", int64(n.Timeout))
			time.Sleep(time.Second * n.Timeout)
			continue
		}
		n.log("listening on", n.Accept)
		for {
			c1, err := ln.Accept()
			if err != nil {
				n.log(err)
				n.log("sleeping for", int64(n.Timeout))
				time.Sleep(time.Second * n.Timeout)
				ln.Close()
				break
			}
			n.log("connection from", c1.RemoteAddr().String())
			go func() {
				n.log("connecting to", n.Connect)
				c2, err := n.dial()
				if err != nil {
					n.log(err)
					c1.Close()
					return
				}
				n.log("beginning tunnel from", c1.RemoteAddr().String(),
					"to", c1.LocalAddr().String(),
					"to", c2.LocalAddr().String(),
					"to", c2.RemoteAddr().String())
				n.copyWG.Add(2)
				go n.copy(c1, c2)
				go n.copy(c2, c1)
				n.copyWG.Wait()
				n.log("closed tunnel from", c1.RemoteAddr().String(),
					"to", c1.LocalAddr().String(),
					"to", c2.LocalAddr().String(),
					"to", c2.RemoteAddr().String())
			}()
		}
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
	n.logInterface <- append([]interface{}{"--> " + n.Mode + n.Name + " -/"}, v...)
}

//TODO renaming variables, CODE REVIEW, better logging
