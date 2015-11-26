package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

// node implements one end of a TunneLS tunnel
type node struct {
	// name for logging
	Name string

	// node mode
	Mode string

	// listen address
	Accept string

	// dial address
	Connect string

	// path to ca
	CA string

	// path to certificate chain presented to other side of the connection
	Cert string

	// path to key for certificate
	Key string

	// Duration for sleep after network error in seconds, default is 15
	Timeout time.Duration

	// interval between session ticket key rotations in seconds, default is 28800 or 8 hours
	SessionTicketKeyRotationInterval time.Duration

	// tcp keep alive interval in seconds, default is 15
	TCPKeepAliveInterval time.Duration

	// ciphers to use
	Ciphers []string

	// controls logging the actual writing/reading of data
	LogData bool

	// type of client authentication to use
	ClientAuth string

	// path to CRL for client-authentication
	CRL string

	// tls configuration
	tlsConfig *tls.Config

	// wg for the copy goroutines, to write logs in sync after they exit
	copyWG sync.WaitGroup

	// listen on Accept address
	listen func() (net.Listener, error)

	// dials the Connect address
	dial func() (net.Conn, error)
}

func (n *node) parseFields() {
	// get real time.Duration for time fields
	n.Timeout *= time.Second
	n.SessionTicketKeyRotationInterval *= time.Second
	n.TCPKeepAliveInterval *= time.Second
	n.tlsConfig.CipherSuites = n.parseCiphers()
}

// set defaults for time fields
func (n *node) setDefaults() {
	if n.Timeout == 0 {
		n.Timeout = 15
	}
	if n.SessionTicketKeyRotationInterval == 0 {
		n.SessionTicketKeyRotationInterval = 28800
	}
	if n.TCPKeepAliveInterval == 0 {
		n.TCPKeepAliveInterval = 15
	}
}

// initialize and then run the node according to its mode
// also set some mutual TLSConfig parameters
func (n *node) run(wg *sync.WaitGroup) {
	n.logln("initializing")
	defer func() {
		if r := recover(); r != nil {
			n.logln(r)
		}
		n.logln("exiting")
		wg.Done()
	}()
	// you can use 5000 as a port instead of :5000
	if !strings.Contains(n.Accept, ":") {
		n.Accept = ":" + n.Accept
	}
	if !strings.Contains(n.Connect, ":") {
		n.Connect = ":" + n.Connect
	}
	n.setDefaults()
	n.parseFields()
	// set mutual TLSConfig fields
	n.tlsConfig = new(tls.Config)
	n.tlsConfig.MinVersion = tls.VersionTLS11
	n.tlsConfig.NextProtos = []string{"http/1.1"}
	if n.Cert != "" {
		n.logf("loading cert %s and key %s", n.Cert, n.Key)
		var err error
		n.tlsConfig.Certificates = make([]tls.Certificate, 1)
		n.tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(n.Cert, n.Key)
		if err != nil {
			panic(err)
		}
	}
	switch strings.ToLower(n.Mode) {
	case "server":
		n.server()
	case "client":
		n.client()
	default:
		panic("invalid mode")
	}
}

func (n *node) readCAIntoPool() (pool *x509.CertPool) {
	if n.CA != "" {
		ca, err := ioutil.ReadFile(n.CA)
		if err != nil {
			panic(err)
		}
		pool = x509.NewCertPool()
		n.logf("adding %s to CA pool", n.CA)
		ok := pool.AppendCertsFromPEM(ca)
		if ok == false {
			panic("could not append cert to RootCAs pool")
		}
	}
	return
}

func (n *node) parseCiphers() []uint16 {
	var (
		ok bool
		c  = make([]uint16, len(n.Ciphers))
	)
	for i, s := range n.Ciphers {
		c[i], ok = ciphers[s]
		if !ok {
			panic(fmt.Sprintf("%s is not a valid cipher", s))
		}
	}
	return c
}

var clientAuthTypes = map[string]tls.ClientAuthType{
	"NoClientCert":               tls.NoClientCert,
	"RequestClientCert":          tls.RequestClientCert,
	"RequireAnyClientCert":       tls.RequireAnyClientCert,
	"VerifyClientCertIfGiven":    tls.VerifyClientCertIfGiven,
	"RequireAndVerifyClientCert": tls.RequireAndVerifyClientCert,
}

func (n *node) parseClientAuthType() tls.ClientAuthType {
	ca, ok := clientAuthTypes[n.ClientAuth]
	if !ok {
		panic(fmt.Sprintf("%s is not a valid client authentication type", n.ClientAuth))
	}
	return ca
}

func (n *node) initializeSessionTicketKeyRotation(){
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
			n.logf("session ticket key rotation sleeping for %vs", float64(n.SessionTicketKeyRotationInterval/time.Second))
			time.Sleep(n.SessionTicketKeyRotationInterval)
			n.logln("updating session ticket rotation keys")
			keys[0] = keys[1]
			keys[1] = keys[2]
			updateKey(&keys[2])
		}
	}()
}

// run the node as a server
// accept TLS TCP and dial plain TCP
// then copying all data between the two connections
func (n *node) server() {
	if n.ClientAuth != "" {
		n.tlsConfig.ClientAuth = n.parseClientAuthType()
	}
	n.tlsConfig.PreferServerCipherSuites = true
	n.tlsConfig.ClientCAs = n.readCAIntoPool()
	n.initializeSessionTicketKeyRotation()
	n.listen = func() (tlsLn net.Listener, err error) {
		ln, err := net.Listen("tcp", n.Accept)
		if err != nil {
			return nil, err
		}
		tlsLn, err = tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener), n.TCPKeepAliveInterval}, n.tlsConfig), err
		if n.CRL != "" {
			tlsLn = &crlListener{tlsLn, n}
		}
		return
	}
	n.dial = func() (c net.Conn, err error) {
		d := &net.Dialer{KeepAlive: n.TCPKeepAliveInterval}
		return d.Dial("tcp", n.Connect)
	}
	n.listenAndServe()
}

// runs the node as a client
// accept plain TCP and dial TLS TCP
// then copying all data between the two connections
func (n *node) client() {
	host, _, err := net.SplitHostPort(n.Connect)
	if err != nil {
		panic(err)
	}
	if host == "" {
		host = "localhost"
	}
	n.tlsConfig.ServerName = host
	n.tlsConfig.RootCAs = n.readCAIntoPool()
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
}

// listenAndServeErr accepts connections on n.Accept
// it then dials n.Connect and copies all data between the two
// connections. Listening is done with the n.Listen function
// and dialing is done with the n.Dial function. Any errors are returned
func (n *node) listenAndServeErr() error {
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
		go n.dialAndTunnel(c1)
	}
}

// ListenAndServe creates a loop to call listenAndServeErr and then
// on the return of errors timeout and restart
func (n *node) listenAndServe() {
	for {
		err := n.listenAndServeErr()
		n.logln(err)
		n.logf("sleeping for %vs", float64(n.Timeout/time.Second))
		time.Sleep(n.Timeout)
	}
}

// takes the first conn, dials the connection address, then creates a tunnel between the two
func (n *node) dialAndTunnel(c1 net.Conn) {
	n.logln("connecting to", n.Connect)
	c2, err := n.dial()
	if err != nil {
		c1.Close()
		n.logln(err)
		return
	}
	n.tunnel(c1, c2)
}

// creates the tunnel between c1 and c2
func (n *node) tunnel(c1, c2 net.Conn) {
	n.logf("beginning tunnel from %s to %s then %s to %s", c1.RemoteAddr(), c1.LocalAddr(), c2.LocalAddr(), c2.RemoteAddr())
	n.copyWG.Add(2)
	go n.copy(c1, c2)
	go n.copy(c2, c1)
	n.copyWG.Wait()
	n.logf("closed tunnel from %s to %s then %s to %s", c1.RemoteAddr(), c1.LocalAddr(), c2.LocalAddr(), c2.RemoteAddr())
}

// copy copies all data from src to dst
// then calls Done() on the copyWG to allow
// the calling routine to stop waiting followed by closing dst
func (n *node) copy(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	var f func(io.Writer, io.Reader) (int64, error)
	if n.LogData {
		f = n.copyBuffer
	} else {
		f = io.Copy
	}
	if _, err := f(dst, src); err != nil {
		n.logln(err)
	}
	n.copyWG.Done()
}

func (n *node) copyBuffer(dst io.Writer, src io.Reader) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		n.logf("read %d bytes", nr)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
			n.logf("written %d bytes", nw)
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}

// logln logs to the global fileLogger as global
// arguments are handled same as fmt.Println
func (n *node) logln(v ...interface{}) {
	l.println(append([]interface{}{"-->", n.Mode + n.Name, "-/"}, v...)...)
}

// logf logs to the global fileLogger as global
// arguments are handled same as fmt.Printf
func (n *node) logf(format string, v ...interface{}) {
	l.printf("--> "+n.Mode+n.Name+" -/ "+format, v...)
}

var ciphers = map[string]uint16{
	"FALLBACK_SCSV":                       tls.TLS_FALLBACK_SCSV,
	"RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	"RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE_RSA_WITH_AES_256_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
}

// tcpKeepAliveListener wraps a TCPListener to
// activate TCP keep alive on every accepted connection
type tcpKeepAliveListener struct {
	// inner TCPlistener
	*net.TCPListener

	// interval between keep alives to set on accepted conns
	keepAliveInterval time.Duration
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
	err = tc.SetKeepAlivePeriod(ln.keepAliveInterval)
	if err != nil {
		return
	}
	return tc, nil
}

type crlListener struct {
	net.Listener
	n *node
}

func (ln *crlListener) Accept() (net.Conn, error) {
listen:
	for {
		c, err := ln.Listener.Accept()
		if err != nil {
			return nil, err
		}
		clrRaw, err := ioutil.ReadFile(ln.n.CRL)
		if err != nil {
			return nil, err
		}
		clr, err := x509.ParseCRL(clrRaw)
		if err != nil {
			return nil, err
		}
		tlsC := c.(*tls.Conn)
		err = tlsC.Handshake()
		if err != nil {
			ln.n.logln(err)
			continue
		}
		certs := tlsC.ConnectionState().PeerCertificates
		cert := certs[len(certs)-1]
		for _, revoked := range clr.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				ln.n.logf("got revoked %s certificate from %s", cert.Subject.CommonName, c.RemoteAddr())
				continue listen
			}
		}
		ln.n.logf("accepted %s certificate from %s", cert.Subject.CommonName, c.RemoteAddr())
		return c, err
	}
}
