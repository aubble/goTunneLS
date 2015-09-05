package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPCert represents a tls.Certificate that has its OCSPStaple field constantly updated
type OCSPCert struct {
	// inner certificate to modify
	cert       *tls.Certificate

	// request to send to OCSP responder
	req        []byte

	// issuer of cert to verify OCSP response
	issuer     *x509.Certificate

	// time until checking OCSP responder again
	nextUpdate time.Time

	// for concurrent access
	sync.RWMutex

	// spawning node for logging purposes
	n *node
}

// updateStaple concurrently updates the OCSP staple of OCSPC.cert
func (OCSPC *OCSPCert) updateStaple() error {
	OCSPC.n.logln("sending request to OCSP servers", OCSPC.cert.Leaf.OCSPServer)
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
		OCSPC.n.logln(err)
		if i+1 == len(OCSPC.cert.Leaf.OCSPServer) {
			return errors.New("could not request OCSP servers")
		}
	}
	OCSPC.n.logln("reading response")
	OCSPStaple, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	OCSPC.n.logln("parsing response")
	OCSPResp, err := ocsp.ParseResponse(OCSPStaple, OCSPC.issuer)
	if err != nil {
		return err
	}
	if OCSPResp.NextUpdate.IsZero() {
		OCSPC.nextUpdate = time.Now().Add(OCSPC.n.OCSPInterval)
	} else {
		OCSPC.nextUpdate = OCSPResp.NextUpdate
	}
	OCSPC.n.logln("updating OCSP staple")
	OCSPC.Lock()
	OCSPC.cert.OCSPStaple = OCSPStaple
	OCSPC.Unlock()
	OCSPC.n.logln("next OCSP staple at", OCSPC.nextUpdate)
	return nil
}

// forever loops updating the OCSP staple of OCSPC.cert
// after every update sleeps until next update or the
// OCSP staple interval configured in the node
func (OCSPC *OCSPCert) updateStapleLoop() {
	for {
		if err := OCSPC.updateStaple(); err == nil {
			OCSPC.n.logf("OCSP staple loop sleeping for %vs", OCSPC.nextUpdate.Sub(time.Now()).Seconds(),)
			time.Sleep(OCSPC.nextUpdate.Sub(time.Now()))
		} else {
			if time.Now().After(OCSPC.nextUpdate) {
				OCSPC.Lock()
				OCSPC.cert.OCSPStaple = nil
				OCSPC.Unlock()
			}
			OCSPC.n.logln(err)
			OCSPC.n.logf("OCSP staple loop sleeping for %vs", float64(OCSPC.n.Timeout/time.Second))
			time.Sleep(OCSPC.n.Timeout)
		}
	}
}

func (OCSPC *OCSPCert) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	OCSPC.RLock()
	defer OCSPC.RUnlock()
	return OCSPC.cert, nil
}
