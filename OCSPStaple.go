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
