package core

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

func (e *Engine) ocsp(cert, issuer *x509.Certificate) (Revocation, bool) {
	if len(cert.OCSPServer) == 0 {
		return Revocation{}, false
	}
	result := Revocation{Certificate: fingerprint(cert.Raw), Status: "UNAVAILABLE", Method: "OCSP", Checked: time.Now().UTC().Format(time.RFC3339)}
	request, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		result.Detail = err.Error()
		return result, true
	}
	for _, endpoint := range cert.OCSPServer {
		if e.requests >= 64 {
			result.Detail = "network request limit reached"
			break
		}
		e.requests++
		u, er := url.Parse(endpoint)
		if er != nil {
			continue
		}
		if er = e.checkURL(u); er != nil {
			e.log("OCSP", endpoint, "BLOCKED", er.Error())
			continue
		}
		req, er := http.NewRequestWithContext(e.ctx, "POST", endpoint, bytes.NewReader(request))
		if er != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")
		resp, er := e.client.Do(req)
		if er != nil {
			e.log("OCSP", endpoint, "ERROR", er.Error())
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
		resp.Body.Close()
		if readErr != nil || len(body) > 2<<20 || resp.StatusCode != http.StatusOK {
			e.log("OCSP", endpoint, "ERROR", fmt.Sprintf("HTTP %d / response error", resp.StatusCode))
			continue
		}
		// ParseResponseForCert verifies the response signature, delegated responder
		// authorization and certificate serial against the issuer.
		verified, er := ocsp.ParseResponseForCert(body, cert, issuer)
		if er != nil {
			e.log("OCSP", endpoint, "UNVERIFIED", er.Error())
			continue
		}
		now := time.Now()
		if verified.Certificate != nil && (now.Before(verified.Certificate.NotBefore) || now.After(verified.Certificate.NotAfter)) {
			e.log("OCSP", endpoint, "UNVERIFIED", "Delegated responder certificate outside validity period")
			continue
		}
		if verified.ThisUpdate.IsZero() || (!verified.NextUpdate.IsZero() && verified.NextUpdate.Before(verified.ThisUpdate)) {
			e.log("OCSP", endpoint, "UNVERIFIED", "Invalid OCSP time interval")
			continue
		}
		if verified.ThisUpdate.After(now.Add(5*time.Minute)) || (!verified.NextUpdate.IsZero() && now.After(verified.NextUpdate)) {
			e.log("OCSP", endpoint, "STALE", "OCSP response outside freshness window")
			result.Status = "STALE"
			result.Detail = "OCSP response outside freshness window"
			continue
		}
		if verified.NextUpdate.IsZero() && now.Sub(verified.ThisUpdate) > 24*time.Hour {
			e.log("OCSP", endpoint, "STALE", "No nextUpdate and thisUpdate older than 24 hours")
			continue
		}
		switch verified.Status {
		case ocsp.Good:
			result.Status = "GOOD"
		case ocsp.Revoked:
			result.Status = "REVOKED"
			result.Detail = verified.RevokedAt.Format(time.RFC3339)
		default:
			result.Status = "UNKNOWN"
		}
		result.Source = "ONLINE: " + endpoint
		e.log("OCSP", endpoint, "VERIFIED", result.Status)
		return result, true
	}
	if result.Detail == "" {
		result.Detail = "No verified and fresh OCSP response"
	}
	return result, true
}
