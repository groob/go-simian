package simian

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientAuth(t *testing.T) {
	ts := newTestServer(t)
	defer ts.teardown()

	conf, err := loadConfig("testdata/settings.cfg")
	if err != nil {
		t.Fatal(err)
	}
	conf.ClientSSLPath = "testdata/ssl"
	conf.Certname = "client-identity.pem"
	client, err := NewClient(ts.server.URL, WithConfig(conf))
	if err != nil {
		t.Fatal(err)
	}
	gotToken := strings.Split(client.Auth1Token(), "=")[1]
	if have, want := gotToken, ts.token; have != want {
		t.Errorf("have %s, want %s", have, want)
	}
}

type testServer struct {
	CACertificate *x509.Certificate
	Certificate   []byte // PEM data
	PrivateKey    *rsa.PrivateKey
	serverNonce   string
	server        *httptest.Server
	token         string

	teardown func()
}

func (ts *testServer) auth(w http.ResponseWriter, r *http.Request) {
	// auth is done in two steps.
	// during the first leg, the client will send the nonce as n
	// durin ghte second leg, the client will send signature with s, m values
	nonce := r.FormValue("n")
	if nonce != "" {
		ts.authStepA(w, r)
		return
	}
	ts.authStepB(w, r)
}

func (ts *testServer) authStepA(w http.ResponseWriter, r *http.Request) {
	clientNonce := r.FormValue("n")
	tmpM := strings.Join([]string{clientNonce, ts.serverNonce}, " ")
	hashed := sha1.Sum([]byte(tmpM))
	outSig, err := rsa.SignPKCS1v15(rand.Reader, ts.PrivateKey, crypto.SHA1, hashed[:])
	if err != nil {
		http.Error(w, "sign msg "+err.Error(), http.StatusInternalServerError)
		return
	}
	outSigb64 := base64.URLEncoding.EncodeToString(outSig)
	resp := strings.Join([]string{clientNonce, ts.serverNonce, outSigb64}, " ")
	w.Write([]byte(resp))
}

func (ts *testServer) authStepB(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:  "Auth1Token",
		Value: ts.token,
	}
	http.SetCookie(w, cookie)
}

func newTestServer(t *testing.T) *testServer {
	ts := &testServer{}
	ts.loadCerts(t)
	sn, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		t.Fatalf("creating server nonce: %s", err)
	}
	ts.serverNonce = sn.String()
	ts.token = "SERVER_COOKIE"

	ts.server = httptest.NewServer(http.HandlerFunc(ts.auth))
	ts.teardown = ts.server.Close
	return ts
}

func (ts *testServer) loadCerts(t *testing.T) {
	caPath := "testdata/ssl/ca_public_cert.pem"
	certPath := "testdata/ssl/server_public_cert.pem"
	pkeyPath := "testdata/ssl/private_keys/server_private_key.pem"
	data, err := ioutil.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	ts.CACertificate, err = loadCert(data)
	if err != nil {
		t.Fatal(err)
	}

	ts.Certificate, err = ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	data, err = ioutil.ReadFile(pkeyPath)
	if err != nil {
		t.Fatal(err)
	}

	ts.PrivateKey, err = loadKey(data)
	if err != nil {
		t.Fatalf("loading private key: %s", err)
	}
}
