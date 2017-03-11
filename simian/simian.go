package simian

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

type Client struct {
	*http.Client
	CACert         *x509.Certificate
	ServerCert     *x509.Certificate
	MachineCert    *x509.Certificate
	MachineKey     *rsa.PrivateKey
	rawMachineCert []byte // PEM format

	ServerURL *url.URL // munki repo url
	authURL   string
	authToken string

	conf         *Config
	customConfig bool
}

type Option func(*Client)

// WithConfig overrides the default client config.
func WithConfig(conf *Config) Option {
	return func(c *Client) {
		c.conf = conf
		c.customConfig = true
	}
}

// NewClient returns an authenticated Simian client.
func NewClient(repoURL string, opts ...Option) (*Client, error) {
	cookieJar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: cookieJar}
	client := new(Client)
	client.Client = httpClient
	su, err := url.Parse(repoURL)
	if err != nil {
		return nil, errors.Wrapf(err, "parsing repo url: %s", repoURL)
	}
	client.ServerURL = su

	for _, opt := range opts {
		opt(client)
	}

	if !client.customConfig {
		client.conf, err = loadConfig(configFilePath)
		if err != nil {
			return nil, errors.Wrap(err, "loading settings")
		}
	}

	if err := client.loadPKI(); err != nil {
		return nil, err
	}

	if err := client.authenticate(); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) Auth1Token() string {
	return c.authToken
}

// default paths of simian certificates
const (
	serverPublicCertFile = "server_public_cert.pem"
	caCertFile           = "ca_public_cert.pem"
	clientSSLPriv        = "private_keys"
	clientSSLCerts       = "certs"
	configFilePath       = "/etc/simian/settings.cfg"
)

// loadPKI loads and validates server and client certificates
func (c *Client) loadPKI() error {
	caCertPath := filepath.Join(c.conf.ClientSSLPath, caCertFile)
	data, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return errors.Wrapf(err, "reading %s", caCertPath)
	}
	c.CACert, err = loadCert(data)
	if err != nil {
		return errors.Wrap(err, "loading CA Certificate")
	}

	serverPublicCertPath := filepath.Join(c.conf.ClientSSLPath, serverPublicCertFile)
	data, err = ioutil.ReadFile(serverPublicCertPath)
	if err != nil {
		return errors.Wrapf(err, "reading %s", serverPublicCertPath)
	}
	c.ServerCert, err = loadCert(data)
	if err != nil {
		return errors.Wrap(err, "loading server identity certificate")
	}

	err = c.ServerCert.CheckSignatureFrom(c.CACert)
	if err != nil {
		return errors.Wrapf(err,
			"verifying that %s is signed by %s", serverPublicCertPath,
			caCertPath)
	}

	if err := c.loadMachineCert(); err != nil {
		return errors.Wrap(err, "loading client certificate")
	}
	err = c.MachineCert.CheckSignatureFrom(c.CACert)
	if err != nil {
		return errors.Wrapf(err,
			"verifying that client cert is signed by CA: %s",
			caCertPath)
	}

	if err := c.loadPrivateKey(); err != nil {
		return errors.Wrap(err, "loading client certificate private key")
	}

	return nil
}

// loads either config.Certname or first cert in folder
func (c *Client) loadMachineCert() error {
	var pubCertPath string
	pub := filepath.Join(c.conf.ClientSSLPath, clientSSLCerts)
	if c.conf.Certname == "" {
		// load first cert in path
		all, err := ioutil.ReadDir(pub)
		if err != nil {
			return errors.Wrap(err, "loading client certs dir")
		}
		if len(all) < 1 {
			return errors.New("no certs found in path: " + pub)
		}
		pubCertPath = filepath.Join(pub, all[0].Name())
	} else {
		pubCertPath = filepath.Join(pub, c.conf.Certname)
	}
	data, err := ioutil.ReadFile(pubCertPath)
	if err != nil {
		return errors.Wrapf(err, "reading cert file %s", pubCertPath)
	}
	// the PEM bytes of the client certificate will be used to construct
	// the signature sent during Authenticate
	c.rawMachineCert = data
	c.MachineCert, err = loadCert(data)
	if err != nil {
		return errors.Wrapf(err, "loading client certificate %s", pubCertPath)
	}
	return nil
}

func (c *Client) loadPrivateKey() error {
	var pkeyPath string
	priv := filepath.Join(c.conf.ClientSSLPath, clientSSLPriv)
	if c.conf.Certname == "" {
		all, err := ioutil.ReadDir(priv)
		if err != nil {
			return errors.Wrap(err, "loading private key dir")
		}
		if len(all) < 1 {
			return errors.New("no private key found in path: " + priv)
		}
		pkeyPath = filepath.Join(priv, all[0].Name())
	} else {
		pkeyPath = filepath.Join(priv, c.conf.Certname)
	}
	data, err := ioutil.ReadFile(pkeyPath)
	if err != nil {
		return errors.Wrapf(err, "reading private key %s", pkeyPath)
	}
	c.MachineKey, err = loadKey(data)
	if err != nil {
		return errors.Wrapf(err, "loading client private key %s", pkeyPath)
	}
	return nil
}

// Authenticate completes the simian custom authentication flow.
// https://github.com/google/simian/wiki/DesignDocument#custom-authentication
func (c *Client) authenticate() error {
	cn, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		return errors.Wrap(err, "creating client nonce")
	}
	clientNonce := cn.String()

	au := c.ServerURL
	au.Path = "/auth"
	c.authURL = au.String()

	v := url.Values{}
	v.Set("n", clientNonce)
	resp, err := c.PostForm(c.authURL, v)
	if err != nil {
		return errors.Wrap(err, "sending client nonce")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "reading response body")
	}
	parsedBody := bytes.SplitN(body, []byte(" "), 3)
	respClientNonce := parsedBody[0]
	if string(respClientNonce) != clientNonce {
		return errors.New("mismatched client nonce returned by server")
	}

	serverNonce := string(parsedBody[1])
	sig := string(parsedBody[2])
	signature, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return errors.Wrap(err, "decoding server signature")
	}
	tmpM := strings.Join([]string{clientNonce, serverNonce}, " ")
	err = c.ServerCert.CheckSignature(x509.SHA1WithRSA, []byte(tmpM), signature)
	if err != nil {
		return errors.Wrap(err, "verifying server signature")
	}

	b64Cert := base64.URLEncoding.EncodeToString(c.rawMachineCert)
	outM := strings.Join([]string{b64Cert, clientNonce, serverNonce}, " ")
	hashed := sha1.Sum([]byte(outM))
	outSig, err := rsa.SignPKCS1v15(rand.Reader, c.MachineKey, crypto.SHA1, hashed[:])
	if err != nil {
		return errors.Wrap(err, "signing outgoign signature for server")
	}
	outSigb64 := base64.URLEncoding.EncodeToString(outSig)
	vv := url.Values{}
	vv.Set("m", outM)
	vv.Set("s", outSigb64)
	rresp, err := c.PostForm(c.authURL, vv)
	if err != nil {
		return errors.Wrap(err, "sending client signature")
	}
	defer rresp.Body.Close()
	if rresp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	var hasAuthCookie bool
	for _, cookie := range c.Jar.Cookies(au) {
		if cookie.Name == "Auth1Token" {
			hasAuthCookie = true
			c.authToken = cookie.String()
			break
		}
	}
	if !hasAuthCookie {
		return errors.New("server returned auth response without Auth1Token")
	}

	return nil
}

func loadCert(data []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != "CERTIFICATE" {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

func loadKey(data []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

func loadKeyX(data []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("unmatched type or headers")
	}

	b, err := x509.DecryptPEMBlock(pemBlock, []byte(""))
	if err != nil {
		return nil, err
	}

	priv, _ := x509.ParsePKCS1PrivateKey(b)
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pemBlockX := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privBytes,
	}
	var buf bytes.Buffer
	if err = pem.Encode(&buf, pemBlockX); err != nil {
		return nil, err
	}
	ioutil.WriteFile("decr.pem", buf.Bytes(), 0777)

	return x509.ParsePKCS1PrivateKey(b)
}
