// Package dependencies contains integration towards the dependencies service
package dependencies

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bxcodec/httpcache"
	sharedscanner "github.com/openclarity/kubeclarity/shared/pkg/scanner"
	jose "gopkg.in/go-jose/go-jose.v2"
	kc "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Image struct {
	ID       string    `json:"ref"`
	Sha      string    `json:"sha,omitempty"`
	Central  bool      `json:"central"`
	LastScan time.Time `json:"last"`
}

type ScanResult struct {
	Sha             string                               `json:"sha"`
	Vulnerabilities []*sharedscanner.MergedVulnerability `json:"vulnerabilities"`
	BOM             *cdx.BOM                             `json:"sbom"`
	Workload        WorkloadRef                          `json:"workload"`
}

type WorkloadRef struct {
	FQDN       string `json:"cluster"`
	NRN        string `json:"nrn"`
	ApiVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

type Service interface {
	GetImage(ctx context.Context, ref string) (*Image, error)
	PushScan(ctx context.Context, repo string, res *ScanResult) error
}

type client struct {
	clusterID   string
	clusterNRN  string
	client      *http.Client
	cacheClient *http.Client
	baseURL     string
	signer      jose.Signer
	certFile    string
	keyFile     string
}

const MIMEApplicationJOSEJSON = "application/jose+json"

func New(clusterID, clusterNRN, baseURL, certFile, keyFile string) (Service, error) {
	cl := &http.Client{}
	_, err := httpcache.NewWithInmemoryCache(&http.Client{}, true)
	if err != nil {
		return nil, err
	}

	c := &client{
		clusterID:   clusterID,
		clusterNRN:  clusterNRN,
		cacheClient: cl,
		client:      &http.Client{},
		baseURL:     baseURL,
		certFile:    certFile,
		keyFile:     keyFile,
	}
	c.refreshCertificates()
	return c, nil
}

func (c *client) refreshCertificates() {
	if c.certFile == "" || c.keyFile == "" {
		return
	}

	reschedule := func(d time.Duration) {
		log.Log.Info("refreshing key and certificate", "duration", d)
		t := time.NewTimer(d)
		<-t.C
		c.refreshCertificates()
	}

	certificates, key, err := readKeyAndCertificates(c.certFile, c.keyFile)
	if err != nil {
		log.Log.Error(err, "Unable to read certificates")
		go reschedule(2 * time.Minute)
		return
	}

	jwk := jose.JSONWebKey{Certificates: certificates, Key: key}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS512, Key: jwk}, &jose.SignerOptions{EmbedJWK: true})
	if err != nil {
		log.Log.Error(err, "Unable to create JOSE signer")
		go reschedule(2 * time.Minute)
		return
	}
	c.signer = signer

	if len(certificates) > 0 {
		d := time.Until(certificates[0].NotAfter)
		go reschedule(d - (5 * time.Minute))
	}
}

func readKeyAndCertificates(certFile, keyFile string) ([]*x509.Certificate, any, error) {
	certificates := []*x509.Certificate{}
	data, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		return nil, nil, err
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certificates = append(certificates, cert)
	}

	data, err = os.ReadFile(filepath.Clean(keyFile))
	if err != nil {
		return nil, nil, err
	}
	p, _ := pem.Decode(data)
	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			return nil, nil, err
		}
	}

	return certificates, key, nil
}

func (c *client) GetImage(ctx context.Context, repo string) (*Image, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s", c.baseURL, repo), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.cacheClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	img := &Image{}
	err = json.NewDecoder(resp.Body).Decode(img)
	if err != nil {
		return nil, err
	}

	return &Image{
		LastScan: img.LastScan,
		Central:  img.Central,
	}, nil
}

func (c *client) PushScan(ctx context.Context, repo string, res *ScanResult) error {
	res.Workload.FQDN = c.clusterID
	res.Workload.NRN = c.clusterNRN

	b := new(bytes.Buffer)
	err := json.NewEncoder(b).Encode(res)
	if err != nil {
		return err
	}

	var req *http.Request
	if c.signer != nil {
		jws, err := c.signer.Sign(b.Bytes())
		if err != nil {
			return err
		}

		req, err = http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s/%s", c.baseURL, repo), strings.NewReader(jws.FullSerialize()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", MIMEApplicationJOSEJSON)

	} else {
		var err error
		req, err = http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s/%s", c.baseURL, repo), bytes.NewReader(b.Bytes()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return fmt.Errorf("error pushing scan results: %s", resp.Status)
	}

	return nil
}

func RefFromKind(obj kc.Object) WorkloadRef {
	return WorkloadRef{
		Kind:       obj.GetObjectKind().GroupVersionKind().Kind,
		ApiVersion: obj.GetObjectKind().GroupVersionKind().GroupVersion().Identifier(),
		Namespace:  obj.GetNamespace(),
		Name:       obj.GetName(),
	}
}
