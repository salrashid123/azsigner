//go:build go1.18
// +build go1.18

package azsigner

import (
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	yk "github.com/salrashid123/golang-jwt-signer"
)

const ()

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	ExtExpiresIn int64  `json:"ext_expires_in,omitempty"`
}

// ClientCertificateCredentialOptions contains optional parameters for ClientCertificateCredential.
type SignerClientCertificateCredentialOptions struct {
	azcore.ClientOptions

	SendCertificateChain bool
}

// ClientCertificateCredential authenticates a service principal with a certificate.
type SignerCredential struct {
	tenantID string
	clientID string
	certs    []*x509.Certificate
	key      crypto.Signer
	opts     SignerClientCertificateCredentialOptions
}

func NewSignerCredentials(tenantID string, clientID string, certs []*x509.Certificate, key crypto.Signer, options *SignerClientCertificateCredentialOptions) (*SignerCredential, error) {

	yk.SigningMethodSignerRS256.Override()

	if tenantID == "" || clientID == "" || len(certs) == 0 || key == nil {
		return nil, errors.New("specify tenantID, clientID, x509 certs and a crypto.singer")
	}
	if options == nil {
		options = &SignerClientCertificateCredentialOptions{}
	}

	return &SignerCredential{
		tenantID: tenantID,
		clientID: clientID,
		certs:    certs,
		key:      key,
		opts:     *options,
	}, nil
}

func (c *SignerCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {

	if len(opts.Scopes) == 0 {
		return azcore.AccessToken{}, fmt.Errorf("Scopes cannot be empty")
	}

	// https://github.com/AzureAD/microsoft-authentication-library-for-go/blob/main/apps/internal/oauth/ops/accesstokens/accesstokens.go#L112
	token := jwt.NewWithClaims(yk.SigningMethodSignerRS256, jwt.MapClaims{
		"aud": fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.tenantID),
		"exp": json.Number(strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)),
		"iss": c.clientID,
		"jti": uuid.New().String(),
		"nbf": json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
		"sub": c.clientID,
	})
	token.Header = map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"x5t": base64.StdEncoding.EncodeToString(thumbprint(c.certs[0])),
	}

	keyctx, err := yk.NewSignerContext(ctx, &yk.SignerConfig{
		Signer: c.key,
	})
	if err != nil {
		fmt.Printf("Unable to initialize signer:  %v\n", err)
		return azcore.AccessToken{}, err
	}

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		return azcore.AccessToken{}, err
	}

	stsClient := &http.Client{}
	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("scope", fmt.Sprintf(strings.Join(opts.Scopes[:], ",")))
	form.Add("client_id", c.clientID)
	form.Add("client_assertion", tokenString)
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	stsResp, err := stsClient.PostForm(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.tenantID), form)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	defer stsResp.Body.Close()

	if stsResp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(stsResp.Body)
		if err != nil {
			return azcore.AccessToken{}, err
		}
		return azcore.AccessToken{}, fmt.Errorf("error reading sts response from azure status %d   %s", stsResp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(stsResp.Body)
	if err != nil {
		return azcore.AccessToken{}, err
	}

	var result TokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return azcore.AccessToken{}, err
	}

	return azcore.AccessToken{
		Token:     result.AccessToken,
		ExpiresOn: time.Now().Add(time.Second * time.Duration(result.ExpiresIn)).UTC(),
	}, nil
}

func thumbprint(cert *x509.Certificate) []byte {
	/* #nosec */
	a := sha1.Sum(cert.Raw)
	return a[:]
}

var _ azcore.TokenCredential = (*SignerCredential)(nil)
