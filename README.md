
## KMS, TPM and HSM based Azure Certificate Credentials 

Azure Credential class that allows you to use HSM, KMS or TPM embedded private keys.  It allows for Azure API access using any golang construct that fulfils the [crypto.Signer](https://pkg.go.dev/crypto#Signer) interface.

[Microsoft identity platform application authentication certificate credentials](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials) describes how an admin can associate an `x509.Certificate` with an application and then access Azure API using the private key.

However, the default azure library only allows providing the private key as a raw PEM file (see [azidentity.NewClientCertificateCredential()](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#NewClientCertificateCredential)).   In other words, the private key is on disk and can be compromised.

This repo allows you to pass in an arbitrary `crypto.Signer` interface instead of the raw key. 

That abstraction allows any underlying backend to hold the private key material.

For example, [go-tpm-tools Signer](https://pkg.go.dev/github.com/google/go-tpm-tools/client#Key.GetSigner)  allows you to embed the private key into a Trusted Platform Module (TPM)

There are plenty of other signers around and some unsupported ones can be found here that show how to use GCP KMS, TPM and just as a demo, a PEM file

* [crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules](https://github.com/salrashid123/signer)

To use this, first setup an azure application and upload the public x509.  in the example below, i've uploaded the certs provided in this repo

![images/client_cert.png](images/client_cert.png)

The specific `crypto.Signer` i've used here in the example is silly:  its a `crypto.Signer` that uses a PEM file (which doesn't make that much sense since its equivalent security that `azidentity`). 

However, i've also shown a `crypto.Signer` that uses my KMS key (eg, i have the same KMS )

### References

* [Exchange Google and Firebase OIDC tokens for Azure STS](https://github.com/salrashid123/azcompat)
* [golang-jwt for crypto.Signer](https://blog.salrashid.dev/articles/2022/golang-jwt-signer/)

---

```golang
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/salrashid123/azsigner"
	salpem "github.com/salrashid123/signer/pem"
	// salkms "github.com/salrashid123/signer/kms"
)

const (
	clientID = "cffeaee2-5617-4784-8a4b-b647efd676d2"
	audience = "api://AzureADTokenExchange"
	tenantID = "45243fbe-b73f-4f7d-8213-a104a99e228e"

	subscriptionID = "450b3122-bc25-49b7-86be-7dc86269a2e4"
	resourceGroup  = "rg1"
	vmName         = "vm1"
)

func main() {

	ctx := context.Background()
	ksigner, err := salpem.NewPEMCrypto(&salpem.PEM{
		PrivatePEMFile: "../certs/client_rsa.key",
	})

	// ksigner, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "mineral-minutia-820",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "s",
	// 	KeyVersion:         "1",
	// 	SignatureAlgorithm: x509.SHA256WithRSA,
	// })
	if err != nil {
		fmt.Println(err)
		return
	}

	localhostCert, err := ioutil.ReadFile("../certs/client.crt")
	pubBlock, _ := pem.Decode([]byte(localhostCert))

    cert, err := x509.ParseCertificate(pubBlock.Bytes)


	cred, err := azsigner.NewSignerCredentials(
		tenantID,
		clientID,
		[]*x509.Certificate{cert},
		ksigner, nil)

	client, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)

	v, err := client.Get(ctx, resourceGroup, vmName, nil)

	fmt.Printf("VM: %s\n", *v.ID)
}

```

```
$ openssl x509 -in client.crt -noout -fingerprint
    SHA1 Fingerprint=EE:57:F7:A0:1B:C2:A1:34:80:BC:59:BA:C9:1D:48:CB:A3:B6:92:41
$ openssl x509 -in kms_client.crt -noout -fingerprint
    SHA1 Fingerprint=C1:67:5A:A5:64:A0:A6:21:3B:08:17:08:E4:FA:8C:EE:6E:75:A2:9A
```

---

