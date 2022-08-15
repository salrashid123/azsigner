
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

	//"github.com/go-piv/piv-go/piv"
	salpem "github.com/salrashid123/signer/pem"
	// salkms "github.com/salrashid123/signer/kms"
	// saltpm "github.com/salrashid123/signer/tpm"
	// "github.com/ThalesIgnite/crypto11"
	// salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"
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
	// demo signer
	r, err := salpem.NewPEMCrypto(&salpem.PEM{
		PrivatePEMFile: "../certs/client_rsa.key",
	})

	// // rsa.PrivateKey also implements a crypto.Signer
	// // https://pkg.go.dev/crypto/rsa#PrivateKey.Sign
	// privatePEM, err := ioutil.ReadFile("../certs/client_rsa.key")
	// if err != nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }
	// rblock, _ := pem.Decode(privatePEM)
	// if rblock == nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }
	// r, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)
	// if err != nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }

	// ############# KMS

	// r, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "mineral-minutia-820",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "s",
	// 	KeyVersion:         "1",
	// })

	// ############# TPM

	// r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmDevice:     "/dev/tpm0",
	// 	TpmHandleFile: "/tmp/key.bin",
	// 	//TpmHandle:     0x81010002,
	// })

	// ############# Yubikey

	// cards, err := piv.Cards()
	// if err != nil {
	// 	fmt.Printf("unable to open yubikey %v", err)
	// 	os.Exit(1)
	// }
	// var ykey *piv.YubiKey
	// for _, card := range cards {
	// 	if strings.Contains(strings.ToLower(card), "yubikey") {
	// 		if ykey, err = piv.Open(card); err != nil {
	// 			fmt.Printf("unable to open yubikey %v", err)
	// 			os.Exit(1)
	// 		}
	// 		break
	// 	}
	// }
	// if ykey == nil {
	// 	fmt.Printf("yubikey not found Please make sure the key is inserted %v", err)
	// 	os.Exit(1)
	// }
	// defer ykey.Close()

	// cert, err := ykey.Certificate(piv.SlotSignature)
	// if err != nil {
	// 	fmt.Printf("unable to load certificate not found %v", err)
	// 	os.Exit(0)
	// }

	// auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	// priv, err := ykey.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	// if err != nil {
	// 	fmt.Printf("unable to load privateKey %v", err)
	// 	os.Exit(0)
	// }

	// r, ok := priv.(crypto.Signer)
	// if !ok {
	// 	fmt.Printf("expected private key to implement crypto.Signer")
	// 	os.Exit(0)
	// }

	// ############# PKCS11

	// export SOFTHSM2_CONF=/path/to/softhsm.conf
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	// 	TokenLabel: "token1",
	// 	Pin:        "mynewpin",
	// }

	// cctx, err := crypto11.Configure(config)
	// if err != nil {
	// 	fmt.Printf("error creating pkcs11 config%v", err)
	// 	os.Exit(0)
	// }
	// defer cctx.Close()

	// r, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
	// 	Context:        cctx,
	// 	PkcsId:         nil,                 //softhsm
	// 	PkcsLabel:      []byte("keylabel1"), //softhsm
	// 	PublicCertFile: "client.crt",        //softhsm
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
		r, nil)

	client, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)

	v, err := client.Get(ctx, resourceGroup, vmName, nil)

	fmt.Printf("VM: %s\n", *v.ID)
}

```

