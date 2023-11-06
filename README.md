
## KMS, TPM and HSM based Azure Certificate Credentials 

Azure Credential class that allows you to use HSM, KMS or TPM embedded private keys.  

It allows for Azure API access using any golang construct that fulfils the [crypto.Signer](https://pkg.go.dev/crypto#Signer) interface.

[Microsoft identity platform application authentication certificate credentials](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials) describes how an admin can associate an `x509.Certificate` with an application and then access Azure API using the private key.

However, the default azure library only allows providing the private key as a raw PEM file (see [azidentity.NewClientCertificateCredential()](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#NewClientCertificateCredential)).   In other words, the private key is on disk and can be compromised.

This repo allows you to pass in an arbitrary `crypto.Signer` interface instead of the raw key. 

That abstraction allows any underlying backend to hold the private key material.

For example, [go-tpm-tools Signer](https://pkg.go.dev/github.com/google/go-tpm-tools/client#Key.GetSigner)  allows you to embed the private key into a Trusted Platform Module (TPM)

There are plenty of other signers around and some unsupported ones can be found here that show how to use GCP KMS, TPM and just as a demo, a PEM file

* [crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules](https://github.com/salrashid123/signer)

To use this, first setup an azure application and upload the public x509.  in the example below, i've uploaded the certs provided in this repo (you can use these keys but really, you should generate your own)

![images/client_cert.png](images/client_cert.png)

The specific `crypto.Signer` i've used here in the example is silly:  its a `crypto.Signer` that uses a PEM file (which doesn't make that much sense since its equivalent security that `azidentity`). 

However, i've also shown a `crypto.Signer` that uses my KMS key (eg, i have the same KMS )

### References

* [Exchange Google and Firebase OIDC tokens for Azure STS](https://github.com/salrashid123/azcompat)
* [golang-jwt for crypto.Signer](https://blog.salrashid.dev/articles/2022/golang-jwt-signer/)

---

#### Usage


see `example/` folder on usage

```golang

import (
   	"github.com/salrashid123/azsigner"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"    
)

const (
   	clientID = "yourclientID"
	containerName  = "yourcontainer"
	url            = "https://yourstorageaccount.blob.core.windows.net/"
)

func main() {
    ksigner := foo  // <<<<<<<<<< anything that implements crypto.Signer() for RSA

	cred, err := azsigner.NewSignerCredentials(
		tenantID,
		clientID,
		[]*x509.Certificate{cert},
		ksigner, nil)

	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{fmt.Sprintf("api://%s/.default", clientID)},
	})

	fmt.Printf("Azure token: %s\n", tk.Token)

	client, err := azblob.NewClient(url, cred, nil)

	pager := client.NewListBlobsFlatPager(containerName, &azblob.ListBlobsFlatOptions{})

	for pager.More() {
		resp, err := pager.NextPage(context.TODO())
		for _, blob := range resp.Segment.BlobItems {
			fmt.Println(*blob.Name)
		}
	}
}
```
