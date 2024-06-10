package main

import (
	"context"

	"crypto/x509"

	"encoding/pem"
	"fmt"

	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/salrashid123/azsigner"
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
	containerName  = "yourcontainer"
	url            = "https://yourstorageaccount.blob.core.windows.net/"
	vmName         = "vm1"
)

// var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

// func OpenTPM(path string) (io.ReadWriteCloser, error) {
// 	if slices.Contains(TPMDEVICES, path) {
// 		return tpmutil.OpenTPM(path)
// 	} else if path == "simulator" {
// 		return simulator.GetWithFixedSeedInsecure(1073741825)
// 	} else {
// 		return net.Dial("tcp", path)
// 	}
// }

func main() {

	//ctx := context.Background()

	// initialize anything that implements RSA crypto.Signer

	// // rsa.PrivateKey also implements a crypto.Signer
	// // https://pkg.go.dev/crypto/rsa#PrivateKey.Sign

	// use a different keypair!
	//  openssl rsa -in client.key -out client_rsa.key -traditional

	privatePEM, err := os.ReadFile("../certs/client_rsa.key")
	if err != nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}
	rblock, _ := pem.Decode(privatePEM)
	if rblock == nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}
	ksigner, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)
	if err != nil {
		fmt.Printf("error getting signer %v", err)
		os.Exit(0)
	}

	// ############## KMS

	// ksigner, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "mineral-minutia-820",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "s",
	// 	KeyVersion:         "1",
	// 	SignatureAlgorithm: x509.SHA256WithRSA,
	// })

	// ############## TPM

	// ### using go-tpm-tools
	// "github.com/google/go-tpm-tools/client"
	// "github.com/google/go-tpm-tools/simulator"
	// "github.com/google/go-tpm/tpmutil"

	// rwc, err := OpenTPM("127.0.0.1:2321")
	// if err != nil {
	// 	fmt.Printf("can't open TPM: %v", err)
	// 	return
	// }
	// defer func() {
	// 	if err := rwc.Close(); err != nil {
	// 		fmt.Printf("can't close TPM: %v", err)
	// 	}
	// }()

	// k, err := client.LoadCachedKey(rwc, tpmutil.Handle(0x81010002), nil)
	// if err != nil {
	// 	fmt.Printf("can't get key: %v", err)
	// 	return
	// }
	// ksigner, err := k.GetSigner()
	// if err != nil {
	// 	fmt.Printf("can't get signer: %v", err)
	// 	return
	// }

	//  using salrashid123/signer/tpm Signer

	// rwr := transport.FromReadWriter(rwc)
	// pub, err := tpm2.ReadPublic{
	// 	ObjectHandle: tpm2.TPMHandle(0x81010002),
	// }.Execute(rwr)

	// ksigner, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmDevice: rwc,
	// 	NamedHandle: &tpm2.NamedHandle{
	// 		Handle: tpm2.TPMHandle(0x81010002),
	// 		Name:   pub.Name,
	// 	},
	// })

	// ############## PKCS

	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	// 	TokenLabel: "token1",
	// 	Pin:        "mynewpin",
	// }

	// cctx, err := crypto11.Configure(config)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// defer cctx.Close()

	// ksigner, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
	// 	Context:   cctx,
	// 	PkcsId:    nil,                 //softhsm
	// 	PkcsLabel: []byte("keylabel1"), //softhsm
	// })
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// **************************

	// your cert will be different!
	localhostCert, err := os.ReadFile("../certs/client.crt")
	if err != nil {
		fmt.Printf("Error getting vm: " + err.Error())
		os.Exit(1)
	}
	pubBlock, _ := pem.Decode([]byte(localhostCert))
	cert, err := x509.ParseCertificate(pubBlock.Bytes)
	if err != nil {
		fmt.Printf("Error getting vm: " + err.Error())
		os.Exit(1)
	}

	cred, err := azsigner.NewSignerCredentials(
		tenantID,
		clientID,
		[]*x509.Certificate{cert},
		ksigner, nil)

	if err != nil {
		fmt.Printf("Error getting vm: " + err.Error())
		os.Exit(1)
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{fmt.Sprintf("api://%s/.default", clientID)},
	})
	if err != nil {
		fmt.Printf("Error getting token: " + err.Error())
		os.Exit(1)
	}

	fmt.Printf("Azure token: %s\n", tk.Token)

	// armclient, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	// if err != nil {
	// 	fmt.Printf("Invalid NewVirtualMachinesClient client error: " + err.Error())
	// 	os.Exit(1)
	// }
	// v, err := armclient.Get(context.Background(), resourceGroup, vmName, nil)
	// if err != nil {
	// 	fmt.Printf("Error getting vm: " + err.Error())
	// 	os.Exit(1)
	// }

	// fmt.Printf("VM: %s\n", *v.ID)

	client, err := azblob.NewClient(url, cred, nil)
	if err != nil {
		fmt.Printf("Error creating client: " + err.Error())
		os.Exit(1)
	}
	pager := client.NewListBlobsFlatPager(containerName, &azblob.ListBlobsFlatOptions{})

	fmt.Println("-----------------------")
	fmt.Println("Objects:")
	for pager.More() {
		resp, err := pager.NextPage(context.TODO())
		if err != nil {
			fmt.Printf("Error iterating objects " + err.Error())
			os.Exit(1)
		}
		for _, blob := range resp.Segment.BlobItems {
			fmt.Println(*blob.Name)
		}
	}

}
