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

	// initialize anything that implements RSA crypto.Signer

	ksigner, err := salpem.NewPEMCrypto(&salpem.PEM{
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
	// ksigner, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)
	// if err != nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }

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

	// ksigner, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmDevice:     "/dev/tpm0",
	// 	TpmHandleFile: "/tmp/key.bin",
	// 	//TpmHandle:     0x81010002,
	// })

	// ############## PKCS

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

	// ksigner, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
	// 	Context:        cctx,
	// 	PkcsId:         nil,                 //softhsm
	// 	PkcsLabel:      []byte("keylabel1"), //softhsm
	// 	PublicCertFile: "client.crt",        //softhsm
	// })

	if err != nil {
		fmt.Println(err)
		return
	}

	// **************************

	localhostCert, err := ioutil.ReadFile("../certs/client.crt")
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
	client, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		fmt.Printf("Invalid NewVirtualMachinesClient client error: " + err.Error())
		os.Exit(1)
	}

	v, err := client.Get(ctx, resourceGroup, vmName, nil)
	if err != nil {
		fmt.Printf("Error getting vm: " + err.Error())
		os.Exit(1)
	}

	fmt.Printf("VM: %s\n", *v.ID)

}
