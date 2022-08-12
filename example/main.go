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

	// **************************
	// localhostkey, err := ioutil.ReadFile("../certs/client_rsa.key")
	// if err != nil {
	// 	fmt.Printf("Error finding key file: " + err.Error())
	// 	os.Exit(1)
	// }

	// block, _ := pem.Decode([]byte(localhostkey))
	// key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// if err != nil {
	// 	fmt.Printf("Error loading private key: " + err.Error())
	// 	os.Exit(1)
	// }

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
	//cred, err := azidentity.NewClientCertificateCredential(tenantID, clientID, []*x509.Certificate{cert}, key, nil)
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
