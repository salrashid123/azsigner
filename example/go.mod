module main

go 1.19

require github.com/golang-jwt/jwt/v4 v4.5.0 // indirect

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.7.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.2.0
	//github.com/salrashid123/azsigner v0.0.0-20220812231048-57fa0a48f86e
	github.com/salrashid123/azsigner v0.0.0
	github.com/salrashid123/signer/pem v0.0.0-20220718102027-af49b1c9153d
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.3.0 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/salrashid123/golang-jwt-signer v0.0.0-20220812192832-075740dcd524 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/text v0.9.0 // indirect
)

replace github.com/salrashid123/azsigner => ../
