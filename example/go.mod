module main

go 1.22

toolchain go1.22.2

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.11.1
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.2.0
	github.com/salrashid123/azsigner v0.0.0

)

require (
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/salrashid123/golang-jwt-signer v0.3.0 // indirect
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/text v0.16.0 // indirect
)

replace github.com/salrashid123/azsigner => ../
