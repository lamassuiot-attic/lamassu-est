package main

import (
	"fmt"
	"github.com/lamassuiot/lamassu-est/configs"
)

func main() {
/*
	var caVault *ca.VaultService

	secretsVault, err := vault.NewVaultSecrets(
		"https://lamassu.zpd.ikerlan.es:8200/",
		"bfdc0c07-7f32-07c1-2ed0-9fb23ec13cc0",
		" 2ca86154-4ae0-de50-cacf-eef5d634611c",
		"/certs/vault.crt",
		nil)

	if err != nil {
		fmt.Println("Error on Vault.\n[ERROR] -", err)
	}

	caVault = ca.NewVaultService(secretsVault)

	server, err := estserver.NewServerCa(caVault)
	if err != nil {
		fmt.Println("Error on Server.\n[ERROR] -", err)
	}

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		fmt.Println("Error on Server.\n[ERROR] -", err)
	}*/

	configVault, err := configs.NewConfigEnvServer("ca")
	if err != nil {
		fmt.Errorf("failed to laod env variables %v", err)
	}

	fmt.Println(configVault)
}
