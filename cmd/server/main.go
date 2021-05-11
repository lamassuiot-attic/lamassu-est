package main

import (
	"flag"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassu-est/secrets/ca/vault"
	_ "log"
	"os"

	_ "github.com/globalsign/est"
	"vault"
)

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}

func main() {

	var (
		flVersion           = flag.Bool("version", false, "prints version information")
		flHost              = flag.String("host", envString("SCEP_HOST", "scep"), "host where service is started")
		flPort              = flag.String("port", envString("SCEP_HTTP_LISTEN_PORT", "8080"), "port to listen on")
		flDepotPath         = flag.String("depot", envString("SCEP_FILE_DEPOT", "depot"), "path to ca folder")
		flCAPass            = flag.String("capass", envString("SCEP_CA_PASS", ""), "password for the ca.key")
		flVaultAddress      = flag.String("vaultaddress", envString("SCEP_VAULT_ADDRESS", "vault"), "Vault address")
		flVaultCA           = flag.String("vaultca", envString("SCEP_VAULT_CA", "Lamassu-Root-CA1-RSA4096"), "Vault CA")
		flVaultCACert       = flag.String("vaultcacert", envString("SCEP_VAULT_CA_CERT", ""), "Vault CA certificate")
		flRoleID            = flag.String("roleid", envString("SCEP_ROLE_ID", ""), "Vault RoleID")
		flSecretID          = flag.String("secretid", envString("SCEP_SECRET_ID", ""), "Vault SecretID")
		flHomePath          = flag.String("homepath", envString("SCEP_HOME_PATH", ""), "home path")
		flDBName            = flag.String("dbname", envString("SCEP_DB_NAME", "ca_store"), "DB name")
		flDBUser            = flag.String("dbuser", envString("SCEP_DB_USER", "scep"), "DB user")
		flDBPassword        = flag.String("dbpass", envString("SCEP_DB_PASSWORD", ""), "DB password")
		flDBHost            = flag.String("dbhost", envString("SCEP_DB_HOST", ""), "DB host")
		flDBPort            = flag.String("dbport", envString("SCEP_DB_PORT", ""), "DB port")
		flConsulProtocol    = flag.String("consulprotocol", envString("SCEP_CONSULPROTOCOL", ""), "Consul server protocol")
		flConsulHost        = flag.String("consulhost", envString("SCEP_CONSULHOST", ""), "Consul host")
		flConsulPort        = flag.String("consulport", envString("SCEP_CONSULPORT", ""), "Consul port")
		flConsulCA          = flag.String("consulca", envString("SCEP_CONSULCA", ""), "Consul CA path")
		flClDuration        = flag.String("crtvalid", envString("SCEP_CERT_VALID", "365"), "validity for new client certificates in days")
		flClAllowRenewal    = flag.String("allowrenew", envString("SCEP_CERT_RENEW", "14"), "do not allow renewal until n days before expiry, set to 0 to always allow")
		flChallengePassword = flag.String("challenge", envString("SCEP_CHALLENGE_PASSWORD", ""), "enforce a challenge password")
		flCSRVerifierExec   = flag.String("csrverifierexec", envString("SCEP_CSR_VERIFIER_EXEC", ""), "will be passed the CSRs for verification")
		flDebug             = flag.Bool("debug", envBool("SCEP_LOG_DEBUG"), "enable debug logging")
		flLogJSON           = flag.Bool("log-json", envBool("SCEP_LOG_JSON"), "output JSON logs")
	)

	var caSecrets casecrets.CASecrets
	{
		caSecrets, err = vault.NewVaultSecrets(*flVaultAddress, *flRoleID, *flSecretID, *flVaultCA, *flVaultCACert, lginfo)
		if err != nil {
			level.Error(lginfo).Log("err", err, "msg", "Could not start connection with CA Vault Secret Engine")
			os.Exit(1)
		}
	}
	level.Info(lginfo).Log("msg", "Connection established with CA secret engine")

}
