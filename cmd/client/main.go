package main

import (
	"github.com/lamassuiot/lamassu-est/client/estclient"
)

var (
	PORT    = "6666"
	CA_PATH = "/home/xpb/Desktop/ikl/lamassu/lamassu-est/certs/ca.crt"
)

func main() {

	estclient.Cacerts(nil, "lalala.crt")
}
