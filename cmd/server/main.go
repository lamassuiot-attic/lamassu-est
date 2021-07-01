package main

import (
	_ "context"
	_ "encoding/pem"
	"github.com/lamassuiot/lamassu-est/configs"
	"github.com/lamassuiot/lamassu-est/server/estserver"
	_ "io/ioutil"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config, _:= configs.NewConfigEnvServer("est")
	s, _ := estserver.NewServer(&config, nil)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	go func() {
		err := s.ListenAndServeTLS("", "")
		if err != nil {
			// TODO: Log
		}
	}()
}