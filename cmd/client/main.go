package main

import (
	"crypto/tls"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassu-est/client/api"
	"github.com/lamassuiot/lamassu-est/client/configs"
	"github.com/lamassuiot/lamassu-est/client/estclient"
	"github.com/lamassuiot/lamassu-est/client/utils"
	jaegercfg "github.com/uber/jaeger-client-go/config"
	"net/http"
	"os"
)

var (
	PORT = "6666"
	CA_PATH = "/home/xpb/Desktop/ikl/lamassu/lamassu-est/certs/ca.crt"
)


func main() {

	/*
	Logger
	*/
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger = level.NewFilter(logger, level.AllowInfo())
	}


	/*
	Load Configuration
	 */
	cfg, err := configs.NewConfig()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")


	/*
	Start Jaeger
	 */
	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values from environment")
		os.Exit(1)
	}
	jcfg.ServiceName = "estclietn" //TODO Put this in environment variable
	level.Info(logger).Log("msg", "Jaeger configuration values loaded")
	tracer, closer, err := jcfg.NewTracer()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()
	level.Info(logger).Log("msg", "Jaeger tracer started")


	/*
	Start EST client
	 */
	client, err := estclient.NewClient(&cfg)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Remote EST Client started")

	/*
	Start REST API
	 */
	var s api.Service
	{
		s = api.NewDeviceService(client)
	}

	capool, err := utils.CreateCAPool(CA_PATH)
	if err != nil {
		return
	}

	/*
	Configure and start server
	 */
	server := &http.Server{
		Addr:    ":" + PORT,
		Handler: nil,
		TLSConfig: &tls.Config{
			RootCAs: capool,
		},
	}
	level.Info(logger).Log("msg", "Server created and configured")

	mux := http.NewServeMux()

	mux.Handle("/v1/", api.MakeHTTPHandler(s, log.With(logger, "component", "HTTP"), tracer))
	http.Handle("/", accessControl(mux))

	fmt.Println(cfg, s, server)
}

func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}
