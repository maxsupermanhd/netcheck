package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"main/lib/netcheck"
	"os"
	"os/signal"

	flexutils "github.com/maxsupermanhd/go-flexutils"
	"github.com/maxsupermanhd/lac/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	flConfigPath = flag.String("config", "config.json", "path to config json")
	cfg          lac.Conf

	netChecker *netcheck.Checker
)

func main() {
	flag.Parse()
	configLoad(*flConfigPath)
	log.Logger = log.Output(io.MultiWriter(
		zerolog.ConsoleWriter{Out: os.Stderr},
		&lumberjack.Logger{
			Filename: cfg.GetDString("logs/main.log", "logs", "filename"),
			MaxSize:  cfg.GetDInt(500, "logs", "maxSize"),
			Compress: true,
		}))
	netChecker = netcheck.NewChecker(getConfigEndpoints())

	stopHttp := flexutils.StartBackgroundRoutine(log.Logger, "http", httpRoutine)
	stopChecker := flexutils.StartBackgroundRoutine(log.Logger, "checker", netChecker.Run)

	signalChan := make(chan os.Signal, 2)
	signal.Notify(signalChan, os.Interrupt)

	<-signalChan
	log.Info().Msg("got sigterm, shutting down")

	stopChecker()
	stopHttp()

	log.Info().Msg("bye")
}

func getConfigEndpoints() []netcheck.EndpointDescription {
	ret := []netcheck.EndpointDescription{}
	endpoints, ok := cfg.GetSliceAny("endpoints")
	if !ok {
		return ret
	}
	for _, e := range endpoints {
		switch ee := e.(type) {
		case string:
			ret = append(ret, netcheck.EndpointDescription{
				Endpoint: ee,
			})
		}
	}
	return ret
}

func configLoad(configPath string) {
	var err error
	cfg, err = lac.FromFileJSON(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = lac.NewConf()
			return
		}
		fmt.Fprintln(os.Stderr, "Failed to load config: "+err.Error())
		os.Exit(1)
		panic(err)
	}
}
