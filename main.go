package main

import (
	"context"
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

	netChecker    *netcheck.Checker
	netChecks     = netcheck.DefaultChecks
	storedResults *netcheck.ResultsStorage
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
	resultsStoragePath := cfg.GetDString("results.json", "results", "path")
	storedResults = netcheck.NewResultsStorage(noerr(loadJsonIfExists[[]netcheck.RunResults](resultsStoragePath)), cfg.GetDInt(50, "results", "limit"))
	netChecker = netcheck.NewChecker(log.Logger, cfg.DupSubTree("netcheck"), getConfigEndpoints(), netChecks, storedResults.Add)

	stopHttp := flexutils.StartBackgroundRoutineCtx(context.Background(), log.Logger, "http", httpRoutine)
	stopChecker := flexutils.StartBackgroundRoutineCtx(context.Background(), log.Logger, "checker", netChecker.Run)

	signalChan := make(chan os.Signal, 2)
	signal.Notify(signalChan, os.Interrupt)

	<-signalChan
	log.Info().Msg("got sigterm, shutting down")

	stopChecker()
	stopHttp()

	log.Err(saveJson(resultsStoragePath, storedResults.Get())).Msg("results stored")

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
		case map[string]any:
			ed := netcheck.EndpointDescription{}
			var ok bool
			ed.Endpoint, ok = ee["Endpoint"].(string)
			ed.Alias, ok = ee["Alias"].(string)
			_ = ok
			ret = append(ret, ed)
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
