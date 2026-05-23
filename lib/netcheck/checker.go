package netcheck

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/maxsupermanhd/lac/v2"
	"github.com/rs/zerolog"
)

type EndpointDescription struct {
	Alias    string `json:",omitempty"`
	Endpoint string
}

type CheckResult struct {
	Brief     string `json:",omitempty"`
	BriefHTML string `json:",omitempty"`
	Color     string `json:",omitempty"`

	// usually filled outside of the checker
	Took    time.Duration `json:",omitempty"`
	Content string        `json:",omitempty"`

	// 0 inconclusive >0 positive <0 negative
	Success int `json:",omitempty"`
}

func (e CheckResult) Error() string {
	return e.Content
}

func (e CheckResult) Is(target error) bool {
	var ok bool
	_, ok = target.(CheckResult)
	if ok {
		return true
	}
	_, ok = target.(*CheckResult)
	if ok {
		return true
	}
	return false
}

type RunResults struct {
	StartedAt time.Time
	Duration  time.Duration
	Results   []EndpointResults
}

type EndpointResults struct {
	Endpoint EndpointDescription
	Results  map[string]CheckResult
}

func (e EndpointResults) Clone() EndpointResults {
	ret := e
	ret.Results = maps.Clone(e.Results)
	return ret
}

type Checker struct {
	logger zerolog.Logger
	cfg    lac.Conf

	endpoints []EndpointDescription
	results   []EndpointResults
	state     string
	lock      sync.Mutex
	checks    []Check

	updateListener chan struct{}

	resultsLogger func(RunResults)
}

func NewChecker(l zerolog.Logger, cfg lac.Conf, n []EndpointDescription, checks []Check, resultsLogger func(RunResults)) *Checker {
	c := &Checker{
		logger:         l,
		cfg:            cfg,
		updateListener: make(chan struct{}),
		checks:         checks,
		resultsLogger:  resultsLogger,
	}
	c.UpdateEndpoints(n)
	return c
}

func (c *Checker) UpdateEndpoints(n []EndpointDescription) {
	c.lock.Lock()
	c.endpoints = n
	c.lock.Unlock()
}

func (c *Checker) GetResults() []EndpointResults {
	c.lock.Lock()
	ret := make([]EndpointResults, len(c.results))
	for i := range c.results {
		ret[i] = c.results[i].Clone()
	}
	c.lock.Unlock()
	return ret
}

func (c *Checker) GetState() string {
	c.lock.Lock()
	ret := c.state
	c.lock.Unlock()
	return ret
}

func (c *Checker) ListenChan() chan struct{} {
	c.lock.Lock()
	ret := c.updateListener
	c.lock.Unlock()
	return ret
}

func (c *Checker) broadcastUpdateNOLOCK() {
	ret := c.updateListener
	c.updateListener = make(chan struct{})
	if ret != nil {
		close(ret)
	}
}

func (c *Checker) Run(ctx context.Context) {
	if waitOrAbort(ctx.Done(), time.Duration(c.cfg.GetDInt(10, "initialPauseSeconds"))*time.Second) {
		return
	}
	for {
		c.logger.Info().Msg("starting checks")
		timings := time.Now()
		c.doChecks(ctx)
		c.logger.Info().Dur("took", time.Since(timings)).Msg("checks finished")
		if c.resultsLogger != nil {
			select {
			case <-ctx.Done():
			default:
				c.resultsLogger(RunResults{
					StartedAt: timings,
					Duration:  time.Since(timings),
					Results:   c.GetResults(),
				})
			}
		}
		if waitOrAbort(ctx.Done(), time.Duration(c.cfg.GetDInt(10, "checksIntervalSeconds"))*time.Second) {
			return
		}
	}
}

type CheckFunc func(context.Context, EndpointDescription) error

type Check struct {
	Name string
	Fn   CheckFunc
}

var (
	DefaultChecks = []Check{
		{Name: "resolve", Fn: CheckEndpointResolve},
		{Name: "ping", Fn: CheckEndpointPing},
		{Name: "http", Fn: CheckEndpointPlainHTTP},
		{Name: "tls12", Fn: CheckEndpointTLS12},
		{Name: "tls13", Fn: CheckEndpointTLS13},
		{Name: "tls13ech", Fn: CheckEndpointTLS13ECH},
	}
)

func (c *Checker) doChecks(ctx context.Context) {

	c.lock.Lock()
	c.results = make([]EndpointResults, len(c.endpoints))
	c.state = "working"
	c.broadcastUpdateNOLOCK()
	endpoints := slices.Clone(c.endpoints)
	c.lock.Unlock()

	wg := &sync.WaitGroup{}
	for i, endpoint := range endpoints {
		wg.Go(func() {
			eres := EndpointResults{
				Endpoint: endpoint,
				Results:  map[string]CheckResult{},
			}
			for _, check := range c.checks {
				eres.Results[check.Name] = checkResultScheduled
			}
			c.lock.Lock()
			c.results[i] = eres
			c.broadcastUpdateNOLOCK()
			c.lock.Unlock()

			if waitOrAbort(ctx.Done(), time.Duration(i*c.cfg.GetDInt(100, "staggerSleepMilliseconds"))*time.Millisecond) {
				return
			}

			for checkNum, check := range c.checks {
				minWait := time.Duration(c.cfg.GetDInt(10, "checkIntervalSeconds")) * time.Second

				c.lock.Lock()
				eres.Results[check.Name] = checkResultPending
				c.broadcastUpdateNOLOCK()
				c.lock.Unlock()

				cctx, cctxCancel := context.WithTimeout(ctx, time.Duration(c.cfg.GetDInt(10, "checkTimeoutSeconds"))*time.Second)
				cres := performCheck(cctx, check.Fn, endpoint)
				cctxCancel()

				c.lock.Lock()
				eres.Results[check.Name] = cres
				c.broadcastUpdateNOLOCK()
				c.lock.Unlock()

				if checkNum != len(c.checks)-1 {
					if waitOrAbort(ctx.Done(), minWait-cres.Took) {
						return
					}
				}
			}
		})
	}

	wg.Wait()

	c.lock.Lock()
	c.state = "done"
	c.broadcastUpdateNOLOCK()
	c.lock.Unlock()
}

func waitOrAbort(abort <-chan struct{}, wait time.Duration) bool {
	select {
	case <-time.After(wait):
		return false
	case <-abort:
		return true
	}
}

var (
	checkResultScheduled = CheckResult{
		Brief: "schd",
		Color: "gray",
	}
	checkResultPending = CheckResult{
		Brief: "check",
		Color: "gray",
	}
)

func performCheck(ctx context.Context, checkFn CheckFunc, desc EndpointDescription) CheckResult {
	perf := time.Now()
	err := checkFn(ctx, desc)
	ret := CheckResult{
		Brief:   "OK",
		Color:   "green",
		Took:    time.Since(perf),
		Success: 1,
	}
	if err == nil {
		return ret
	}
	ret.Content = err.Error()
	if err2, ok := errors.AsType[CheckResult](err); ok {
		err2.Took = time.Since(perf)
		return err2
	}
	if errors.Is(err, ErrPartialRead{}) {
		ret.Brief = "FAIL"
		ret.Color = "orange"
		ret.Success = -1
		return ret
	}
	ret.Brief = "FAIL"
	ret.Color = "red"
	ret.Success = -1
	return ret
}
