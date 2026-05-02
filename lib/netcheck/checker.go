package netcheck

import (
	"errors"
	"maps"
	"sync"
	"time"
)

type EndpointDescription struct {
	Endpoint string
}

type CheckResult struct {
	Brief   string
	Color   string
	Took    time.Duration
	Content string
}

type EndpointResults struct {
	Endpoint   EndpointDescription
	ResolvedTo string
	Results    map[string]CheckResult
}

func (e EndpointResults) Clone() EndpointResults {
	ret := e
	ret.Results = maps.Clone(e.Results)
	return ret
}

type Checker struct {
	endpoints []EndpointDescription
	results   []EndpointResults
	state     string
	lock      sync.Mutex

	updateListener chan struct{}
}

func NewChecker(n []EndpointDescription) *Checker {
	c := &Checker{
		updateListener: make(chan struct{}),
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
	return
}

func (c *Checker) Run(exitChan <-chan struct{}) {
	for {
		select {
		case <-exitChan:
			return
		case <-time.After(5 * time.Second):
		}
		c.doChecks(exitChan)
		select {
		case <-exitChan:
			return
		case <-time.After(25 * time.Second):
		}
	}
}

type CheckFunc func(EndpointDescription, time.Duration) error

type Check struct {
	Name string
	Fn   CheckFunc
}

func (c *Checker) doChecks(exitChan <-chan struct{}) {

	checks := []Check{
		{Name: "http", Fn: CheckEndpointPlainHTTP},
		{Name: "tls12", Fn: CheckEndpointTLS12},
		{Name: "tls13", Fn: CheckEndpointTLS13},
		{Name: "tls13ech", Fn: CheckEndpointTLS13ECH},
	}

	wg := &sync.WaitGroup{}
	c.lock.Lock()
	c.results = make([]EndpointResults, len(c.endpoints))
	c.state = "working"
	c.broadcastUpdateNOLOCK()
	for i, endpoint := range c.endpoints {
		wg.Go(func() {
			eres := EndpointResults{
				Endpoint: endpoint,
				Results:  map[string]CheckResult{},
			}
			for _, check := range checks {
				eres.Results[check.Name] = checkResultPending
			}
			c.lock.Lock()
			c.results[i] = eres
			c.broadcastUpdateNOLOCK()
			c.lock.Unlock()

			for _, check := range checks {
				minWait := 5 * time.Second
				cres := performCheck(check.Fn, endpoint, 5*time.Second)
				c.lock.Lock()
				eres.Results[check.Name] = cres
				c.broadcastUpdateNOLOCK()
				c.lock.Unlock()
				time.Sleep(minWait - cres.Took)
			}
		})
	}
	c.lock.Unlock()
	wg.Wait()
	c.lock.Lock()
	c.state = "done"
	c.broadcastUpdateNOLOCK()
	c.lock.Unlock()
}

var checkResultPending = CheckResult{
	Brief: "schd",
	Color: "gray",
}

func performCheck(checkFn CheckFunc, desc EndpointDescription, timeout time.Duration) CheckResult {
	perf := time.Now()
	err := checkFn(desc, timeout)
	ret := CheckResult{
		Brief: "OK",
		Color: "green",
		Took:  time.Since(perf),
	}
	if err == nil {
		return ret
	}
	ret.Content = err.Error()
	if errors.Is(err, ErrEchNotUsed) {
		ret.Brief = "UNUSED"
		ret.Color = "yellow"
		return ret
	}
	if errors.Is(err, ErrNoEchDns) {
		ret.Brief = "NODNS"
		ret.Color = "gray"
		return ret
	}
	if errors.Is(err, ErrPartialRead{}) {
		ret.Brief = "FAIL"
		ret.Color = "orange"
		return ret
	}
	if errors.Is(err, ErrRedir{}) {
		ret.Brief = "REDIR"
		ret.Color = "yellow"
		return ret
	}
	ret.Brief = "FAIL"
	ret.Color = "red"
	return ret
}
