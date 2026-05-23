package netcheck

import (
	"main/lib/broadcaster"
	"sort"
	"sync"
)

type ResultsStorage struct {
	results    []RunResults
	lock       sync.Mutex
	hasUpdates broadcaster.Broadcaster
	limiter    int
}

func NewResultsStorage(initialResults []RunResults, limiter int) *ResultsStorage {
	sort.Slice(initialResults, func(a, b int) bool {
		return initialResults[a].StartedAt.Compare(initialResults[b].StartedAt) > 0
	})
	return &ResultsStorage{
		results: initialResults,
		limiter: max(1, limiter),
	}
}

func (s *ResultsStorage) Add(res RunResults) {
	s.lock.Lock()
	s.results = append(s.results, res)
	sort.Slice(s.results, func(a, b int) bool {
		return s.results[a].StartedAt.Compare(s.results[b].StartedAt) > 0
	})
	if len(s.results) > s.limiter {
		s.results = s.results[:s.limiter]
	}
	s.lock.Unlock()
	s.hasUpdates.Broadcast()
}

func (s *ResultsStorage) Get() []RunResults {
	s.lock.Lock()
	ret := make([]RunResults, len(s.results))
	for i, v := range s.results {
		ret[i].StartedAt = v.StartedAt
		results := make([]EndpointResults, len(v.Results))
		for i2, v2 := range v.Results {
			results[i2] = v2.Clone()
		}
		ret[i].Results = results
	}
	s.lock.Unlock()
	return ret
}

func (s *ResultsStorage) Listen() chan struct{} {
	return s.hasUpdates.Listen()
}
