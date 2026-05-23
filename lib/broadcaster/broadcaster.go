package broadcaster

import "sync"

type Broadcaster struct {
	ch   chan struct{}
	lock sync.Mutex
}

func (b *Broadcaster) Broadcast() {
	b.lock.Lock()
	old := b.ch
	b.ch = make(chan struct{})
	if old != nil {
		close(old)
	}
	b.lock.Unlock()
}

func (b *Broadcaster) Listen() chan struct{} {
	b.lock.Lock()
	if b.ch == nil {
		b.ch = make(chan struct{})
	}
	ret := b.ch
	b.lock.Unlock()
	return ret
}
