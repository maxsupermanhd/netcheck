package iocount

import (
	"io"
	"sync/atomic"
)

type CounterReader struct {
	W     io.Reader
	Count int64
}

func NewCounterReader(w io.Reader) *CounterReader {
	return &CounterReader{W: w}
}

func (cw *CounterReader) Read(p []byte) (int, error) {
	n, err := cw.W.Read(p)
	atomic.AddInt64(&cw.Count, int64(n))
	return n, err
}

type CounterWriter struct {
	W     io.Writer
	Count int64
}

func NewCounterWriter(w io.Writer) *CounterWriter {
	return &CounterWriter{W: w}
}

func (cw *CounterWriter) Write(p []byte) (int, error) {
	n, err := cw.W.Write(p)
	atomic.AddInt64(&cw.Count, int64(n))
	return n, err
}
