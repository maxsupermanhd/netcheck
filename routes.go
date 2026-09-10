package main

import (
	"bytes"
	"main/frontend"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/a-h/templ"
	"golang.org/x/net/websocket"
)

func makeHTTPServeMux() http.HandlerFunc {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", httpLog(handle404))

	mux.HandleFunc("GET /static/", httpLog(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))).ServeHTTP))

	mux.HandleFunc("GET /{$}", httpLog(templ.Handler(frontend.Page(frontend.Index())).ServeHTTP))

	mux.HandleFunc("GET /ws", websocket.Server{Handler: handleWebsocket}.ServeHTTP)

	mux.HandleFunc("GET /testpage", httpLog(serveTestpage))

	return mux.ServeHTTP
}

var (
	testpageBufs = sync.Pool{
		New: func() any {
			return &bytes.Buffer{}
		},
	}
	testpageSeed atomic.Uint64
)

func serveTestpage(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	rngSeed := testpageSeed.Add(2)
	rng := rand.NewPCG(uint64(rngSeed), uint64(rngSeed+1))
	buf := testpageBufs.Get().(*bytes.Buffer)
	i := 0
	for i < 200_000 {
		v := rng.Uint64()
		i += 64 / 4
		for range 64 / 4 {
			c := 0x20 + v&0x4f
			v >>= 4
			buf.WriteByte(byte(c))
		}
	}
	w.Write(buf.Bytes())
	buf.Reset()
	testpageBufs.Put(buf)
}
