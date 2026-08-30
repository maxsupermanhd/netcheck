package main

import (
	"bytes"
	"main/frontend"
	"net/http"

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

func serveTestpage(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write(bytes.Repeat([]byte{'f'}, 500_000))
}
