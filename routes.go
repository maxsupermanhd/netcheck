package main

import (
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

	return mux.ServeHTTP
}
