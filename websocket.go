package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"main/frontend"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a-h/templ"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/websocket"
)

func handleWebsocket(ws *websocket.Conn) {
	var clViewing atomic.Pointer[time.Time]
	var clView atomic.Pointer[string]
	def := "live"
	clView.Store(&def)

	wsSendElem(ws, "span", "status", netChecker.GetState())
	renderCurrentView(ws, &clView, &clViewing)
	sendHistory(ws, &clViewing, &clView)
	sendIndicator(ws, &clView, &clViewing)

	closeChan := make(chan struct{})
	wg := &sync.WaitGroup{}

	updHistory := storedResults.Listen()
	updResults := netChecker.ListenChan()

	wg.Go(func() {
		for {
			select {
			case <-updHistory:
				updHistory = storedResults.Listen()
				sendHistory(ws, &clViewing, &clView)
				renderCurrentView(ws, &clView, &clViewing)
			case <-updResults:
				updResults = netChecker.ListenChan()
				wsSendElem(ws, "span", "status", netChecker.GetState())
				if viewMode(&clView) == "live" {
					renderCurrentView(ws, &clView, &clViewing)
				}
			case <-closeChan:
				return
			}
		}
	})
	for {
		var msgA wsMessage
		err := wsRawCodec.Receive(ws, &msgA)
		if err != nil {
			close(closeChan)
			wg.Wait()
			return
		}
		var msg wsClientMessage
		err = json.Unmarshal(msgA.msg, &msg)
		if err != nil {
			log.Err(err).Str("msg", string(msgA.msg)).Msg("client unmarshal")
			close(closeChan)
			wg.Wait()
			return
		}
		switch {
		case msg.Action == "setView":
			setView(ws, msg.Data, &clView, &clViewing)
		case msg.Action == "selectRun":
			selectRun(ws, msg.Data, &clView, &clViewing)
		case msg.Action == "toggleSummary":
			setView(ws, "summary", &clView, &clViewing)
		case msg.Action == "":
			selectRun(ws, msg.Viewing, &clView, &clViewing)
		default:
			close(closeChan)
			wg.Wait()
			return
		}
	}
}

func viewMode(clView *atomic.Pointer[string]) string {
	if p := clView.Load(); p != nil {
		return *p
	}
	return "live"
}

func storeView(clView *atomic.Pointer[string], mode string) {
	m := mode
	clView.Store(&m)
}

// renderCurrentView puts the content for the active view into the #results div.
func renderCurrentView(ws *websocket.Conn, clView *atomic.Pointer[string], clViewing *atomic.Pointer[time.Time]) {
	switch viewMode(clView) {
	case "summary":
		wsSendComp(ws, "div", "results", frontend.SummaryView(storedResults.Get(), netChecks))
	case "history":
		if t := clViewing.Load(); t != nil {
			for _, v := range storedResults.Get() {
				if v.StartedAt.Equal(*t) {
					wsSendComp(ws, "div", "results", frontend.StatusesTable(v.Results, netChecks))
					return
				}
			}
		}
		wsSendComp(ws, "div", "results", frontend.StatusesTable(netChecker.GetResults(), netChecks))
	default:
		wsSendComp(ws, "div", "results", frontend.StatusesTable(netChecker.GetResults(), netChecks))
	}
}

func sendIndicator(ws *websocket.Conn, clView *atomic.Pointer[string], clViewing *atomic.Pointer[time.Time]) {
	switch viewMode(clView) {
	case "summary":
		wsSendElem(ws, "div", "selectedViewIndicator", "Viewing: summary")
	case "history":
		if t := clViewing.Load(); t != nil {
			wsSendElem(ws, "div", "selectedViewIndicator", "Viewing: "+t.Format(time.DateTime))
			return
		}
		wsSendElem(ws, "div", "selectedViewIndicator", "Viewing: history (no run selected)")
	default:
		wsSendElem(ws, "div", "selectedViewIndicator", "Viewing: live results")
	}
}

func sendHistory(ws *websocket.Conn, clViewing *atomic.Pointer[time.Time], clView *atomic.Pointer[string]) {
	var cv *time.Time
	if clViewing != nil {
		cv = clViewing.Load()
	}
	wsSendComp(ws, "div", "history", frontend.HistoryBox(storedResults.Get(), cv, viewMode(clView)))
}

func setView(ws *websocket.Conn, mode string, clView *atomic.Pointer[string], clViewing *atomic.Pointer[time.Time]) {
	if mode != "live" && mode != "history" && mode != "summary" {
		mode = "live"
	}
	storeView(clView, mode)
	if mode == "live" {
		clViewing.Store(nil)
	} else if mode == "history" && clViewing.Load() == nil {
		if runs := storedResults.Get(); len(runs) > 0 {
			t := runs[0].StartedAt
			clViewing.Store(&t)
		}
	}
	renderCurrentView(ws, clView, clViewing)
	sendHistory(ws, clViewing, clView)
	sendIndicator(ws, clView, clViewing)
}

func selectRun(ws *websocket.Conn, ts string, clView *atomic.Pointer[string], clViewing *atomic.Pointer[time.Time]) {
	for _, v := range storedResults.Get() {
		if v.StartedAt.Round(0).Format(time.RFC3339) == ts {
			tt := v.StartedAt
			clViewing.Store(&tt)
			storeView(clView, "history")
			renderCurrentView(ws, clView, clViewing)
			sendHistory(ws, clViewing, clView)
			sendIndicator(ws, clView, clViewing)
			wsSendClientViewing(ws, ts)
			return
		}
	}
	clViewing.Store(nil)
	storeView(clView, "live")
	renderCurrentView(ws, clView, clViewing)
	sendHistory(ws, clViewing, clView)
	sendIndicator(ws, clView, clViewing)
	wsSendClientViewing(ws, "")
}

type wsClientMessage struct {
	Action  string            `json:"action"`
	Data    string            `json:"data"`
	Viewing string            `json:"viewing"`
	HEADERS map[string]string `json:"HEADERS"`
}

func wsSendClientViewing(ws *websocket.Conn, ts string) error {
	fw, err := ws.NewFrameWriter(websocket.TextFrame)
	if err != nil {
		return err
	}
	fmt.Fprintf(fw, `<input type="hidden" id="state-viewing" name="viewing" value="%s" hx-swap-oob="true">`,
		htmlAttr(ts))
	return fw.Close()
}

func htmlAttr(s string) string {
	return strings.NewReplacer(
		`&`, "&amp;",
		`"`, "&quot;",
		`<`, "&lt;",
		`>`, "&gt;",
	).Replace(s)
}

func wsSendElem(ws *websocket.Conn, elem, id, content string) error {
	fw, err := ws.NewFrameWriter(websocket.TextFrame)
	if err != nil {
		return err
	}
	fmt.Fprintf(fw, `<%s id="%s">%s</%s>`, elem, id, content, elem)
	return fw.Close()
}

func wsSendComp(ws *websocket.Conn, elem, id string, content templ.Component) error {
	fw, err := ws.NewFrameWriter(websocket.TextFrame)
	if err != nil {
		return err
	}
	body := &strings.Builder{}
	fmt.Fprintf(body, `<%s id="%s">`, elem, id)
	err = content.Render(context.Background(), body)
	if err != nil {
		return err
	}
	fmt.Fprintf(body, `</%s>`, elem)
	_, err = fw.Write([]byte(body.String()))
	if err != nil {
		return err
	}
	return fw.Close()
}

type wsMessage struct {
	payloadType byte
	msg         []byte
}

var wsRawCodec = websocket.Codec{Marshal: wsRawMarshal, Unmarshal: wsRawUnmarshal}

func wsRawMarshal(v any) (msg []byte, payloadType byte, err error) {
	return nil, websocket.UnknownFrame, websocket.ErrNotSupported
}

func wsRawUnmarshal(msg []byte, payloadType byte, v any) (err error) {
	switch vv := v.(type) {
	case *wsMessage:
		vv.payloadType = payloadType
		vv.msg = msg
		return nil
	default:
		return errors.New("not wsMessage")
	}
}
