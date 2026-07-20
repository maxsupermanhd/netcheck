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
	wsSendElem(ws, "span", "status", netChecker.GetState())
	wsSendComp(ws, "div", "results", frontend.StatusesTable(netChecker.GetResults(), netChecks))
	wsSendComp(ws, "div", "history", frontend.HistoryBox(storedResults.Get(), nil))
	wsSendElem(ws, "div", "selectedViewIndicator", `Viewing: live results`)
	closeChan := make(chan struct{})
	wg := &sync.WaitGroup{}

	updHistory := storedResults.Listen()
	updResults := netChecker.ListenChan()

	var clViewing atomic.Pointer[time.Time]

	wg.Go(func() {
		for {
			select {
			case <-updHistory:
				updHistory = storedResults.Listen()
				wsSendComp(ws, "div", "history", frontend.HistoryBox(storedResults.Get(), clViewing.Load()))
			case <-updResults:
				updResults = netChecker.ListenChan()
				wsSendElem(ws, "span", "status", netChecker.GetState())
				if clViewing.Load() == nil {
					wsSendComp(ws, "div", "results", frontend.StatusesTable(netChecker.GetResults(), netChecks))
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
		type ClientResp struct {
			Action string `json:"action"`
			Data   string `json:"data"`
		}
		var msg ClientResp
		err = json.Unmarshal(msgA.msg, &msg)
		if err != nil {
			log.Err(err).Str("msg", string(msgA.msg)).Msg("client unmarshal")
			close(closeChan)
			wg.Wait()
			return
		}
		switch msg.Action {
		case "changeView":
			clViewingLoaded := clViewing.Load()
			if clViewingLoaded != nil && msg.Data == clViewingLoaded.Format(time.RFC3339) {
				clViewing.Store(nil)
				wsSendComp(ws, "div", "results", frontend.StatusesTable(netChecker.GetResults(), netChecks))
				wsSendComp(ws, "div", "history", frontend.HistoryBox(storedResults.Get(), nil))
				wsSendElem(ws, "div", "selectedViewIndicator", `Viewing: live results`)
				break
			}
			found := false
			for _, v := range storedResults.Get() {
				if v.StartedAt.Round(0).Format(time.RFC3339) == msg.Data {
					t := v.StartedAt
					clViewing.Store(&t)
					wsSendComp(ws, "div", "results", frontend.StatusesTable(v.Results, netChecks))
					wsSendComp(ws, "div", "history", frontend.HistoryBox(storedResults.Get(), &t))
					wsSendElem(ws, "div", "selectedViewIndicator", `Viewing: `+v.StartedAt.Format(time.DateTime))
					found = true
					break
				}
			}
			if !found {
				invalidHistoryEntry := time.Now()
				clViewing.Store(&invalidHistoryEntry)
				wsSendElem(ws, "div", "results", `erm`)
			}
		default:
			close(closeChan)
			wg.Wait()
			return
		}
	}
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
