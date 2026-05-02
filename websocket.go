package main

import (
	"context"
	"errors"
	"fmt"
	"main/frontend"
	"strings"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/websocket"
)

func handleWebsocket(ws *websocket.Conn) {
	wsSendElem(ws, "span", "status", netChecker.GetState())
	wsSendComp(ws, "div", "results", frontend.StatusesTable(netChecker.GetResults()))
	closeChan := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Go(func() {
		for {
			select {
			case <-netChecker.ListenChan():
				wsSendElem(ws, "span", "status", netChecker.GetState())
				wsSendComp(ws, "div", "results", frontend.StatusesTable(netChecker.GetResults()))
			case <-closeChan:
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	for {
		var msgA wsMessage
		err := wsRawCodec.Receive(ws, &msgA)
		if err != nil {
			close(closeChan)
			return
		}
		log.Info().Msg(string(msgA.msg))
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
