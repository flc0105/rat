package handler

import (
	"time"

	"client-go/executor"
)

func Handle(session *executor.Session, msg map[string]interface{}) {
	switch msg["type"] {
	case "heartbeat":
		_ = session.Sock.Send(map[string]interface{}{
			"type":      "heartbeat_ack",
			"id":        msg["id"],
			"client_ts": time.Now().Unix(),
			"cwd":       session.Cwd,
		})

	case "command":
		id := int(msg["id"].(float64))
		cmd := msg["text"].(string)

		status, result := session.Dispatch(id, cmd)

		_ = session.Sock.Send(map[string]interface{}{
			"type":   "result",
			"id":     id,
			"status": status,
			"text":   result,
			"cwd":    session.Cwd,
			"eof":    1,
		})
	}
}
