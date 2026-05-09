package executor

import (
	"os"
	"strings"

	"client-go/protocol"
)

type Session struct {
	Sock             *protocol.RATSocket
	ClientID         string
	HostName         string
	Cwd              string
	CurrentCommandID int
}

func NewSession(sock *protocol.RATSocket, clientID string) *Session {
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}

	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = clientID
	}

	return &Session{
		Sock:     sock,
		ClientID: strings.TrimSpace(clientID),
		HostName: host,
		Cwd:      wd,
	}
}