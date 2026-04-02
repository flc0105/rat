package protocol

import (
	"encoding/binary"
	"encoding/json"
	"net"
)

type RATSocket struct {
	conn net.Conn
}

func NewRATSocket(conn net.Conn) *RATSocket {
	return &RATSocket{conn: conn}
}

func (r *RATSocket) Send(data map[string]interface{}) error {
	bytes, _ := json.Marshal(data)

	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(bytes)))

	if _, err := r.conn.Write(header); err != nil {
		return err
	}
	_, err := r.conn.Write(bytes)
	return err
}

func (r *RATSocket) Recv() (map[string]interface{}, error) {
	header := make([]byte, 4)
	if _, err := r.conn.Read(header); err != nil {
		return nil, err
	}

	length := binary.LittleEndian.Uint32(header)
	body := make([]byte, length)

	if _, err := r.conn.Read(body); err != nil {
		return nil, err
	}

	var result map[string]interface{}
	json.Unmarshal(body, &result)
	return result, nil
}
