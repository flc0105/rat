package executor

import (
	"os/exec"
	"runtime"
	"strings"
)

func (s *Session) Dispatch(commandID int, raw string) (int, string) {
	s.CurrentCommandID = commandID
	defer func() { s.CurrentCommandID = 0 }()

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, "empty command"
	}

	name, args := parseCommand(raw)
	if spec, ok := LookupCommand(name); ok {
		return spec.Handler(s, args)
	}

	return s.runShell(raw)
}

func parseCommand(raw string) (string, []string) {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return "", nil
	}
	return strings.ToLower(parts[0]), parts[1:]
}

func (s *Session) runShell(command string) (int, string) {
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