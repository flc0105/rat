package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	_ = Register(
		"help",
		Usage("help"),
		Help("Show available commands"),
		Group("session"),
		Suggest(),
		cmdHelp,
	)

	_ = Register(
		"kill",
		Usage("kill"),
		Help("Terminate current session"),
		Group("session"),
		Suggest(),
		cmdKill,
	)

	_ = Register(
		"cd",
		Usage("cd <path>"),
		Help("Change current working directory"),
		Group("session"),
		Suggest(),
		cmdCd,
	)

	_ = Register(
		"pwd",
		Usage("pwd"),
		Help("Print current working directory"),
		Group("session"),
		Suggest(),
		cmdPwd,
	)
)

func cmdHelp(_ *Session, _ []string) (int, string) {
	return 1, RenderHelpText()
}

func cmdKill(s *Session, _ []string) (int, string) {
	_ = s.Sock.Close()
	os.Exit(0)
	return 1, ""
}

func cmdCd(s *Session, args []string) (int, string) {
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

func cmdPwd(s *Session, _ []string) (int, string) {
	return 1, s.Cwd
}