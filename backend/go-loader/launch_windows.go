//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func startDetached(cmd *exec.Cmd, cwd string) (*os.Process, error) {
	cmd.Dir = cwd
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000008 | 0x00000200,
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Process, nil
}