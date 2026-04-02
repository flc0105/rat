package executor

import (
	"os/exec"
	"runtime"
)

func Execute(command string) (int, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, string(out)
	}
	return 1, string(out)
}
