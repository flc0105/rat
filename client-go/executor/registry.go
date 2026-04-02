package executor

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type CommandHandler func(*Session, []string) (int, string)

type CommandSpec struct {
	Name    string
	Usage   string
	Help    string
	Group   string
	Suggest bool
	Handler CommandHandler
}

var (
	commandRegistryMu sync.RWMutex
	commandRegistry   = map[string]CommandSpec{}
)

func MustRegisterCommand(spec CommandSpec) {
	name := strings.TrimSpace(strings.ToLower(spec.Name))
	if name == "" {
		panic("command name is required")
	}
	if spec.Handler == nil {
		panic(fmt.Sprintf("command handler is required: %s", name))
	}

	spec.Name = name
	spec.Group = normalizeGroup(spec.Group)

	commandRegistryMu.Lock()
	defer commandRegistryMu.Unlock()

	if _, exists := commandRegistry[name]; exists {
		panic(fmt.Sprintf("duplicate command registration: %s", name))
	}
	commandRegistry[name] = spec
}

func LookupCommand(name string) (CommandSpec, bool) {
	commandRegistryMu.RLock()
	defer commandRegistryMu.RUnlock()

	spec, ok := commandRegistry[strings.ToLower(strings.TrimSpace(name))]
	return spec, ok
}

func AllCommands() []CommandSpec {
	commandRegistryMu.RLock()
	defer commandRegistryMu.RUnlock()

	items := make([]CommandSpec, 0, len(commandRegistry))
	for _, spec := range commandRegistry {
		items = append(items, spec)
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Group != items[j].Group {
			return items[i].Group < items[j].Group
		}
		return items[i].Name < items[j].Name
	})

	return items
}

func CommandManifest() []interface{} {
	commands := AllCommands()
	result := make([]interface{}, 0, len(commands))
	for _, cmd := range commands {
		result = append(result, map[string]interface{}{
			"name":    cmd.Name,
			"usage":   defaultUsage(cmd),
			"help":    cmd.Help,
			"group":   cmd.Group,
			"suggest": cmd.Suggest,
		})
	}
	return result
}

func RenderHelpText() string {
	commands := AllCommands()
	if len(commands) == 0 {
		return "No builtin commands registered."
	}

	groups := map[string][]CommandSpec{}
	groupNames := make([]string, 0)

	for _, cmd := range commands {
		group := cmd.Group
		if _, ok := groups[group]; !ok {
			groupNames = append(groupNames, group)
		}
		groups[group] = append(groups[group], cmd)
	}

	sort.Strings(groupNames)

	lines := make([]string, 0, len(commands)+8)
	for idx, group := range groupNames {
		if idx > 0 {
			lines = append(lines, "")
		}

		lines = append(lines, "["+displayGroup(group)+"]")
		cmds := groups[group]
		sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name < cmds[j].Name })

		maxUsageLen := 0
		for _, cmd := range cmds {
			u := defaultUsage(cmd)
			if len(u) > maxUsageLen {
				maxUsageLen = len(u)
			}
		}

		for _, cmd := range cmds {
			lines = append(lines, fmt.Sprintf("%-*s  %s", maxUsageLen, defaultUsage(cmd), cmd.Help))
		}
	}

	lines = append(lines, "", "[Shell]", "<other command>  Run in system shell when no builtin command matches")
	return strings.Join(lines, "\n")
}

func normalizeGroup(group string) string {
	group = strings.TrimSpace(strings.ToLower(group))
	if group == "" {
		return "misc"
	}
	return group
}

func displayGroup(group string) string {
	switch group {
	case "session":
		return "Session"
	case "platform":
		return "Platform"
	case "file":
		return "File"
	default:
		if group == "" {
			return "Misc"
		}
		return strings.ToUpper(group[:1]) + group[1:]
	}
}

func defaultUsage(spec CommandSpec) string {
	if strings.TrimSpace(spec.Usage) != "" {
		return strings.TrimSpace(spec.Usage)
	}
	return spec.Name
}