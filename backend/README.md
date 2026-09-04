# Remote Control Hub

Remote Control Hub (RCH) is a lightweight remote operations platform for managing connected Python-based clients from a browser UI or the server console.

It combines device/session management, interactive command execution, remote files, artifacts, PTY, Screen View, clipboard exchange, realtime device monitoring, scripts, background jobs, external tools, agent build/update, transfer tracking, notifications, and runtime configuration in one project.

> **Important**
> Use this project only on systems you own or are explicitly authorized to administer. RCH exposes powerful remote execution, file, process, screen, and automation capabilities and should be treated as an administrative/operations tool.

---

## Table of Contents

- [Project Status](#project-status)
- [Overview](#overview)
- [Core Capabilities](#core-capabilities)
- [Architecture](#architecture)
- [Connection and Identity Model](#connection-and-identity-model)
- [Protocol and Execution Model](#protocol-and-execution-model)
- [Web UI](#web-ui)
- [Remote Operations](#remote-operations)
- [Scripts and Jobs](#scripts-and-jobs)
- [External Tools](#external-tools)
- [Agent Build and Update](#agent-build-and-update)
- [Authentication and Script Grants](#authentication-and-script-grants)
- [Runtime Data and Preferences](#runtime-data-and-preferences)
- [Repository Layout](#repository-layout)
- [Getting Started](#getting-started)
- [Development Notes](#development-notes)
- [Roadmap / TODO](#roadmap--todo)
- [Known Limitations](#known-limitations)

---

## Project Status

The project has moved beyond the “missing basic features” stage. Most core operator workflows are already implemented.

| Area | Status | Notes |
| --- | --- | --- |
| Connection / machine identity | Mature | Stable `machine_id`, recent devices, machine grouping, hide/alias, connection history |
| Terminal / command | Mature | Command blocks, history, variables, autocomplete, cancellation, PTY |
| Remote Files | Mature | Browse/search/pagination/upload/download/preview/edit/ZIP Peek/Extract |
| Artifact | Mature | Unified server-side result/file storage with preview/download/history associations |
| Transfer | Mature | TransferManager, progress, cancel, recent transfers, lifecycle SSE |
| Device Monitor | Mature | Realtime dashboard plus process/app/detail monitor channels |
| Clipboard | Mature | Text/image/files/directories, Get/Send, Screen View integration |
| Screen View | Mature | Realtime frames, remote input/control, clipboard interaction |
| External Tools | Mature / evolving | Metadata-driven packages/modules/instances, presets, lifecycle operations |
| Notification | Mature / evolving | Toasts, event preferences, Notification Center; event scope/rules still need convergence |
| Scripts | Mature / evolving | Library, metadata, SDK, temporary grants, remote file pickers |
| Jobs | Functional / legacy runtime | Rich UI and reporting, but runtime is still thread/in-memory oriented |
| Agent build/update | Mature | Multiple build modes, bootstrap, update, client revision detection, safe handoff |
| Frontend | Modernized | Vue 3 + Vite + Element Plus; some large components still need decomposition |

The highest-value next work is mostly **consolidation and reliability**, not adding more isolated managers:

- structured Result/Error models
- automated tests for stateful subsystems
- History/WebTask/Job execution-model convergence
- unified runtime retention/cleanup
- formal SSE event scope/rules
- capability aggregation
- job runtime v2

---

## Overview

RCH is split into a control server, Python clients, shared protocol/runtime utilities, and a Vue 3 web UI.

At a high level it provides:

- **Web terminal** with command blocks, live output, cancellation, JSON rendering, autocomplete, history, and variables
- **Device sidebar** with online/offline/stale state, stable machine ordering, aliases, hiding, groups, and connection history
- **Remote file browser** with search, pagination, preview/edit, upload/download, drag upload, ZIP Peek, Extract Here, multi-select ZIP, and pinned paths
- **Transfer Center** with realtime progress, cancellation, recent transfer records, and lifecycle events
- **Artifact Center** for command/job/file results, previews, downloads, editing, and source tracing
- **Realtime device dashboard** for CPU, memory, storage, network, battery, processes, applications, process connections, and open files
- **PTY** backed by xterm.js
- **Screen View** with realtime frames, remote control, and clipboard integration
- **Clipboard** Get/Send for text, images, files, multiple files, and directories
- **Script Library** with metadata, editing/uploading, remote file parameters, Script SDK, and temporary API grants
- **Background Jobs** with metadata, parameters, lifecycle events, messages/files, and output export to Artifact
- **External Tool Manager** with packages, metadata, install/uninstall, oneshot/daemon execution, instances, logs, and presets
- **Keychain Manager** and Script SDK keychain access
- **Agent build/bootstrap/update** including client source revision detection
- **Settings** for toolbar layout and SSE notification preferences
- **Notification Center** with persisted notification history
- **Runtime Configuration UI** driven by client-reported configuration metadata rather than hard-coded front-end fields
- **Server console** using the same server/session core

The project intentionally remains file-based and does not require a database. Persistent state is stored under `runtime/` and resource metadata under `server/resources/`.

---

# Core Capabilities

## 1. Device and Connection Management

### Stable machine identity

The project distinguishes:

- `client_id` — a single running Client process/session
- `machine_id` — a stable machine-level identity used to correlate reconnects and multiple Client processes on the same host

A single machine can legitimately have multiple simultaneous Clients, for example different user/admin/system contexts.

### Recent devices

Previously connected machines remain visible after disconnect/reload.

Current behavior includes:

- recent/offline device persistence
- online/offline/stale state
- `last_seen_at`
- heartbeat / RTT
- connection duration and history
- machine-level alias
- hide one Client or an entire machine
- remove/forget device records from the UI
- machine-level groups
- stable machine ordering

### Stable sidebar ordering

`runtime/recent_devices.json` stores `machine_order`.

A machine receives a stable order the first time it is persisted. Later reconnects and new `client_id` values do not reorder that machine.

Within one machine, Clients are ordered by newest `connected_at` first.

The current build intentionally **does not include drag-to-reorder**. Ordering can be adjusted manually through the persisted `machine_order` value if necessary.

### Selection restoration

The browser remembers the last selected `machine_id`.

On refresh:

1. if that machine is still available, RCH selects its preferred current Client;
2. if the machine no longer exists, no unrelated device is selected automatically.

This avoids accidentally opening a different test/production device merely because connection arrival order changed.

### Device groups

Groups are assigned to **machines**, not individual connection sessions.

Features:

- create group
- rename group
- delete group
- assign/clear machine group
- filter sidebar by group
- show hidden devices within the selected group
- persist group membership in Server runtime

### Machine connection history

The UI can inspect connection history for a machine, including:

- historical Client IDs
- build/version metadata
- connected/disconnected time
- session duration
- command counts/status
- process/user/platform identity where available

---

## 2. Client Revision and Update Detection

RCH separates build identity from source identity.

### `build_version`

Identifies a specific generated build/bundle artifact.

### `client_revision`

Represents the Client source content revision.

The revision covers the actual Client bundle source roots:

```text
client/
core/
rchclient.py
```

The algorithm is exclusion-based, so newly added Client subdirectories/files are automatically included.

Excluded content includes:

```text
client/config/
__pycache__/
.git/
.idea/
.vscode/
venv/
node_modules/
dist/
build/
*.pyc / *.pyo / *.pyd
.DS_Store
```

This prevents profile/runtime connection configuration changes from being mistaken for Client source updates.

### Live Server revision

The Server does not rely on a startup-only cached source revision.

- connection list/status checks use the current Server-side source tree
- selecting an online Client performs an authoritative revision-status check
- Server source changes can therefore be detected without restarting the Server
- offline Clients are not continuously hashed/checked

### Outdated Client UX

Outdated Clients can still be opened.

For bundle Clients, the Terminal appends a single lightweight warning recommending `update`.

For `build_version=dev`, RCH does **not** recommend `update`, because a dev Client was started from source/IDE and a bundle update would change its launch model. Dev Clients are instructed to restart from the IDE/source environment instead.

Revision details can show:

- Client revision
- current Server revision
- file-level `added`
- file-level `modified`
- file-level `removed`

The Terminal warning is de-duplicated so repeatedly selecting the same Client does not continually append new warnings.

---

## 3. Interactive Terminal and Command Execution

### Command types

RCH intentionally keeps two command styles:

1. **shell-like commands** for convenient interactive use
2. **structured `acmd` commands** with metadata/argument validation

They share the same connection/runtime context without being forced into one syntax model.

### Command registry and manifests

The Client reports command metadata during handshake.

The Web UI uses manifests for:

- command lists
- autocomplete
- argument completion
- help
- command grouping
- capability-aware UI behavior

### Command blocks

Terminal output is modeled as command blocks rather than a flat stream.

Features include:

- live streaming output
- start/running/finished/error state
- colored markers such as informational/warning/error output
- collapse / expand output
- resend command
- save command output to Artifact
- structured JSON rendering
- command/execution detail
- history linkage

### JSON rendering

Complete JSON output can be rendered as:

- table
- flat key/value view
- raw JSON

The operator can switch between structured and raw representations and copy raw output.

### Command variables

Normal commands support Client-side runtime variables.

Namespaces:

```text
${rch:*}
${env:*}
${path:*}
```

Examples of `rch` values include:

```text
exec_path
launch_command
pid
uid
cwd
shell
hostname
command_id
client_id
machine_id
build_ver
py_ver
platform
os_type
os_alias
os_name
os_ver
arch
manufacturer
model
timestamp
datetime
```

`path` includes common dynamic paths such as:

```text
home
desktop
downloads
temp
```

`env` reads the target Client process environment dynamically.

This allows commands such as:

```text
run ${rch:exec_path}
cd ${path:temp}
shell mkdir ${path:temp}/rch-${rch:timestamp}
```

without requiring the Server to query those values before command submission.

### Autocomplete and history

Autocomplete merges:

- Client command manifest
- `acmd` manifest
- Server command candidates
- aliases
- Client variables
- path candidates
- quick history
- recent execution history

History features include:

- search
- pin/star
- pin ordering
- delete single entry
- `!<index>` replay
- machine-scoped history
- full execution history with output/artifact association

### Cancellation and timeouts

Commands use command context with:

- timeout
- cancel state
- cleanup handlers

Cancellation support depends on the active execution/transfer strategy.

### PTY

RCH includes an independent PTY session model:

- xterm.js frontend
- Unix PTY backend
- Windows `pywinpty`
- WebSocket transport
- input
- resize
- close/error lifecycle
- Server-side session cleanup

PTY is separate from normal one-shot shell execution.

---

## 4. Remote Files

The Remote Files UI includes:

### Navigation

- breadcrumb
- direct path navigation
- pagination
- search
- hidden file toggle
- pinned paths
- quick/common paths

### File operations

- create directory
- rename
- move/copy via cut/copy/paste flows
- delete single path
- multi-select delete
- upload to current directory
- drag-to-upload
- download single file
- multi-path ZIP download
- create ZIP

### ZIP operations

- ZIP Peek
- inspect entries
- read an entry
- Extract Here
- archive multiple selected paths

### Preview and editing

- text preview
- line-oriented editing/save
- image preview
- image compression option
- image metadata / EXIF / resolution
- preview cache

### Process/file relationship

The system can inspect which processes are associated with/opening files where supported.

---

## 5. Transfer Center and HTTP File Transfer

Large file movement is separated from the command/control socket.

RCH tracks transfers through a dedicated transfer model.

### Transfer Center

Features:

- running transfers
- recent transfers
- progress
- bytes/speed metadata where available
- cancellation
- clear recent
- delete recent record
- lifecycle SSE
- optional transfer notifications

Browser upload can enter the same transfer model rather than appearing as an opaque request.

### HTTP transfer modes

The Client currently supports two modes:

```text
legacy
cancelable
```

The active mode is exposed through Runtime Configuration and the Client handshake.

#### `legacy`

Compatibility/simple mode.

Upload uses Requests multipart behavior and therefore buffers the multipart body in memory.

To prevent very large memory spikes:

- Legacy **upload** is limited to 1 GB
- larger uploads should use `cancelable`

Legacy **download** uses streamed response reading and is not given the same 1 GB restriction.

#### `cancelable`

Streaming/cancellation-aware mode integrated with command/transfer cleanup.

### Runtime transfer configuration

Current dynamic settings include:

- `HTTP_TRANSFER_MODE`
- `HTTP_TRANSFER_BUFFER_SIZE`
- `HTTP_TRANSFER_IDLE_TIMEOUT_ENABLED`
- `HTTP_TRANSFER_IDLE_TIMEOUT_SECONDS`

The default idle timeout is long enough for large/slow transfers and can be disabled or adjusted through Configuration.

---

## 6. Artifact Center

Artifacts are the main server-side file/result collection model.

Capabilities include:

- list/filter
- download
- raw view
- preview
- rename
- edit content
- delete
- clear category
- upload
- send Artifact back to a Client
- save command output as Artifact
- associate produced files with commands/jobs/history

Artifacts are used by remote files, jobs, screenshots/previews, command outputs, and other result-producing flows.

A remaining technical debt is described in the Roadmap: a small number of remote-file/preview paths still derive Artifact identity from human-readable command text rather than a fully structured result envelope.

---

## 7. Realtime Device Monitor and Process Inspection

Device Monitor is a dedicated realtime session/channel system rather than repeated foreground shell commands.

Supported channels include:

```text
system
storage
network
battery
processes
apps
process_detail
process_connections
process_open_files
```

### Dashboard

Realtime summary includes:

- CPU
- memory
- swap
- uptime
- mounted/storage volumes
- network rate/counters
- battery where available

### Processes and apps

Features include:

- process list
- app list
- process details
- command line/path metadata
- CPU/memory data
- network connections
- open files
- kill process
- kill app

The new monitor path reduces contention with the foreground command slot.

Some older system-inspection Web/foreground paths remain as technical debt and should eventually be explicitly retained as fallback or removed.

---

## 8. Clipboard

Clipboard is exposed as a unified Get/Send dialog.

Supported types:

- text
- image
- file
- multiple files
- directory

### Get

- reads Client clipboard metadata/content
- refreshes when entering the Get view
- remote files are downloaded on demand rather than automatically staged to the Server
- remote directories can be downloaded as ZIP

### Send

- send text
- send image
- send files
- send directories/folder manifests
- drag/drop file/folder inputs in supported UI paths

Clipboard behavior is implemented with platform-specific adapters for Windows/macOS where necessary.

Screen View can use the same clipboard bridge for remote interaction.

A single “Download All” operation for a mixed multi-item remote clipboard is not implemented yet.

---

## 9. Screen View

Screen View runs as an independent session.

Features include:

- realtime frame streaming
- configurable FPS/quality
- WebSocket transport
- session state/error handling
- optional remote input/control
- keyboard/mouse events
- clipboard integration
- session cleanup

---

## 10. Scripts and Script SDK

### Script Library

Scripts are organized under Server resources and managed from the UI.

Capabilities:

- folder navigation
- create folder
- rename folder
- delete folder
- upload script
- create/edit/save
- rename
- delete
- run against selected Client
- metadata-driven parameters
- platform filtering
- Remote File Picker integration

### Script metadata

Scripts can declare `SCRIPT_METADATA` for richer execution forms and presentation.

### Script SDK

The Client runtime exposes Script SDK helpers for common RCH operations, including areas such as:

- artifacts
- command execution
- keychains
- workspace/pinned paths
- external tool helpers

### Temporary Script API grants

Scripts can request short-lived scoped API access.

The Server can issue a temporary token with:

- allowed scopes
- TTL
- maximum use count
- Client binding
- command binding

Current grants are URL/scope-level authorization, not a complete resource-level RBAC system.

---

## 11. Background Jobs

Background Jobs are metadata-driven long-running Client tasks managed through the Server/UI.

Current capabilities:

- job catalog
- platform filtering
- job source management/upload
- metadata-driven parameters
- Remote File/Folder parameter pickers
- start
- stop
- delete
- runtime messages
- file reports
- lifecycle SSE
- Job detail UI
- save/export Job output to structured JSON Artifact

### Current runtime model

The Job model is still one of the older runtime subsystems:

- Client jobs run in-process/thread style
- Server active Job state is primarily in memory
- reporting still has stronger HTTP coupling than newer session/channel subsystems

Process-based/detached Job runtime is a future refactor, not a completed feature.

---

## 12. External Tools

External Tools are metadata-driven packages/modules that can be installed and executed on Clients.

Current features:

- tool catalog
- metadata editing
- package download
- platform/architecture package selection
- install
- uninstall
- package-cache cleanup
- command preview / dry-run
- oneshot execution
- daemon execution
- instance list/status/stop/remove
- logs
- clear logs
- parameter presets / profiles
- lifecycle SSE for daemon/install/uninstall events

Short-lived oneshot execution is intentionally not treated like a noisy daemon lifecycle notification stream.

---

## 13. Keychains and One-liners

### Keychains

Server-side Keychain storage supports:

- list
- search/filter
- create
- edit
- delete
- resolve/read for authorized Script SDK use

Keychain data is stored in Server runtime JSON/files.

### Password Generator

The UI includes a password generator integrated with the credential-management workflow.

### One-liners

The toolbar exposes a One-liners dialog for reusable command snippets.

One-liners are currently a simple snippet catalog, not yet a general Quick Action/alias execution framework.

---

## 14. Notifications and SSE

### SSE Event Bus

The Web UI receives realtime events through SSE.

The event infrastructure supports targeted delivery using `target_tab_id`.

This already enables both:

- events intended for a specific browser tab/operation console
- events without a target, which can be observed more globally

What is still missing is a formal, consistent event taxonomy/scope policy across all subsystems.

### Notification preferences

Settings allow the operator to enable/disable notification categories.

Current categories include:

#### Devices

- online
- offline

#### Files / Transfer

- file ready
- transfer started
- transfer stopped
- transfer error

#### PTY

- started
- stopped
- error

#### Screen View

- starting
- stopped
- error

#### Background Jobs

- started
- finished
- error

#### External Tools

- daemon started/stopped/error
- install completed/failed
- uninstall completed/failed

#### Agent Build

- build completed
- build error

### Notification Center

Displayed notifications can be persisted to Server runtime and viewed in an Element Plus Drawer.

Features:

- notification time
- action links
- delete one
- clear all
- event ID de-duplication across tabs

Browser/OS desktop notifications and a general Rules/Alerts engine are not implemented yet.

---

## 15. Agent Build and Update

### Build modes

The current builder supports several delivery modes:

- **PyInstaller**
- **Bundle**
- **Go (Simple)**
- **Go (Loader)**

### PyInstaller

Builds a packaged Python Client executable for supported environments.

### Bundle

Packages Client source for source-based deployment/update.

The Bundle source roots match the Client revision roots:

```text
client/
core/
rchclient.py
```

### Go (Simple)

A lightweight Go Client path with a smaller feature surface than the full Python Client.

### Go (Loader)

A handoff/bootstrap-oriented Go path that can report environment information, obtain a Python bundle, launch it, and exit.

### Agent Outputs

The Web UI can:

- build
- list outputs
- download output
- delete output
- view build metadata
- clean build output/runtime directories manually

### Bootstrap

The Server can generate bootstrap scripts for initial deployment.

Bootstrap temporary files are cleaned after response completion/failure.

### Update

The Python Client `update` workflow:

1. requests a fresh bundle;
2. downloads it;
3. extracts into a new release;
4. launches the new Client;
5. waits for the new Client to complete connection/handshake and write a ready marker;
6. verifies the new process remains alive briefly;
7. only then exits the old Client.

If the new Client fails to start/handshake, the old Client remains connected and the update reports failure where possible.

Use:

```text
update --keep-old
```

to intentionally keep the old Client after the new one starts.

iOS retains its existing update/restart behavior instead of being forced through the desktop handoff model.

---

## 16. Runtime Configuration

Client runtime configuration is separate from source config.

Defaults live in:

```text
client/config/runtime_config.py
```

Runtime overrides are written to an external runtime configuration file rather than modifying source code.

Configuration metadata is reported to the Server and rendered dynamically in the Connection Info UI.

Examples include:

- command shell timeout
- command stream timeout
- HTTP transfer mode
- transfer buffer
- transfer idle timeout
- preview image compression
- Python execution mode
- reconnect interval
- remote watchdog
- local watchdog

This lets new exposed runtime settings appear in the UI without hard-coding each setting in the frontend.

---

# Architecture

## Server

The Server is the composition root and orchestration layer.

Major responsibilities:

- listener / Client session registry
- heartbeat and RTT
- command dispatch
- web task orchestration
- connection/recent device/history stores
- machine groups and device view preferences
- Artifact persistence
- Transfer service
- PTY / Screen View / Monitor session services
- Remote File orchestration
- Script and Job catalogs
- External Tool orchestration
- Keychains
- Agent builder/bootstrap/update support
- Notification preferences/history
- Toolbar preferences
- authentication and Script grants
- SSE event publication

`ServerWebService` is the root application facade and exposes explicit sub-facades/APIs instead of keeping old all-in-one forwarding methods.

## Client

The Python Client is the remote execution/runtime layer.

Major responsibilities:

- connection and handshake
- command registry
- shell/acmd execution
- command variables
- cancellation/context
- runtime configuration
- HTTP transfer strategies
- TransferManager
- PTY
- Screen View
- Clipboard adapters
- Device Monitor
- Process services
- Script execution / Script SDK
- Background Jobs
- External Tools
- watchdogs
- update handoff

## Core

Shared code includes:

- framed socket protocol
- message types
- machine identity
- platform helpers
- transfer settings
- command completion utilities
- Client revision calculation
- logging/utilities

## Frontend

The current frontend is **Vue 3 + Vite + Element Plus**.

It is no longer the old monolithic/static-JS architecture described by earlier versions of this README.

Major UI modules include:

- Device Sidebar
- Terminal / Command Input
- Connection Info
- Remote Files
- Remote ZIP Peek
- Artifact Center
- Transfer Center
- Clipboard
- PTY
- Screen View
- Device Dashboard / Processes
- Scripts
- Background Jobs
- External Tools
- Agents
- Keychains
- One-liners
- Notification Center
- Settings

---

# Connection and Identity Model

The identity model is intentionally layered:

```text
machine_id
  └─ one physical/logical machine

client_id
  └─ one running Client process/session

build_version
  └─ one generated build artifact

client_revision
  └─ source-content revision of the Client runtime
```

This distinction matters because:

- a Client restart creates a new `client_id`
- one machine may run multiple Clients simultaneously
- a build can change without changing machine identity
- a running dev Client can be outdated relative to current Server source without the Server restarting

---

# Protocol and Execution Model

## Socket control vs HTTP data plane

RCH separates command/control traffic from bulk file bytes.

### Socket/control path

Used for:

- handshake
- commands
- structured `acmd`
- results
- cancel/cancel acknowledgement
- heartbeat
- monitor/session control messages
- other realtime command/control state

The core framed protocol is implemented by `RCHSocket`.

### HTTP data path

Used for:

- file upload/download
- Artifact transfer
- Job-generated files
- Remote File download/upload
- browser upload
- other bulk payload flows

The Web file-transfer server runs separately from the main Web/API port.

## Web realtime paths

The browser additionally uses:

- **SSE** for event/task/notification updates
- **WebSocket** for PTY
- **WebSocket** for Screen View

## Client handshake

The Client handshake reports runtime information including:

- `client_id`
- `machine_id`
- hostname/platform/OS/arch
- process/user information
- current working directory
- Python version
- launch command
- command manifest
- variable manifest
- system paths
- transfer mode
- Python execution mode
- watchdog flags
- build version
- Client revision/manifest information

## Heartbeat and RTT

Heartbeat maintains:

- last-seen state
- stale/offline UX
- RTT
- live connection metadata

## Foreground execution slot

Normal command execution still has one active foreground execution slot per Client.

Several newer subsystems deliberately use independent managers/sessions so they do not need to occupy that slot for their entire lifetime:

- TransferManager
- Device Monitor
- PTY
- Screen View
- Background Job runtime

This reduces, but does not completely eliminate, `Client is busy` behavior for normal foreground commands.

## Python execution strategy

Current Python execution strategies include:

```text
inproc
subprocess_pipe
```

They are exposed through Runtime Configuration.

This is distinct from Background Job execution: Jobs are not yet a process-based runtime.

---

# Web UI

## Device Sidebar

Provides:

- online/offline/stale state
- stable machine ordering
- same-machine Client grouping/order
- alias
- hide Client
- hide machine
- show hidden
- machine group filter
- machine connection history
- revision/outdated indicator

## Terminal

Provides:

- Command Block model
- streaming output
- collapse/expand
- cancellation
- autocomplete
- variables
- history
- URL detection
- JSON rendering
- command resend
- save output as Artifact
- revision/update notice

## Toolbar and More menu

Toolbar actions are configurable.

Current action catalog includes:

```text
Remote Files
Artifacts
Info
Scripts
History
PTY
Screen View
Clipboard
External Tools
Jobs
Agents
Processes
Keychains
One-liners
```

Settings persists Toolbar vs More placement on the Server.

## Connection Info

Current tabs/views include:

- basic connection information
- command list
- runtime configuration
- Client variables

Configuration fields are generated from Client metadata.

## Dialog behavior

Major dialogs use Element Plus and are designed around a consistent full-page modal/overlay behavior, with scrollable internal content where necessary.

---

# Remote Operations

## Remote Files

See [Remote Files](#4-remote-files).

## Process control

Process management is primarily backed by Device Monitor channels and supports:

- inspect
- network connections
- open files
- kill

## Connection control

RCH also includes connection/watchdog control actions such as:

- disconnect
- force-kill/reset/spawn style recovery/control paths

These are control-plane features rather than simple shell aliases.

## File result flow

A common pattern is:

```text
Client operation
→ HTTP transfer
→ Server Artifact
→ Terminal/History/Job/Notification reference
```

This is preferable to embedding large payloads in command messages.

---

# Scripts and Jobs

## Script metadata

`SCRIPT_METADATA` drives:

- display
- platform
- parameter forms
- remote picker integration
- Script grant requirements

## Job metadata

`JOB_METADATA` drives:

- display/catalog
- platform filter
- parameter forms
- start behavior

## Remote pickers

Current job/script forms can use Remote File/Folder selectors where metadata declares those parameter types.

Artifact/Keychain-backed schema pickers and conditional visibility are future enhancements.

---

# External Tools

External Tools use a metadata-driven package/module/instance model.

The system separates:

- package/download metadata
- module/action metadata
- runtime instance
- parameter presets

This avoids hard-coding each external utility directly into the UI.

---

# Agent Build and Update

See [Agent Build and Update](#15-agent-build-and-update).

---

# Authentication and Script Grants

## Browser auth

The Web UI uses session login.

Configuration includes:

```text
RAT_WEB_SESSION_SECRET
RAT_ADMIN_USERNAME
RAT_ADMIN_PASSWORD
RAT_ADMIN_API_TOKEN
RAT_WEB_AUTH_SESSION_DAYS
RAT_WEB_SESSION_COOKIE_NAME
```

The repository currently contains development defaults. Override secrets/credentials through environment configuration before exposing the service outside a controlled environment.

## Static API token

External API clients can authenticate using the configured admin API token where supported by the auth guard.

## Script temporary grants

Script SDK calls can use temporary scoped grants instead of exposing the full admin token to a running Script.

Current grant capabilities include:

- route/scope allow-list
- expiry
- use count
- Client/command binding
- automatic revoke/cleanup

Resource-level authorization and multi-user RBAC are not yet implemented.

---

# Runtime Data and Preferences

The Server intentionally uses file/JSON-backed runtime state instead of a database.

Important paths include:

```text
runtime/recent_devices.json
runtime/device_groups.json
runtime/toolbar_preferences.json
runtime/notification_preferences.json
runtime/notification_center.json
runtime/command_history/
runtime/connection_history/
runtime/pinned_paths/
runtime/keychains/
runtime/web_files/
runtime/agent_output/
runtime/external_tool_param_presets/
```

## Recent devices

`runtime/recent_devices.json` stores machine-oriented recent state including stable `machine_order`.

## Device groups

`runtime/device_groups.json` stores machine group definitions/assignments.

## Toolbar preferences

`runtime/toolbar_preferences.json` stores Toolbar vs More layout.

## Notification preferences

`runtime/notification_preferences.json` stores event toggle preferences.

## Notification Center

`runtime/notification_center.json` stores notifications that were actually presented and retained by Notification Center.

## Client runtime overrides

Client runtime overrides are stored separately from source defaults so `set`/Configuration changes do not modify `client/config/runtime_config.py`.

---

# Repository Layout

At repository/archive root:

```text
.
├── backend/
│   ├── client/                  # Python Client runtime
│   ├── core/                    # Shared protocol/runtime utilities
│   ├── docs/                    # Backend/project-specific documentation
│   ├── server/                  # Server application, web/API, resources, runtime services
│   ├── README.md                # This project README
│   ├── rchclient.py             # Python Client entrypoint
│   ├── rchserver.py             # Server + console entrypoint
│   ├── run_web.py               # Server + Web/API/WS entrypoint
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── api/                 # API wrappers
    │   ├── components/          # Vue UI modules/dialogs
    │   ├── composables/         # Connection/SSE/terminal/task state
    │   └── data/                # Toolbar/notification/one-liner catalogs
    ├── index.html
    ├── package.json
    └── vite.config.js
```

## Key Server application areas

```text
server/application/
├── agent/
├── artifact/
├── auth/
├── clipboard/
├── command/
├── completion/
├── connection/
├── execution/
├── external_tools/
├── history/
├── jobs/
├── keychains/
├── monitor/
├── pinned_paths/
├── preferences/
├── screen/
├── scripts/
├── tasks/
├── terminal/
├── transfers/
└── web/
```

## Web route modules

Current Flask route modules include:

```text
agent
artifacts
auth
background_jobs
clipboard
command_execution
command_history
connections
device_monitor
external_tools
keychains
notification_history
notification_preferences
pinned_paths
remote_files
screen_view
scripts
stream_control
system_inspection
terminal
toolbar_preferences
transfers
```

---

# Getting Started

## Backend requirements

Typical backend/client dependencies are listed in:

```text
backend/requirements.txt
```

The project uses packages including Flask/FastAPI/Uvicorn/WebSockets, Requests, Pillow, psutil, and platform-specific integrations.

Install from the backend directory:

```bash
cd backend
python -m pip install -r requirements.txt
```

## Start the Server + console

```bash
cd backend
python rchserver.py
```

This starts:

- RCH socket listener
- heartbeat runner
- interactive server console

## Start the Web/API Server

```bash
cd backend
python run_web.py
```

This starts:

- RCH socket listener
- heartbeat runner
- main Web/API ASGI service
- PTY/Screen View WebSocket endpoints
- separate HTTP file-transfer server

Default ports are defined in `server/config/config.py`.

## Start the Python Client

Configure the target Server in the appropriate Client config/profile, then:

```bash
cd backend
python rchclient.py
```

## Frontend development

The active frontend is Vite + Vue 3.

```bash
cd frontend
npm install
npm run dev
```

The development server defaults to:

```text
http://localhost:5173
```

and proxies `/api` and `/ws` to the backend Web service.

Production/static integration should be handled by building/copying the frontend output into the static location expected by the Web Server deployment. The source archive itself is primarily configured for Vite development.

## Build frontend

```bash
cd frontend
npm run build
```

---

# Development Notes

## Frontend architecture

The old static modular-JS architecture has been replaced by Vue 3/Vite.

Current API wrappers already include modules such as:

- connections
- clipboard
- device groups
- external tools
- notification history/preferences
- screen view
- tasks
- toolbar preferences
- transfers

Some large Vue components still call APIs directly and should eventually migrate fully into `src/api/*`.

## Metadata-driven extensibility

Several systems are intentionally metadata-driven:

- commands
- `acmd`
- scripts
- jobs
- external tools
- runtime configuration
- Client variables

Prefer extending metadata/registries over hard-coding UI fields.

## Runtime cleanup already implemented locally

Several temporary resources already clean themselves up:

- preview cache can clear on Server startup
- normal upload temp paths clean after operation
- bootstrap temp files clean after response
- temporary archive directories clean after transfer/build use
- PTY sessions are released
- expired Script grants are cleaned
- `session_messages.log` was removed rather than retained indefinitely
- Transfer recent is bounded in memory

There is still no unified configurable RetentionService for all runtime categories.

## No formal automated test suite yet

The current repository does not contain a meaningful `tests/`, `test_*.py`, `*.spec.js`, or `*.test.js` suite.

Given the number of stateful subsystems now present, this is a significant reliability gap.

---

# Roadmap / TODO

This section is intentionally limited to work that is still genuinely incomplete or only partially complete in the current code.

Status:

- ✅ completed
- 🟡 partially implemented / needs convergence
- ⬜ not implemented
- ⏸ deferred / low priority

## Completed items that older README versions still listed as TODO

These are already implemented and should not be re-created:

- ✅ Vue 3 + Vite frontend
- ✅ xterm.js PTY
- ✅ Client-side command variables
- ✅ dynamic Client values such as PID/UID/shell/path
- ✅ shell-style command output redirection
- ✅ Terminal JSON / UI toggle
- ✅ Screen View
- ✅ file search
- ✅ hide/remove connection UI
- ✅ machine identity and connection history
- ✅ stable recent-device machine ordering
- ✅ Device Groups by `machine_id`
- ✅ External Tool Manager
- ✅ realtime device Dashboard
- ✅ process/app realtime monitor channels
- ✅ ZIP Peek
- ✅ Extract Here / unzip to current dir
- ✅ browser/remote download progress
- ✅ realtime progress message type
- ✅ Transfer Center / cancel / recent
- ✅ Notification Settings
- ✅ Notification Center
- ✅ External Tool lifecycle SSE
- ✅ Job start/end SSE
- ✅ Job output export to Artifact
- ✅ runtime Configuration UI
- ✅ Client variable manifest UI
- ✅ admin/static token plus temporary Script grants
- ✅ Client revision/update detection
- ✅ safe update handoff and `update --keep-old`
- ✅ Clipboard Get/Send
- ✅ multiple file/directory clipboard support
- ✅ Screen View clipboard interaction
- ✅ command block collapse/resend/save-to-Artifact

## P0 — architecture/reliability

### ⬜ Structured Result / Error envelope

The system still has multiple result/error shapes:

```text
human-readable command text
structured acmd payloads
HTTP JSON
SSE payloads
Transfer records
Job messages/files
Artifact-producing command text
```

Target direction:

```text
ExecutionResult
- status
- message
- data
- error
- artifacts[]
- actions[]
- meta
```

And a consistent error model:

```text
code
message
detail
retryable
context
```

This should also eliminate remaining parsing of human-readable `Artifact ID: ...` output.

### ⬜ Automated tests for core state machines

Priority coverage:

- Transfer lifecycle/cancel
- Device Monitor session lifecycle
- PTY lifecycle
- Screen View lifecycle
- EventBus tab targeting
- Notification preference gate
- machine group/recent-order behavior
- Client revision/update handoff
- Job state transitions
- Result/Error envelope

### 🟡 History / WebTask / Job execution-model convergence

Current models duplicate lifecycle/output fields.

Potential common abstractions:

```text
ExecutionIdentity
ExecutionLifecycle
ExecutionOutput
ExecutionArtifactRef
```

They do not have to become one store, but their core semantics should converge.

### 🟡 Unified runtime retention / cleanup

Already implemented locally:

- preview startup cleanup
- operation-scoped upload temp cleanup
- bootstrap temp cleanup
- temporary ZIP cleanup
- PTY session cleanup
- expired Script grant cleanup
- bounded Transfer recent
- removed `session_messages.log`

Still missing:

- one configurable RuntimeCleanup/Retention service
- crash-residual upload temp cleanup
- age-based Agent work/build cleanup
- watchdog log rotation
- old WebTask/Job runtime cleanup
- notification retention policy
- Settings choices such as disabled / 24h / 3 days

## P1 — platform convergence

### 🟡 SSE global vs current-console scope

Low-level `target_tab_id` routing already exists.

Still missing:

- formal scope field/model such as `tab | global`
- consistent default scope per event type
- separation of transport scope from presentation policy

### ⬜ Rules / Alerts engine

Future unified model for cases such as:

- external drive attached
- watchdog unhealthy/recovered
- device online/offline
- disk threshold
- job finished
- transfer failed
- future remind-me-when behavior

Suggested concepts:

```text
trigger
condition
scope
actions
cooldown
enabled
```

### 🟡 Capability Matrix

Capability data already exists in multiple manifests/handshake fields:

- command manifest
- variable manifest
- clipboard capabilities
- platform/arch
- Python execution mode
- transfer mode
- watchdog flags
- system paths
- build/revision

Still missing one aggregated capability model for frontend feature gating and mixed Client generations.

### ⬜ Job Runtime v2

Remaining work:

- process/subprocess Job execution mode
- detached Job
- real process kill/isolation
- persistent last-known runtime state
- less HTTP-coupled reporting/control

Do not confuse this with `PYTHON_EXECUTION_MODE=subprocess_pipe`, which is already implemented for Python command execution.

### ⬜ Multi-device batch execution

Not implemented.

Should be built only after structured results/capabilities/confirmation are strong enough to support:

- target selection
- concurrency limit
- dry-run/confirmation
- per-device results
- partial failure isolation

### ⬜ Quick Actions backed by Alias/Command

Current Toolbar supports only built-in action placement and One-liners are static snippets.

A future Quick Action model could support:

```text
builtin
alias
command
copy
```

### ⬜ Operation Audit / Event Log

Current history is fragmented across command history, connection history, notification history, Jobs, and Transfers.

A future audit/event model should capture:

- when
- browser tab/operator context
- target machine/client
- action/API
- result
- request/correlation ID

### 🟡 Frontend API-layer cleanup

`frontend/src/api/*` exists, but several large components still call `/api/...` directly.

Long-term target:

```text
Vue component
→ api module
→ shared http layer
```

### 🟡 Process legacy-path cleanup

Realtime Process/Apps UI now uses Device Monitor channels.

Older system-inspection/foreground command paths remain and should eventually be explicitly retained as fallback or removed.

## P2 — feature additions

### ⬜ Clipboard “Download All”

Current state:

- single file download ✅
- directory → ZIP ✅
- mixed/multiple remote clipboard items → one Download All archive ⬜

### ⬜ Remote PDF Preview

PDF-specific browser preview is not implemented.

Suggested order:

1. PDF
2. simple CSV/XLSX read-only table
3. DOCX/other office formats later

### ⬜ Watchdog lifecycle SSE

Watchdog exists, but there is no dedicated lifecycle event family for:

- watchdog restart reason
- unhealthy
- recovered

Prefer implementing this on top of the future event/rules model.

### ⬜ Desktop notifications

Current delivery channels are Web toast + Notification Center.

Browser/OS desktop notification can become another presentation/delivery channel after event scope/rules converge.

### ⬜ Listener management

No UI/runtime model currently exists for creating/switching listener types such as WS/TCP/HTTP.

### ⬜ Preview text encoding selector

Useful future addition for non-UTF8 remote text files.

## P3 / deferred

### ⏸ General file tree

Current breadcrumb + pagination + search + pinned paths already covers the main workflow.

A remote tree can generate many lazy network requests and is not high priority.

### ⏸ Word / Excel preview

Defer until PDF preview is proven useful.

### ⏸ curl-wrapper command layer

A wrapper around `curl` for Server APIs is not currently implemented.

If a first-class CLI automation layer is needed, a proper API client/facade is preferable to a large catalog of shell-generated curl strings.

### ⏸ Process thread list

Thread count exists; full thread listing is low priority compared with process connections/open files/cmdline/resource data.

## Explicit TODOs currently present in source

The code currently contains very few explicit `TODO` comments.

### `server/application/artifact/remote_file_service.py`

Remote File/Artifact result handling still contains a TODO to remove parsing of human-readable Artifact IDs from command output.

This belongs under the Structured Result work above.

### `client/commands/common/services/filesystem/path_resolver.py`

An empty path currently falls back to `.` and has a TODO for additional command-level defense to reduce accidental current-directory operations.

This is a small but worthwhile safety hardening item.

---

# Known Limitations

## 1. Foreground execution is still single-slot

One Client still effectively has one normal active foreground command slot.

Independent managers/sessions have reduced contention, but ordinary foreground commands can still report `Client is busy`.

## 2. Background Job runtime is still legacy-style

Jobs are not yet isolated process-based/detached workloads and active runtime state is not fully persistent across Server restarts.

## 3. Result/Error models are not globally normalized

Some subsystems already use structured payloads, but there is no single cross-system Result/Error envelope.

## 4. Runtime cleanup is distributed

Many temporary resources clean themselves correctly, but there is no one configurable retention policy/service for all runtime categories.

## 5. Event scope/rules are not formalized

SSE tab targeting exists, but event taxonomy, global/tab scope policy, alert rules, and desktop delivery are not one unified model yet.

## 6. Capability data is fragmented

The Server already has enough handshake/manifests to infer many capabilities, but there is no formal Capability Matrix used consistently by the UI.

## 7. No meaningful automated test suite

The current codebase has enough asynchronous/session/state-machine behavior that compile checks and manual UI testing are no longer sufficient as the only verification strategy.

## 8. Production frontend static deployment is not fully automated in this source layout

Frontend development is Vite-based and proxies to the backend.

The backend still expects a static deployment directory for integrated page serving, but the source archive does not contain an automated build/copy deployment step.

---

## License / Usage Note

Before publishing or redistributing this repository, add a license and usage policy appropriate to the intended environment.

Recommended documentation should include:

- explicit authorization-only usage statement
- deployment/security guidance
- license
- default-secret replacement requirements
