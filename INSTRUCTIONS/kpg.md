# Kraken Admin Tool — AI Plugin Developer Instruction Guide

> **Target Audience**: AI Coding Assistants, LLMs (ChatGPT, Claude, Gemini, DeepSeek, Cursor, Copilot), and Autonomous Agents.  
> **Mission**: Generate a production-grade, self-contained, and secure plugin for **Kraken Admin Tool** in an isolated workspace.

---

## 1. System Architecture & Security Model

Plugins in Kraken Admin Tool run inside a strictly isolated, multi-tier sandbox:

1. **Frontend Isolation (No IFrames)**:
   - Plugin UI code (`frontend/worker.js`) executes inside a dedicated **Web Worker thread**.
   - **Zero DOM / Storage Access**: The Web Worker has **no access** to `window`, `document`, `localStorage` (where user JWT tokens reside), cookies, or parent frames.
   - **Declarative Remote UI**: The worker computes UI state and sends declarative JSON node trees via `kraken.render(uiTree)`.
   - **Native Theme Inheritance**: The Kraken React host renders the nodes natively, automatically applying the user's active theme (Dark, Light, High Contrast, Colorblind Safe, Sepia).
   - **Closed Shadow DOM**: Custom HTML/CSS uses a sanitized, closed ShadowRoot.

2. **Backend Execution Options**:
   - **No Backend (`"runtime": { "type": "none" }`)**: Recommended for UI-only plugins, dashboards, widgets, monitoring viewers, and direct API integrations. Requires **zero compilation** and **no Go code**.
   - **WASM Sandbox (`"runtime": { "type": "wasm" }`)**: Embedded WebAssembly runtime powered by pure-Go `wazero`. Reads JSON request from `os.Stdin` and writes JSON response to `os.Stdout`. Quota: 64 MB memory, 15s execution timeout.
   - **Container Sidecar (`"runtime": { "type": "container" }`)**: Runs as a managed Docker container sidecar for long-running services, Python/Node/Go servers, or microservices.
     - **Auto-Build from Dockerfile**: You do **NOT** need to pre-build or push images to Docker Hub or external registries! Simply supply a standard `Dockerfile` in the root or in `backend/Dockerfile`. Kraken Admin Tool automatically compiles and tags the container image upon import.
     - **Pre-built Images**: If using an existing image from a registry, specify `"entrypoint": "image:tag"`.

3. **Built-in Kraken Auto-Builder (Source-Only Plugins)**:
   > ⚡ **CRITICAL FOR AI ASSISTANTS**:
   > Chat models and text generators (Microsoft Copilot, ChatGPT, Claude) typically **lack system compilers** (`go` / `tinygo`) in their generation sandboxes and cannot build Docker images.
   > - **For WASM plugins**: Simply provide Go source code in `backend/main.go`. Kraken Admin Tool compiles `plugin.wasm` automatically.
   > - **For Container plugins**: Simply provide a `Dockerfile` in the root or `backend/Dockerfile`. Kraken Admin Tool builds the container image locally automatically during import/installation!

---

## 2. Directory Layout Contract

Every plugin must be created as a standalone repository or folder with this exact layout:

```text
my-plugin-root/
├── plugin.json             # [REQUIRED] Identity, entrypoints, permissions and UI extensions
├── README.md               # [REQUIRED] Markdown documentation shown in store/inspection
├── icon.svg                # [OPTIONAL] Vector icon for UI navigation and cards
├── frontend/
│   └── worker.js           # [REQUIRED if UI is provided] Isolated Web Worker UI logic
└── backend/
    ├── main.go             # [REQUIRED if runtime.type is "wasm"] Go source code
    ├── go.mod              # [OPTIONAL] Module definition (auto-created by Kraken if omitted)
    └── plugin.wasm         # [OPTIONAL for AI] Pre-compiled WASI binary. If omitted, Kraken auto-compiles!
```

> 💡 **DIRECT FOLDER INSTALLATION**:
> Plugins can be installed directly from an uncompressed folder on the host (e.g. `./examples/plugins/my-plugin` or `/path/to/my-plugin`) via the UI ("Instalação Direta > Opção 3: Pasta Local Descompactada") or the REST API (`POST /api/plugins/install-directory`), without needing to package into `.zip` or `.tar.gz` first!

---

## 3. Manifest Specification (`plugin.json`)

The `plugin.json` file at the root defines the plugin's metadata, security permissions, and UI extension points.

### Mode A: Pure Frontend Plugin (Zero Compilation, 100% JavaScript)
Use this whenever your plugin only adds UI pages, dashboards, tables, or interacts with Kraken's existing APIs:
```json
{
  "id": "com.mycompany.service-dashboard",
  "name": "Service Health Dashboard",
  "version": "1.0.0",
  "description": "Visual overview of node health and container status",
  "author": "Your Company / Author",
  "license": "Apache-2.0",
  "runtime": {
    "type": "none"
  },
  "frontend": {
    "entrypoint": "frontend/worker.js"
  },
  "permissions": [
    "ui:sidebar",
    "ui:dashboard_widget",
    "docker:read"
  ],
  "ui_extensions": {
    "sidebar": [
      {
        "id": "nav-dashboard",
        "title": "Health Dashboard",
        "icon": "activity"
      }
    ],
    "dashboard_widgets": [
      {
        "id": "widget-summary",
        "title": "Node Status"
      }
    ]
  }
}
```

### Mode B: Plugin with Go Backend (Auto-Compiled by Kraken)
```json
{
  "id": "com.mycompany.port-auditor",
  "name": "Port Security Auditor",
  "version": "1.0.0",
  "description": "Audits open ports and flags security anomalies",
  "author": "Your Company / Author",
  "license": "Apache-2.0",
  "runtime": {
    "type": "wasm",
    "entrypoint": "backend/plugin.wasm"
  },
  "frontend": {
    "entrypoint": "frontend/worker.js"
  },
  "permissions": [
    "ui:sidebar",
    "ui:dashboard_widget",
    "hosts:read",
    "storage:kv"
  ],
  "ui_extensions": {
    "sidebar": [
      {
        "id": "nav-auditor",
        "title": "Port Auditor",
        "icon": "shield-check",
        "badge": "Audit"
      }
    ],
    "dashboard_widgets": [
      {
        "id": "widget-summary",
        "title": "Audit Summary"
      }
    ]
  }
}
```

### Mode C: Plugin with Container Backend (Auto-Built from Dockerfile)
Use this when your plugin requires Python, Node.js, external binaries, or long-running background workers.
Kraken will automatically build the container image using the provided `Dockerfile` (or `backend/Dockerfile`) during plugin import without requiring an external registry or pre-built images.
```json
{
  "id": "com.mycompany.container-service",
  "name": "Custom Microservice Plugin",
  "version": "1.0.0",
  "description": "Runs a Python or Node sidecar container service",
  "author": "Your Company / Author",
  "license": "Apache-2.0",
  "runtime": {
    "type": "container",
    "dockerfile": "Dockerfile",
    "port": 8080
  },
  "frontend": {
    "entrypoint": "frontend/worker.js"
  },
  "permissions": [
    "ui:sidebar",
    "docker:read"
  ]
}
```
> 💡 *Note*: If `dockerfile` is omitted in the manifest, Kraken automatically looks for `Dockerfile` or `backend/Dockerfile` in the plugin archive. If `entrypoint` is omitted, Kraken automatically generates a local tag `kraken-plugin-<id>:<version>`.

### Permitted Scopes (`permissions`)
Only declare permissions strictly required by your plugin:
- `ui:sidebar` — Adds an entry to the Kraken left navigation menu.
- `ui:dashboard_widget` — Renders an overview widget on the main dashboard.
- `ui:server_tab` — Adds a tab inside individual server/host detail pages.
- `docker:read` — Queries Docker containers, images, volumes, and stacks.
- `docker:write` — Starts, stops, or creates Docker containers and workloads.
- `hosts:read` — Queries remote host system package inventory and OS updates.
- `hosts:exec` — Dispatches administrative SSH commands on target hosts.
- `k8s:read` — Queries Kubernetes Pods, Deployments, and Namespaces.
- `k8s:write` — Restarts or scales Kubernetes workloads.
- `storage:kv` — Reads and writes scoped key-value persistent storage.
- `http:outbound` — Enables outbound HTTP calls to domains declared in `allowed_hosts`.
- `credentials:resolve` — Dynamically resolves server logon secrets (SSH keys, passwords) Just-in-Time for external Key Vaults.
- `credentials:manage` — Manages external Key Vault secrets (list, create, bind, test connection).

---

## 4. Frontend Development (`frontend/worker.js`)

In the Web Worker environment, the Kraken host automatically injects the global `self.kraken` object before your script executes.

### Global `kraken` SDK Methods

```javascript
// 1. Render UI tree (declarative Remote UI)
kraken.render(uiNode);

// 2. Listen to UI events (button clicks, form submits)
kraken.on(actionId, async (payload, eventType) => { ... });

// 3. Call backend action (invokes backend/plugin.wasm or container)
const result = await kraken.backend.call(actionName, payloadObject);

// 4. Scoped persistent Key-Value storage
await kraken.kv.set("last_run", new Date().toISOString());
const lastRun = await kraken.kv.get("last_run");

// 5. Logging (forwarded safely to host terminal and audit log)
kraken.log("Audit complete", { count: 42 });

// 6. Context variables
const currentSurface = self.kraken.surface; // "page" | "widget" | "tab"
const pluginId = self.kraken.pluginId;
```

### Declarative UI Components

The declarative tree emitted by `kraken.render(node)` supports the following node types:

| Component Type | Supported Properties | Usage / Children |
|---|---|---|
| `Page` | `title`, `description`, `children` | Top-level container for full-page surface |
| `Grid` | `cols` (1, 2, 3, 4), `gap`, `children` | Responsive column layout |
| `Card` | `title`, `description`, `children` | Elevated card container |
| `FieldGroup` / `FormRow` | `children` | Responsive horizontal group aligning inputs and buttons cleanly |
| `Form` | `id`, `actionId`, `children` | Form container emitting a `submit` event on submission |
| `Input` / `TextInput` | `id`, `label`, `placeholder`, `value`, `defaultValue`, `inputType` (`text`, `url`, `number`, `password`, `email`), `disabled`, `required`, `description` | Form input field with automatic two-way binding |
| `Textarea` | `id`, `label`, `placeholder`, `value`, `defaultValue`, `rows`, `disabled`, `required`, `description` | Multiline text input |
| `Select` | `id`, `label`, `options` (`[{label, value}]` or `["val1", "val2"]`), `value`, `disabled`, `description` | Dropdown select menu |
| `Checkbox` | `id`, `label`, `checked`, `disabled`, `description` | Boolean toggle checkbox |
| `Button` | `id`, `title`, `variant` (`default`, `secondary`, `destructive`, `outline`), `disabled` | Interactive button triggering `kraken.on(id)`. Automatically passes form inputs in `payload.formData` and top-level fields |
| `StatCard` | `title`, `value`, `description`, `variant` (`running`, `error`, `pending`, `outline`) | Key metric indicator |
| `Table` | `columns` (`[{key, label}]`), `rows` (`[{...}]`) | Data table with automatic styling |
| `Badge` | `label`, `variant` (`running`, `error`, `pending`, `outline`) | Status tag |
| `Alert` | `title`, `description`, `variant` (`info`, `warning`, `destructive`, `success`) | Contextual callout banner |
| `Terminal` / `CodeBlock` | `code`, `value`, `language` | Formatted monospaced output block |
| `CustomShadowHtml` | `html` | Isolated Shadow DOM HTML container (styles and scripts sandboxed) |
| `CodeEditor` | `id`, `value`, `defaultValue`, `language`, `theme`, `readOnly`, `lineNumbers`, `minimap`, `wordWrap`, `tabSize`, `insertSpaces`, `automaticLayout`, `height`, `saveActionId`, `label`, `description` | Full-featured Monaco code editor (VS Code-like) with syntax highlighting, line numbers, automatic indentation, tab formatting, bracket pair colorization, search/replace, responsive auto-layout, debounced change events, immediate form participation, and Ctrl+S/Cmd+S save shortcut support |

### CodeEditor Component (Monaco Editor)

Kraken Admin Tool provides a native Remote UI component called `CodeEditor`, powered by Monaco Editor (the editor core of VS Code). It allows isolated Web Worker plugins to provide professional code editing capabilities with syntax highlighting, line numbers, and shortcuts without requiring direct DOM access or loading untrusted external scripts.

#### Declarative Contract (`uiNode`)

```json
{
  "type": "CodeEditor",
  "id": "editor_content",
  "value": "const express = require('express');\nconst app = express();",
  "defaultValue": "",
  "language": "javascript",
  "theme": "dark",
  "readOnly": false,
  "lineNumbers": true,
  "minimap": false,
  "wordWrap": "off",
  "tabSize": 4,
  "insertSpaces": true,
  "automaticLayout": true,
  "height": 500,
  "saveActionId": "btn-save",
  "label": "Código-fonte da Aplicação",
  "description": "Edite o script e pressione Ctrl+S / Cmd+S para salvar"
}
```

#### Supported Properties & Safety Limits

| Property | Type | Default | Description & Security Constraints |
|---|---|---|---|
| `id` | `string` | **Required** | Unique editor identifier in the declarative UI tree. Used to bind `change` events and populate form values. |
| `value` | `string` | `""` | Document text content. Protected by a 5MB safety limit. Re-renders that keep identical content preserve cursor position, selection, undo stack, and scroll offset. |
| `defaultValue` | `string` | `""` | Initial fallback content when `value` is omitted. |
| `language` | `string` | `"plaintext"` | Monaco language ID or common alias (e.g. `js`, `ts`, `py`, `sh`, `tf`, `yml`, `docker`). Unknown languages safely fall back to `plaintext`. |
| `theme` | `string` | Inherits Kraken theme | `"dark"`, `"light"`, `"hc"` / `"high-contrast"`. If omitted, automatically synchronizes with active Kraken UI theme (Dark, Light, High Contrast, Colorblind, Sepia). |
| `readOnly` | `boolean` | `false` | When `true`, disables editing and prevents document modification. |
| `lineNumbers` | `boolean` | `true` | Shows line number gutter on the left margin. |
| `minimap` | `boolean` | `false` | Shows a code minimap overview on the right. |
| `wordWrap` | `string` | `"off"` | `"off"`, `"on"` or `"bounded"`. Safe sanitization falls back to `"off"` for invalid values. |
| `tabSize` | `number` | `4` | Number of spaces per tab indentation (safely clamped between 1 and 8). |
| `insertSpaces` | `boolean` | `true` | Inserts spaces instead of tab characters when pressing Tab. |
| `automaticLayout` | `boolean` | `true` | Automatically resizes editor canvas on container or window layout changes. |
| `height` | `number` | `400` | Editor height in pixels (safely clamped between 100px and 2000px). Displays a matching loading skeleton to guarantee Zero Cumulative Layout Shift (CLS). |
| `saveActionId` | `string` | `undefined` | When configured, pressing `Ctrl+S` (Windows/Linux) or `Cmd+S` (macOS) intercepts the browser save dialog and immediately triggers this action event with `eventType: "save"`. |
| `label` | `string` | `undefined` | Optional top label displayed above the editor. |
| `description` | `string` | `undefined` | Optional helper text displayed below the editor. |

#### Supported Languages & Aliases

The editor supports full syntax highlighting for:
`plaintext`, `javascript`, `typescript`, `json`, `html`, `xml`, `css`, `scss`, `less`, `markdown`, `yaml`, `ini`, `python`, `go`, `rust`, `java`, `kotlin`, `csharp`, `c`, `cpp`, `php`, `ruby`, `perl`, `lua`, `shell`, `powershell`, `sql`, `dockerfile`, and `hcl`.

Aliases automatically resolved:
- `js`, `jsx` → `javascript`
- `ts`, `tsx` → `typescript`
- `py`, `py3` → `python`
- `golang` → `go`
- `sh`, `bash`, `zsh` → `shell`
- `ps1`, `pwsh` → `powershell`
- `yml` → `yaml`
- `md` → `markdown`
- `docker` → `dockerfile`
- `tf`, `terraform` → `hcl`
- `c++` → `cpp`
- `c#` → `csharp`
- `rs` → `rust`
- `rb` → `ruby`

#### Web Worker Event Contracts

1. **Text Modification Event (`change` - Debounced ~250ms):**
   ```javascript
   kraken.on("editor_content", (payload, eventType) => {
     // eventType === "change"
     // payload.id === "editor_content"
     // payload.value -> complete current document string
     // payload.editor_content -> complete current document string
     // payload.formData -> dictionary containing all current form field values
   });
   ```

2. **Save Shortcut (`save` - Immediate on Ctrl+S / Cmd+S):**
   ```javascript
   kraken.on("btn-save", (payload, eventType) => {
     // eventType === "save"
     // payload.id === "editor_content"
     // payload.value -> latest document string at time of save
     // payload.editor_content -> latest document string
     // payload.formData -> dictionary containing all current form field values
   });
   ```

3. **Form & Button Integration:**
   - Every keystroke immediately synchronizes the host's form state synchronously.
   - When any `Button` in the same form or page is clicked, `payload.formData.editor_content` and `payload.editor_content` immediately reflect the latest editor text without waiting for the `change` debounce timer.

#### Complete Plugin Example (`worker.js`)

```javascript
let scriptCode = `// Microservice Script\nconst http = require('http');\n\nconst server = http.createServer((req, res) => {\n  res.writeHead(200, { 'Content-Type': 'application/json' });\n  res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));\n});\n\nserver.listen(8080);`;

function renderUI() {
  kraken.render({
    type: "Page",
    title: "Script Runner & Editor",
    description: "Manage container execution scripts using Monaco CodeEditor",
    children: [
      {
        type: "Card",
        title: "Service Script (index.js)",
        children: [
          {
            type: "CodeEditor",
            id: "service_script",
            value: scriptCode,
            language: "javascript",
            height: 480,
            lineNumbers: true,
            tabSize: 2,
            minimap: false,
            wordWrap: "on",
            saveActionId: "btn-save-script",
            label: "JavaScript Service Code",
            description: "Press Ctrl+S / Cmd+S or click 'Salvar' to persist changes."
          },
          {
            type: "FieldGroup",
            children: [
              {
                type: "Button",
                id: "btn-save-script",
                title: "Salvar Script (Ctrl+S)",
                variant: "default"
              },
              {
                type: "Button",
                id: "btn-reset",
                title: "Reset",
                variant: "outline"
              }
            ]
          }
        ]
      }
    ]
  });
}

// Initial render
renderUI();

// Track changes (debounced)
kraken.on("service_script", (payload, eventType) => {
  if (eventType === "change") {
    scriptCode = payload.value;
  }
});

// Save handler (triggered via Ctrl+S or clicking the button)
kraken.on("btn-save-script", async (payload, eventType) => {
  const currentCode = payload.service_script || payload.value;
  kraken.log(`[ScriptEditor] Saving script via ${eventType}...`);
  await kraken.kv.set("saved_service_script", currentCode);
  scriptCode = currentCode;
  kraken.log("[ScriptEditor] Script successfully saved!");
});

// Reset handler
kraken.on("btn-reset", () => {
  scriptCode = "// Default Script\nconsole.log('Restored');";
  renderUI();
});
```

### Form Inputs & Configuration Handling

Plugins that need user configuration (such as API URLs, thresholds, tokens, or filters) should use `Input` / `TextInput` inside a `Card` or `FieldGroup`.

**How Form Data Reaches Your Worker Event Handlers:**
1. Whenever a `Button` is clicked, Kraken bundles **all form input values** into `payload.formData` and also flattens them directly on `payload` by their `id`.
   - For example: if you define an `<Input id="api_url" ... />`, your button click handler receives:
     ```javascript
     kraken.on("save-config", async (payload) => {
       const url = payload.api_url || payload.formData?.api_url;
       await kraken.kv.set("api_url", url);
     });
     ```
2. You can also listen directly to input changes or enter presses with `kraken.on(inputId, (payload, eventType) => ...)`:
   - `eventType` will be `"change"` or `"enter"`.
   - `payload.value` contains the typed string.
3. Persistent settings should be saved to Kraken Key-Value store:
   - `await kraken.kv.set(key, value)`
   - `await kraken.kv.get(key)`

#### Example: Configuration Form with Remote API Integration

```javascript
// Local reactive state
const state = {
  apiUrl: "",
  data: null,
  loading: false,
  error: ""
};

function renderUI() {
  kraken.render({
    type: "Page",
    title: "Monitor de Serviço",
    children: [
      ...(state.error ? [{
        type: "Alert",
        title: "Erro",
        description: state.error,
        variant: "destructive"
      }] : []),
      {
        type: "Card",
        title: "Configuração da API",
        description: "Informe o endpoint HTTP para consumo de métricas.",
        children: [
          {
            type: "FieldGroup",
            children: [
              {
                type: "Input",
                id: "api_url",
                label: "URL da API",
                placeholder: "https://api.exemplo.com/metricas",
                inputType: "url",
                value: state.apiUrl
              },
              {
                type: "Button",
                id: "save-api",
                title: state.loading ? "Salvando..." : "Salvar e Atualizar",
                variant: "default",
                disabled: state.loading
              }
            ]
          }
        ]
      }
    ]
  });
}

kraken.on("save-api", async (payload) => {
  const url = (payload.api_url || payload.formData?.api_url || "").trim();
  if (!url) {
    state.error = "A URL da API não pode ser vazia.";
    renderUI();
    return;
  }
  state.apiUrl = url;
  await kraken.kv.set("api_url", url);
  state.error = "";
  await fetchMetrics();
});

// Initialize on plugin startup
(async () => {
  try {
    state.apiUrl = (await kraken.kv.get("api_url")) || "";
  } catch (_) {}
  renderUI();
  if (state.apiUrl) await fetchMetrics();
})();
```

### Complete Frontend Example (`frontend/worker.js`)

```javascript
// Local worker reactive state
const state = {
  items: [],
  warnings: 0,
  lastScan: "Never",
  loading: false
};

function renderUI() {
  const surface = self.kraken.surface || "page";

  // Compact Widget Surface (Overview Dashboard)
  if (surface === "widget") {
    kraken.render({
      type: "Card",
      title: "Auditor Status",
      children: [
        {
          type: "StatCard",
          title: "Issues Detected",
          value: String(state.warnings),
          variant: state.warnings > 0 ? "error" : "running",
          description: `Last run: ${state.lastScan}`
        },
        {
          type: "Button",
          id: "btn-run-audit",
          title: state.loading ? "Auditing..." : "Scan Now",
          disabled: state.loading
        }
      ]
    });
    return;
  }

  // Full Page Surface
  kraken.render({
    type: "Page",
    title: "Port Security Auditor",
    description: "Real-time inspection of listening services and open network ports",
    children: [
      {
        type: "Grid",
        cols: 2,
        children: [
          {
            type: "StatCard",
            title: "Total Audited",
            value: String(state.items.length || 6),
            variant: "running"
          },
          {
            type: "StatCard",
            title: "High Risk Flags",
            value: String(state.warnings),
            variant: state.warnings > 0 ? "error" : "running"
          }
        ]
      },
      {
        type: "Card",
        title: "Actions",
        children: [
          {
            type: "Button",
            id: "btn-run-audit",
            title: state.loading ? "Running Audit..." : "Run Security Audit",
            disabled: state.loading
          }
        ]
      },
      {
        type: "Card",
        title: "Discovered Ports & Services",
        children: [
          {
            type: "Table",
            columns: [
              { key: "host", label: "Host" },
              { key: "port", label: "Port" },
              { key: "proto", label: "Protocol" },
              { key: "service", label: "Service" },
              { key: "risk", label: "Risk" },
              { key: "status", label: "Status" }
            ],
            rows: state.items
          }
        ]
      }
    ]
  });
}

// Event handler for button clicks
kraken.on("btn-run-audit", async () => {
  state.loading = true;
  renderUI();

  try {
    // If backend WASM is enabled:
    const res = await kraken.backend.call("audit", { timestamp: Date.now() });
    if (res && res.findings) {
      state.items = res.findings;
      state.warnings = res.risk_detected || 0;
      state.lastScan = new Date().toLocaleTimeString();
    }
  } catch (err) {
    kraken.log("Audit error: " + (err.message || err));
  } finally {
    state.loading = false;
    renderUI();
  }
});

// Initial render
renderUI();
```

---

## 5. Backend Go Development & Kraken Auto-Builder

### Go WASI Contract
When `kraken.backend.call(action, payload)` is executed from the frontend:
1. The Kraken host pipes a JSON request into `os.Stdin`:
   ```json
   {
     "action": "audit",
     "payload": { ... },
     "plugin_id": "com.mycompany.port-auditor"
   }
   ```
2. The Go program reads `os.Stdin`, computes the result, and writes JSON to `os.Stdout`.
3. Standard library packages (`encoding/json`, `fmt`, `io`, `os`, `strings`, `time`) work out of the box with zero external dependencies.

### Complete Go Template (`backend/main.go`)

```go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

type Request struct {
	Action   string          `json:"action"`
	Payload  json.RawMessage `json:"payload"`
	PluginID string          `json:"plugin_id"`
}

type PortFinding struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Host    string `json:"host"`
	Status  string `json:"status"`
	Risk    string `json:"risk"`
}

type AuditResponse struct {
	Status        string        `json:"status"`
	Timestamp     string        `json:"timestamp"`
	TotalAudited  int           `json:"total_audited"`
	RiskDetected  int           `json:"risk_detected"`
	Findings      []PortFinding `json:"findings"`
}

func main() {
	var req Request
	data, err := io.ReadAll(os.Stdin)
	if err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &req)
	}

	// Execution logic
	resp := AuditResponse{
		Status:       "completed",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		TotalAudited: 4,
		RiskDetected: 1,
		Findings: []PortFinding{
			{Port: 22, Proto: "TCP", Service: "OpenSSH 8.9", Host: "srv-01", Status: "OK", Risk: "Baixo"},
			{Port: 80, Proto: "TCP", Service: "Nginx Ingress", Host: "srv-01", Status: "OK", Risk: "Baixo"},
			{Port: 443, Proto: "TCP", Service: "Nginx TLS", Host: "srv-01", Status: "OK", Risk: "Baixo"},
			{Port: 6379, Proto: "TCP", Service: "Redis Unprotected", Host: "srv-01", Status: "CRÍTICO", Risk: "Alto"},
		},
	}

	out, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(out)
}
```

### How Compilation Works (For AI and Developers)

#### Option 1: Let Kraken Compile Automatically (Recommended for AI Chat / Copilot)
- **Do not worry about compiling `plugin.wasm`!**
- Include your `backend/main.go` source code inside the archive.
- Leave `plugin.wasm` out, or include a placeholder.
- When the user uploads or installs the `.zip` / `.tar.gz`, Kraken detects the Go source files and compiles `plugin.wasm` automatically using its internal Go wasip1 / TinyGo engine in < 1 second.

#### Option 2: Pre-compilation via Docker (Developer Local Terminal)
If the developer wants to pre-compile the binary locally before distributing:
```bash
# Using TinyGo:
docker run --rm -v "$PWD":/src -w /src tinygo/tinygo:latest tinygo build -target=wasi -no-debug -o backend/plugin.wasm backend/main.go

# Or using standard Go (wasip1):
cd backend
GOOS=wasip1 GOARCH=wasm go build -ldflags="-s -w" -o plugin.wasm main.go
```

---

## 6. Host Adapter & Real Operations on Monitored Nodes

Kraken allows plugins to perform **real network audits and system administration** on registered remote servers (connected via SSH or local socket), without breaking sandbox isolation.

### The `needs_host_adapter` Protocol
Because WebAssembly sandboxes cannot open raw sockets to external subnets directly, the Go backend requests Kraken to execute host operations by returning a structured `needs_host_adapter` response:

```json
{
  "status": "needs_host_adapter",
  "data": {
    "operation": "network.scan_external_listeners",
    "scope": "all_monitored_hosts",
    "external_only": true
  }
}
```

Kraken checks if the user granted the required permission, executes the command across the target hosts, and automatically replaces the response with the real operational data (`status: "success"`).

### Supported Host Operations:

| Operation | Required Permission | Input Parameters | Output Data |
|---|---|---|---|
| `network.scan_external_listeners` | `hosts:read` | `{"scope": "all_monitored_hosts"}` ou `{"host": "srv-01"}` | `{"scanned_hosts": N, "ports": [{host, port, protocol, service, process, address, exposure}]}` |
| `network.block_external_port` | `hosts:exec` | `{"host": "srv-01", "port": 8080, "protocol": "tcp"}` | `{"message": "Port blocked successfully on host"}` |
| `hosts.list` | `hosts:read` | None | `{"hosts": [{id, name, host_url, status}]}` |
| `hosts.exec` | `hosts:exec` | `{"host": "srv-01", "cmd": "uptime"}` | `{"stdout": "...", "exit_code": 0}` |

> 🔒 **Security Rules**:
> - Automated blocking of SSH (Port 22) is permanently denied by safety policy.
> - The administrator must explicitly review and grant `hosts:read` and `hosts:exec` upon installing the plugin.

---

## 7. Packaging & Distribution

Kraken supports two package archive formats: `.zip` and `.tar.gz`.

### Packaging Rules
1. **Root Directory**: `plugin.json` and `README.md` must be at the root of the archive (or enclosed in a single root folder).
2. **Files to Include**:
   - For UI-only plugins (`runtime: "none"`): `plugin.json`, `README.md`, `frontend/worker.js`, optional `icon.svg`.
   - For WASM plugins: `plugin.json`, `README.md`, `frontend/worker.js`, `backend/main.go` (and optionally `backend/plugin.wasm`).
3. **No Traversal**: Never include `..` or absolute paths (`/etc/`, `C:\`).
4. **Limits**: Max archive size 50 MB (max uncompressed size 150 MB).

### Commands to Package

```bash
# For a Pure Frontend plugin:
zip -r my-plugin.zip plugin.json README.md frontend/

# For a Plugin with Go Backend (Kraken auto-compiles backend/main.go!):
zip -r my-plugin.zip plugin.json README.md frontend/ backend/

# Tar.gz format:
tar -czf my-plugin.tar.gz plugin.json README.md frontend/ backend/
```

---

## 8. Cryptographic Signing (Ed25519)

Kraken verifies publisher authenticity using Ed25519 signatures.

### 1. Generate Signing Keypair
Using the Kraken `pluginsign` utility (or OpenSSL/Go):
```bash
pluginsign -generate-key
```

### 2. Sign the Archive
```bash
pluginsign -sign my-plugin.zip -private-key <PRIVATE_KEY_HEX>
```
This generates `my-plugin.zip.sig`. When distributing via catalog, place `my-plugin.zip.sig` in the same download location.

---

## 9. Online Catalog Schema (`index.json`)

To host a private or public plugin store, serve an `index.json` file via any standard HTTP server (GitHub Pages, AWS S3, Nginx):

```json
{
  "name": "Corporate Plugin Repository",
  "description": "Approved internal plugins for Kraken Admin Tool",
  "url": "https://plugins.example.com/index.json",
  "updated_at": "2026-10-28T12:00:00Z",
  "plugins": [
    {
      "id": "com.mycompany.port-auditor",
      "name": "Port Security Auditor",
      "version": "1.0.0",
      "description": "Audits open ports and flags security anomalies",
      "author": "Your Company",
      "homepage": "https://example.com/plugin",
      "license": "Apache-2.0",
      "download_url": "https://plugins.example.com/downloads/my-plugin.zip",
      "sha256": "<CALCULATED_SHA256_HEX>",
      "runtime_type": "wasm",
      "permissions": [
        "ui:sidebar",
        "ui:dashboard_widget",
        "hosts:read",
        "storage:kv"
      ],
      "readme_markdown": "# Port Security Auditor\n\nFull documentation..."
    }
  ]
}
```

---

## 10. AI Assistant Self-Verification Checklist

Before presenting the generated plugin code to the user, the AI must verify:

- [ ] `plugin.json` contains valid `id` (alphanumeric with dots/dashes), `name`, `version`, `author`, and `description`.
- [ ] If the plugin only requires UI/dashboards, `runtime.type` is set to `"none"` (no Go backend needed).
- [ ] If `runtime.type` is `"wasm"`, `backend/main.go` is provided and reads `os.Stdin` / writes JSON to `os.Stdout`.
- [ ] (AI Environment): If the AI cannot compile WASM, the AI simply supplies the Go source code in `backend/main.go` and notes that Kraken will auto-build it.
- [ ] All declared permissions match the official list of 11 allowed scopes.
- [ ] `frontend/worker.js` does NOT reference `window`, `document`, `localStorage`, or `sessionStorage`.
- [ ] `frontend/worker.js` uses `kraken.render(uiTree)` with supported declarative nodes (`Page`, `Grid`, `Card`, `StatCard`, `Table`, `Button`, `Badge`, `Alert`).
- [ ] `frontend/worker.js` handles both `self.kraken.surface === "widget"` and full page rendering.
