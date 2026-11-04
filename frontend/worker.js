/**
 * Kraken Admin Tool — Azure Key Vault Integration Plugin
 * Frontend Worker (Remote Declarative UI)
 */

// Local reactive state
const state = {
  config: {
    auth_method: "user_account",
    tenant_id: "",
    client_id: "",
    client_secret: "",
    vault_name: "",
    vault_url: "",
    auto_convention: false, // Default false when disconnected
    naming_pattern: "srv-{hostname}-pwd",
    server_bindings: {}, // serverId -> secretName
    active_account_id: "",
    accounts: [] // [{ id, email, name, tenant_id, source, token, access_token, refresh_token, expires_at }]
  },
  discoveredVaults: [],
  discoveringVaults: false,
  krakenUser: null,
  isKrakenUserMicrosoft: false,
  deviceLogin: {
    active: false,
    user_code: "",
    device_code: "",
    verification_uri: "https://microsoft.com/devicelogin",
    message: "",
    polling: false,
    pollTimer: null,
    isChecking: false,
    completed: false
  },
  bindForm: {
    selected_server_id: "",
    secret_name: "",
    create_new_secretValue: ""
  },
  secrets: [],
  secretsTable: {
    searchQuery: "",
    pageSize: 10,
    currentPage: 1
  },
  revealedSecrets: {}, // { [name]: { value: string, isMasked: boolean } } strictly in-memory
  secretVersions: {}, // { [name]: number } to bust React input state cache on updates
  loadingSecretName: "",
  copyLoadingSecret: "",
  copiedSecretName: "",
  copiedSecretTimeout: null,
  clipboardNotice: null,
  clipboardTimerInterval: null,
  servers: [],
  testResult: null,
  loading: false,
  saving: false,
  message: { type: "", text: "" }
};

// -------------------------------------------------------------
// JWT Helper (Safe Base64URL + UTF-8 Decoder for Web Worker)
// -------------------------------------------------------------

function parseJwtClaims(jwtStr) {
  if (!jwtStr || typeof jwtStr !== "string") return null;
  try {
    const parts = jwtStr.split(".");
    if (parts.length < 2) return null;

    let base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4 !== 0) {
      base64 += "=";
    }

    const binaryStr = self.atob(base64);
    let jsonStr;
    try {
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }
      jsonStr = new TextDecoder("utf-8").decode(bytes);
    } catch (_) {
      jsonStr = binaryStr;
    }

    return JSON.parse(jsonStr);
  } catch (err) {
    self.kraken.log("Failed to parse JWT claims: " + (err.message || err));
    return null;
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// -------------------------------------------------------------
// IndexedDB Helper for Web Worker
// -------------------------------------------------------------

function openLocalIDB() {
  return new Promise((resolve) => {
    if (!self.indexedDB) {
      resolve(null);
      return;
    }
    try {
      const req = self.indexedDB.open("kraken_azure_kv_plugin_db", 1);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains("kv")) {
          db.createObjectStore("kv");
        }
      };
      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror = () => resolve(null);
    } catch (_) {
      resolve(null);
    }
  });
}

async function idbGet(key) {
  const db = await openLocalIDB();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction("kv", "readonly");
      const req = tx.objectStore("kv").get(key);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => resolve(null);
    } catch (_) {
      resolve(null);
    }
  });
}

async function idbSet(key, val) {
  const db = await openLocalIDB();
  if (!db) return;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction("kv", "readwrite");
      tx.objectStore("kv").put(val, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    } catch (_) {
      resolve();
    }
  });
}

async function idbClear() {
  const db = await openLocalIDB();
  if (!db) return;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction("kv", "readwrite");
      tx.objectStore("kv").clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    } catch (_) {
      resolve();
    }
  });
}

// -------------------------------------------------------------
// Backend Host Adapter Invocation Helper
// -------------------------------------------------------------

async function callBackendAction(action, payload, maxRetries = 4) {
  let attempt = 0;
  while (attempt < maxRetries) {
    attempt++;
    try {
      const res = await self.kraken.backend.call(action, payload);
      if (res) {
        const errMsg = String(res.error || res.data?.error?.message || res.data?.error || "");
        if (errMsg.includes("not instantiated") || errMsg.includes("module[kraken]") || errMsg.includes("failed to instantiate")) {
          if (attempt < maxRetries) {
            await new Promise(r => setTimeout(r, 200 * attempt));
            continue;
          }
        }

        if (res.data && typeof res.data.stdout === "string") {
          const trimmed = res.data.stdout.trim();
          if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
              const parsed = JSON.parse(trimmed);
              return { status: "success", data: parsed };
            } catch (_) {
              const lines = trimmed.split("\n");
              for (let i = lines.length - 1; i >= 0; i--) {
                const line = lines[i].trim();
                if (line.startsWith("{")) {
                  try {
                    const parsedLine = JSON.parse(line);
                    return { status: "success", data: parsedLine };
                  } catch (_) {}
                }
              }
            }
          }
        }
        return res;
      }
    } catch (err) {
      const msg = String(err?.message || err);
      if ((msg.includes("not instantiated") || msg.includes("module[kraken]") || msg.includes("failed to instantiate")) && attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 200 * attempt));
        continue;
      }
      throw err;
    }
  }
  return null;
}

// -------------------------------------------------------------
// Kraken User & Session Detection
// -------------------------------------------------------------

function detectKrakenUser() {
  const user = self.kraken.user || self.kraken.params?.user || self.kraken.context?.user || self.kraken.session?.user || null;
  state.krakenUser = user;

  if (!user) {
    state.isKrakenUserMicrosoft = false;
    return;
  }

  const provider = String(user.auth_provider || user.provider || "").toLowerCase();
  const email = String(user.email || user.username || "").toLowerCase();

  const isMsProvider = provider.includes("microsoft") || provider.includes("azure") || provider.includes("entra") || provider.includes("office365");
  const isMsDomain = email.endsWith("@outlook.com") ||
                     email.endsWith("@hotmail.com") ||
                     email.endsWith("@live.com") ||
                     email.endsWith("@microsoft.com") ||
                     email.includes(".onmicrosoft.com");

  state.isKrakenUserMicrosoft = isMsProvider || isMsDomain;
}

function getActiveAccount() {
  if (!state.config.accounts || state.config.accounts.length === 0) return null;
  return state.config.accounts.find(a => a.id === state.config.active_account_id) || state.config.accounts[0];
}

function isKeyVaultOperable() {
  const activeAcc = getActiveAccount();
  const hasVault = Boolean(state.config.vault_name || state.config.vault_url);
  const hasAuth = Boolean(
    activeAcc ||
    (state.config.auth_method === "service_principal" && state.config.client_id && state.config.client_secret) ||
    state.config.auth_method === "managed_identity" ||
    state.config.auth_method === "azure_cli"
  );
  return hasVault && hasAuth;
}

async function persistConfig() {
  const serialized = JSON.stringify(state.config);
  try {
    await idbSet("azure_kv_config", serialized);
  } catch (_) {}
  try {
    await self.kraken.kv.set("azure_kv_config", serialized);
  } catch (err) {
    self.kraken.log("Error persisting Azure KV config to backend: " + (err.message || err));
  }
}

async function loadConfig() {
  let raw = null;
  try {
    const backendRaw = await self.kraken.kv.get("azure_kv_config");
    if (backendRaw && typeof backendRaw === "string" && backendRaw.trim().startsWith("{")) {
      raw = backendRaw;
    } else if (backendRaw && typeof backendRaw === "object" && backendRaw.auth_method) {
      raw = JSON.stringify(backendRaw);
    }
  } catch (err) {
    self.kraken.log("Backend KV get fallback: " + (err.message || err));
  }

  if (!raw) {
    try {
      raw = await idbGet("azure_kv_config");
    } catch (_) {}
  }

  if (raw) {
    try {
      const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
      if (parsed && typeof parsed === "object") {
        state.config = { ...state.config, ...parsed };
        if (!state.config.server_bindings) state.config.server_bindings = {};
        if (!Array.isArray(state.config.accounts)) state.config.accounts = [];
      }
    } catch (err) {
      self.kraken.log("Failed to parse KV config: " + (err.message || err));
    }
  }
}

function extractHostname(hostUrl, fallbackName) {
  if (!hostUrl) return fallbackName || "unknown";
  let h = String(hostUrl).trim();
  if (h.startsWith("unix://")) return "localhost";
  h = h.replace(/^[a-zA-Z0-9+.-]+:\/\//, "");
  if (h.includes("@")) {
    h = h.split("@").pop();
  }
  if (h.includes(":")) {
    h = h.split(":")[0];
  }
  return h || fallbackName || "unknown";
}

async function loadMonitoredServers() {
  try {
    const res = await callBackendAction("get_hosts", {});
    const hostList = res?.data?.hosts || res?.hosts || [];
    if (Array.isArray(hostList) && hostList.length > 0) {
      // Filter out local docker sockets (Local Daemon / unix sockets) so only real remote servers appear
      state.servers = hostList
        .filter(h => {
          const url = String(h.host_url || "").toLowerCase();
          const name = String(h.name || "").toLowerCase();
          if (name.includes("daemon") || url.startsWith("unix://")) return false;
          return true;
        })
        .map(h => ({
          id: String(h.id),
          name: h.name || String(h.id),
          hostname: extractHostname(h.host_url, h.name),
          host_url: h.host_url || "",
          status: h.status || "UNKNOWN"
        }));

      if (!state.bindForm.selected_server_id && state.servers.length > 0) {
        state.bindForm.selected_server_id = state.servers[0].id;
      }
      return;
    }
  } catch (err) {
    self.kraken.log("Failed to load hosts from Kraken: " + (err.message || err));
  }

  if (!state.servers || state.servers.length === 0) {
    state.servers = [];
  }
}

// -------------------------------------------------------------
// Auto-Discovery of Key Vaults from Azure Resource Manager
// -------------------------------------------------------------

async function discoverUserVaults(autoSelectIfSingle) {
  const activeAcc = getActiveAccount();
  if (!activeAcc) return;

  state.discoveringVaults = true;
  renderUI();

  try {
    const res = await callBackendAction("list_user_vaults", state.config);
    let vaultsFound = [];

    if (res && res.data) {
      const d = res.data;
      if (d.error && d.error.message) {
        state.message = {
          type: "warning",
          text: `Aviso ao listar cofres no Azure: ${d.error.message}`
        };
        renderUI();
        return;
      }
      if (Array.isArray(d.vaults)) {
        vaultsFound = d.vaults;
      } else if (Array.isArray(d.value)) {
        vaultsFound = d.value;
      }
    }

    if (vaultsFound.length > 0) {
      state.discoveredVaults = vaultsFound.map(v => {
        const name = v.name || v.id?.split("/").pop() || "vault";
        const url = v.properties?.vaultUri || `https://${name}.vault.azure.net`;
        const location = v.location || "";
        return { name, url, location };
      });

      if (autoSelectIfSingle && (!state.config.vault_name || state.config.vault_name.trim() === "")) {
        const target = state.discoveredVaults[0];
        state.config.vault_name = target.name;
        state.config.vault_url = target.url;
        await persistConfig();
      }

      state.message = {
        type: "success",
        text: `${state.discoveredVaults.length} Azure Key Vault(s) localizado(s) na sua assinatura!`
      };
    } else {
      self.kraken.log("No vaults returned from ARM discovery");
      state.message = {
        type: "info",
        text: "Nenhum Key Vault foi retornado pela API da Azure para as assinaturas vinculadas a esta conta."
      };
    }
  } catch (err) {
    self.kraken.log("Failed to discover Azure Key Vaults: " + (err.message || err));
    state.message = {
      type: "error",
      text: `Erro ao buscar Key Vaults: ${err.message || err}`
    };
  } finally {
    state.discoveringVaults = false;
    renderUI();
  }
}

function stopPollingTimer() {
  if (state.deviceLogin.pollTimer) {
    clearInterval(state.deviceLogin.pollTimer);
    state.deviceLogin.pollTimer = null;
  }
}

function startPollingTimer() {
  stopPollingTimer();
  state.deviceLogin.pollTimer = setInterval(async () => {
    if (!state.deviceLogin.active || !state.deviceLogin.device_code || state.deviceLogin.completed) {
      stopPollingTimer();
      return;
    }
    if (state.deviceLogin.isChecking) return;

    await performPollCheck(true);
  }, 3500);
}

// Unified poll verification function
async function performPollCheck(isAutomatic) {
  if (!state.deviceLogin.device_code || state.deviceLogin.completed) return;
  if (state.deviceLogin.isChecking) return;

  state.deviceLogin.isChecking = true;
  if (!isAutomatic) {
    state.deviceLogin.polling = true;
    renderUI();
  }

  try {
    const res = await callBackendAction("auth.poll_device_login", {
      config: state.config,
      device_code: state.deviceLogin.device_code
    });

    if (state.deviceLogin.completed) {
      return;
    }

    if (res && res.data) {
      const data = res.data;

      const rawToken = data.access_token || (data.account && (data.account.access_token || data.account.token)) || "";
      if (rawToken) {
        let newAcc;
        if (data.account && (data.account.token || data.account.access_token)) {
          newAcc = {
            ...data.account,
            token: data.account.token || data.account.access_token,
            access_token: data.account.access_token || data.account.token
          };
        } else {
          let email = "";
          let name = "";
          let tenantId = state.config.tenant_id || "common";

          const idClaims = parseJwtClaims(data.id_token) || {};
          const accessClaims = parseJwtClaims(rawToken) || {};
          const claims = { ...accessClaims, ...idClaims };

          if (claims.name) name = String(claims.name);
          else if (claims.given_name) name = String(claims.given_name);

          if (claims.preferred_username) email = String(claims.preferred_username);
          else if (claims.email) email = String(claims.email);
          else if (claims.upn) email = String(claims.upn);
          else if (claims.unique_name) email = String(claims.unique_name);

          if (claims.tid) tenantId = String(claims.tid);

          if (!email) email = "conta.microsoft@azure.com";
          if (!name) name = email.split("@")[0] || "Usuário Microsoft";

          newAcc = {
            id: `acc-${Date.now()}`,
            email: email,
            name: name,
            tenant_id: tenantId,
            source: "device_login",
            token: rawToken,
            access_token: rawToken,
            refresh_token: data.refresh_token || "",
            expires_at: Math.floor(Date.now() / 1000) + (Number(data.expires_in) || 3600)
          };
        }

        const idx = state.config.accounts.findIndex(
          a => (a.email && newAcc.email && a.email.toLowerCase() === newAcc.email.toLowerCase()) || a.id === newAcc.id
        );
        if (idx >= 0) {
          state.config.accounts[idx] = newAcc;
        } else {
          state.config.accounts.push(newAcc);
        }

        state.config.active_account_id = newAcc.id;
        state.config.auth_method = "user_account";
        if (!state.config.tenant_id && newAcc.tenant_id && newAcc.tenant_id !== "common") {
          state.config.tenant_id = newAcc.tenant_id;
        }

        state.deviceLogin.completed = true;
        state.deviceLogin.active = false;
        state.deviceLogin.polling = false;
        stopPollingTimer();

        state.message = {
          type: "success",
          text: `Conta Microsoft '${newAcc.name}' (${newAcc.email}) conectada com sucesso! Buscando seus Key Vaults...`
        };

        renderUI();
        await persistConfig();

        await discoverUserVaults(true);
        if (state.config.vault_name || state.config.vault_url) {
          await performTestConnection(true);
        }
        return;
      }

      if (data.error === "authorization_pending" || data.error === "slow_down" || data.status === "pending") {
        if (!isAutomatic) {
          state.message = {
            type: "info",
            text: `Aguardando confirmação na janela da Microsoft... Digite o código '${state.deviceLogin.user_code}' e aprove o acesso.`
          };
          renderUI();
        }
        return;
      }

      if (data.error || data.status === "error") {
        stopPollingTimer();
        let errMsg = data.desc || data.error_description || data.error;
        if (data.error === "invalid_grant" || data.error === "expired_token") {
          state.deviceLogin.active = false;
          errMsg = "O código anterior expirou ou já foi utilizado. Clique em 'Conectar Conta Microsoft' para gerar um novo código.";
        } else if (data.error === "authorization_declined") {
          state.deviceLogin.active = false;
          errMsg = "A autorização foi recusada na janela da Microsoft.";
        }
        state.message = {
          type: "error",
          text: errMsg
        };
        renderUI();
      }
    }
  } catch (err) {
    self.kraken.log("Error in performPollCheck: " + (err.message || err));
    if (!isAutomatic) {
      state.message = { type: "error", text: "Erro ao verificar status: " + (err.message || err) };
      renderUI();
    }
  } finally {
    state.deviceLogin.isChecking = false;
    state.deviceLogin.polling = false;
    if (!isAutomatic && !state.deviceLogin.completed) {
      renderUI();
    }
  }
}

// -------------------------------------------------------------
// Render Dispatcher
// -------------------------------------------------------------

function renderUI() {
  const surface = self.kraken.surface || "page";

  if (surface === "widget") {
    renderDashboardWidget();
    return;
  }

  if (surface === "tab") {
    renderServerTab();
    return;
  }

  renderFullPage();
}

// -------------------------------------------------------------
// 1. Dashboard Widget Surface
// -------------------------------------------------------------
function renderDashboardWidget() {
  const activeAcc = getActiveAccount();
  const operable = isKeyVaultOperable();
  const boundCount = operable ? Object.keys(state.config.server_bindings || {}).length : 0;

  self.kraken.render({
    type: "Card",
    title: "Azure Key Vault — Credenciais JIT",
    description: "Cofre centralizado de senhas de servidores (zero persistência local)",
    children: [
      {
        type: "Grid",
        cols: 2,
        children: [
          {
            type: "StatCard",
            title: "Conta Conectada",
            value: activeAcc ? activeAcc.name : "Desconectado",
            variant: activeAcc ? "running" : "pending",
            description: activeAcc ? activeAcc.email : "Nenhuma conta vinculada"
          },
          {
            type: "StatCard",
            title: "Servidores Protegidos",
            value: String(boundCount),
            variant: boundCount > 0 ? "running" : "outline",
            description: operable && state.config.auto_convention ? "Convenção automática ativa" : "Apenas bind manual"
          }
        ]
      },
      {
        type: "FieldGroup",
        children: [
          {
            type: "Button",
            id: "btn-widget-test-conn",
            title: state.loading ? "Testando..." : "Testar Conexão",
            variant: "outline",
            disabled: state.loading || !operable
          }
        ]
      }
    ]
  });
}

// -------------------------------------------------------------
// 2. Server Details Tab Surface (Individual Server Bind)
// -------------------------------------------------------------
function renderServerTab() {
  const ctx = self.kraken.params || self.kraken.context || {};
  const serverId = String(ctx.server_id || ctx.id || "srv-01");
  const serverName = ctx.server_name || ctx.name || "Servidor Alvo";
  const hostname = extractHostname(ctx.host_url || ctx.hostname, serverName);
  const activeAcc = getActiveAccount();
  const operable = isKeyVaultOperable();

  const currentBinding = (operable && state.config.server_bindings) ? state.config.server_bindings[serverId] : "";
  const conventionSecret = state.config.naming_pattern
    ? state.config.naming_pattern.replace("{hostname}", hostname.toLowerCase().replace(/\./g, "-")).replace("{server_id}", serverId)
    : `srv-${hostname.toLowerCase().replace(/\./g, "-")}-pwd`;

  const secretOptions = [
    { label: "-- Sem Vínculo Manual (Usar Convenção Padrão) --", value: "" },
    ...state.secrets.map(s => ({ label: `${s.name} ${s.enabled ? "" : "(desativado)"}`, value: s.name }))
  ];
  if (currentBinding && !secretOptions.some(o => o.value === currentBinding)) {
    secretOptions.push({ label: `${currentBinding} (vinculado)`, value: currentBinding });
  }

  self.kraken.render({
    type: "Page",
    title: `Azure Key Vault — ${serverName}`,
    description: "Gerenciamento de segredo e autenticação segura sem armazenamento local da senha.",
    children: [
      ...(state.message.text ? [{
        type: "Alert",
        title: state.message.type === "success" ? "Sucesso" : "Atenção",
        description: state.message.text,
        variant: state.message.type === "success" ? "success" : "destructive"
      }] : []),
      {
        type: "Card",
        title: "Segurança de Acesso SSH",
        description: "As credenciais são buscadas Just-In-Time na Azure e descartadas da memória após o handshake.",
        children: [
          {
            type: "Alert",
            title: "Zero Local Database Persistence",
            description: "A senha deste servidor NUNCA é salva em bancos locais do Kraken. A consulta é efêmera via Azure Key Vault.",
            variant: "info"
          },
          {
            type: "FieldGroup",
            children: [
              {
                type: "Badge",
                label: activeAcc ? `Conta: ${activeAcc.email}` : "Sem conta Microsoft conectada",
                variant: activeAcc ? "running" : "error"
              },
              {
                type: "Badge",
                label: !operable
                  ? "Sem Proteção (Vault Desconectado)"
                  : (currentBinding ? `Vínculo Manual: ${currentBinding}` : `Convenção Ativa: ${conventionSecret}`),
                variant: operable ? "running" : "pending"
              },
              {
                type: "Badge",
                label: `Vault: ${state.config.vault_name || "Não configurado"}`,
                variant: operable ? "running" : "pending"
              }
            ]
          },
          {
            type: "Form",
            id: "form-server-binding",
            actionId: "btn-save-server-binding",
            children: [
              {
                type: "Select",
                id: "server_tab_secret_name",
                label: "Selecionar Secret Existente no Key Vault",
                description: "Escolha um secret listado no cofre ou informe o nome manualmente abaixo.",
                value: currentBinding || "",
                options: secretOptions,
                disabled: !operable
              },
              {
                type: "Input",
                id: "server_tab_custom_secret",
                label: "Ou Digite o Nome do Secret no Azure Key Vault",
                placeholder: conventionSecret,
                value: currentBinding || "",
                disabled: !operable
              },
              {
                type: "FieldGroup",
                children: [
                  {
                    type: "Button",
                    id: "btn-save-server-binding",
                    title: state.saving ? "Salvando..." : "Salvar Vínculo do Servidor",
                    variant: "default",
                    disabled: state.saving || !operable
                  },
                  {
                    type: "Button",
                    id: "btn-refresh-tab-secrets",
                    title: "Recarregar Secrets do Vault",
                    variant: "outline",
                    disabled: state.loading || !operable
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  });
}

// -------------------------------------------------------------
// Interactive 5-Column Single-Line Secrets Table (CustomShadowHtml)
// -------------------------------------------------------------

function renderSecretsTableHtml(pageSecrets) {
  const clickHandler = `(async function(e) {
  var btn = e.target.closest("button[data-action]");
  if (!btn) return;
  var action = btn.getAttribute("data-action");
  var secretName = btn.getAttribute("data-secret-name");
  if (!action || !secretName) return;

  var tr = btn.closest("tr");
  if (!tr) return;
  var input = tr.querySelector("input[data-secret-name]");
  if (!input) return;

  var showBtn = tr.querySelector("button[data-action=\x27toggle-show\x27]");
  var copyBtn = tr.querySelector("button[data-action=\x27copy\x27]");

  async function fetchSecretValue() {
    var token = (window.localStorage && (window.localStorage.getItem("kraken_auth_token") || window.localStorage.getItem("token") || window.localStorage.getItem("auth_token"))) || "";
    var port8080Url = window.location.protocol + "//" + window.location.hostname + ":8080/api/plugins/com.kraken.azure-keyvault/call";
    var localUrl = window.location.origin + "/api/plugins/com.kraken.azure-keyvault/call";
    var endpoints = [port8080Url, localUrl];

    var attempt = 0;
    while (attempt !== 4) {
      attempt++;
      for (var u = 0; u !== endpoints.length; u++) {
        var url = endpoints[u];
        try {
          var resp = await fetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(token ? { "Authorization": "Bearer " + token } : {})
            },
            body: JSON.stringify({
              action: "get_secret",
              payload: { secret_name: secretName }
            })
          });

          var text = await resp.text();
          var data = null;
          try {
            data = JSON.parse(text);
          } catch (e) {
            continue;
          }

          var resData = data && data.result ? data.result : data;
          if (resData && resData.data && !resData.data.error) {
            var val = resData.data.value !== undefined ? resData.data.value : (resData.data.secret || "");
            return val;
          }
          var errStr = String(data ? (data.error || resData.error || (resData.data && resData.data.error && resData.data.error.message) || "") : "");
          if (errStr.indexOf("not instantiated") !== -1 || errStr.indexOf("failed to instantiate") !== -1) {
            break;
          }
          if (u === endpoints.length - 1 && attempt === 4) {
            throw new Error(errStr || "Falha ao buscar secret");
          }
        } catch (err) {
          if (u === endpoints.length - 1 && attempt === 4) {
            throw err;
          }
        }
      }
      await new Promise(function(resolve) { setTimeout(resolve, 200 * attempt); });
    }
    return "";
  }

  if (action === "toggle-show") {
    var currentVal = input.getAttribute("data-secret-val");
    if (input.type === "text") {
      input.type = "password";
      input.value = "••••••••••••••••";
      btn.innerText = "👁️";
      btn.title = "Mostrar segredo";
    } else {
      if (currentVal !== null && currentVal !== undefined) {
        input.type = "text";
        input.value = currentVal;
        btn.innerText = "🙈";
        btn.title = "Ocultar segredo";
      } else {
        var oldText = btn.innerText;
        btn.innerText = "⏳";
        btn.disabled = true;
        try {
          var val = await fetchSecretValue();
          input.setAttribute("data-secret-val", val);
          input.type = "text";
          input.value = val;
          btn.innerText = "🙈";
          btn.title = "Ocultar segredo";
        } catch (err) {
          alert("Erro ao buscar secret " + secretName + ": " + (err.message || err));
          btn.innerText = oldText;
        } finally {
          btn.disabled = false;
        }
      }
    }
  } else if (action === "copy") {
    var valToCopy = input.getAttribute("data-secret-val");
    if (valToCopy === null || valToCopy === undefined) {
      var oldCopyText = btn.innerText;
      btn.innerText = "⏳";
      btn.disabled = true;
      try {
        valToCopy = await fetchSecretValue();
        input.setAttribute("data-secret-val", valToCopy);
      } catch (err) {
        alert("Erro ao buscar secret " + secretName + " para cópia: " + (err.message || err));
        btn.innerText = oldCopyText;
        btn.disabled = false;
        return;
      }
      btn.disabled = false;
    }

    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(valToCopy);
      } else {
        input.type = "text";
        input.value = valToCopy;
        input.select();
        document.execCommand("copy");
        input.type = "password";
        input.value = "••••••••••••••••";
      }
      btn.innerText = "✅";
      setTimeout(function() { btn.innerText = "📋"; }, 3000);

      setTimeout(function() {
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText("");
          }
        } catch (_) {}
      }, 30000);
    } catch (clipErr) {
      alert("Não foi possível copiar automaticamente para o clipboard. Revelando campo para cópia manual.");
      input.type = "text";
      input.value = valToCopy;
      if (showBtn) showBtn.innerText = "🙈";
    }
  }
})(event)`.replace(/"/g, "&quot;");

  let rows = "";
  for (const s of pageSecrets) {
    const isEnabled = s.enabled !== false;
    const statusDot = isEnabled ? "🟢" : "🔴";
    const statusTitle = isEnabled ? "Ativo no Azure Key Vault" : "Desativado/Inativo no Azure Key Vault";
    const tagsArr = s.tags && typeof s.tags === "object" ? Object.entries(s.tags) : [];
    const tagsHtml = tagsArr.length > 0 
      ? `<div style="font-size: 11px; color: #94a3b8; margin-top: 2px; white-space: normal;">${tagsArr.map(([k, v]) => `<span style="background: rgba(148,163,184,0.12); padding: 1px 5px; border-radius: 3px; margin-right: 4px; display: inline-block;">#${escapeHtml(k)}: ${escapeHtml(v)}</span>`).join("")}</div>`
      : "";

    rows += `
      <tr style="border-bottom: 1px solid rgba(255,255,255,0.06); transition: background 0.15s;" onmouseover="this.style.background='rgba(255,255,255,0.03)'" onmouseout="this.style.background='transparent'">
        <td style="width: 36px; text-align: center; padding: 10px 8px; vertical-align: middle;">
          <span title="${statusTitle}" style="font-size: 14px; cursor: help; user-select: none;">${statusDot}</span>
        </td>
        <td style="padding: 10px 12px; vertical-align: middle;">
          <div style="font-weight: 600; font-size: 13px; color: #f1f5f9; font-family: monospace; letter-spacing: 0.3px;">${escapeHtml(s.name)}</div>
          ${tagsHtml}
        </td>
        <td style="width: 210px; padding: 10px 8px; vertical-align: middle;">
          <input type="password" 
                 readonly 
                 value="••••••••••••••••" 
                 data-secret-name="${escapeHtml(s.name)}"
                 oncopy="setTimeout(function(){ try { navigator.clipboard.writeText(''); } catch(e){} }, 30000);"
                 style="width: 100%; max-width: 200px; background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 6px; padding: 5px 10px; color: #f8fafc; font-family: monospace; font-size: 12px; letter-spacing: 1.5px; outline: none; box-sizing: border-box;" 
                 title="Valor do secret (clique em 👁️ para mostrar ou 📋 para copiar)" />
        </td>
        <td style="width: 46px; text-align: right; padding: 10px 6px; vertical-align: middle;">
          <button type="button" 
                  data-action="toggle-show" 
                  data-secret-name="${escapeHtml(s.name)}" 
                  title="Mostrar / Ocultar secret" 
                  style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; width: 34px; height: 32px; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; font-size: 14px; transition: all 0.15s;" 
                  onmouseover="this.style.background='rgba(255,255,255,0.12)'" 
                  onmouseout="this.style.background='rgba(255,255,255,0.06)'">👁️</button>
        </td>
        <td style="width: 46px; text-align: right; padding: 10px 8px 10px 4px; vertical-align: middle;">
          <button type="button" 
                  data-action="copy" 
                  data-secret-name="${escapeHtml(s.name)}" 
                  title="Copiar secret para a área de transferência (auto-limpa em 30s)" 
                  style="background: #0284c7; border: none; border-radius: 6px; width: 34px; height: 32px; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; font-size: 14px; transition: all 0.15s;" 
                  onmouseover="this.style.background='#0369a1'" 
                  onmouseout="this.style.background='#0284c7'">📋</button>
        </td>
      </tr>
    `;
  }

  return `
    <div onclick="${clickHandler}" style="width: 100%; overflow-x: auto; background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(51, 65, 85, 0.6); border-radius: 8px;">
      <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; color: #cbd5e1;">
        <thead>
          <tr style="background: rgba(15, 23, 42, 0.9); border-bottom: 1px solid rgba(51, 65, 85, 0.8); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8;">
            <th style="width: 36px; padding: 10px 8px; text-align: center;">Status</th>
            <th style="padding: 10px 12px;">Nome do Segredo</th>
            <th style="width: 210px; padding: 10px 8px;">Valor Mascarado</th>
            <th style="width: 46px; padding: 10px 6px; text-align: right;">Ver</th>
            <th style="width: 46px; padding: 10px 10px 10px 4px; text-align: right;">Copiar</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
  `;
}

// -------------------------------------------------------------
// 3. Full Page Surface (Main Plugin Management Page)
// -------------------------------------------------------------
function renderFullPage() {
  const activeAcc = getActiveAccount();
  const hasAccounts = state.config.accounts && state.config.accounts.length > 0;
  const operable = isKeyVaultOperable();

  const tableRows = state.servers.map(srv => {
    const manualSecret = (operable && state.config.server_bindings)
      ? (state.config.server_bindings[srv.id] || state.config.server_bindings[srv.hostname])
      : "";

    const conventionSecret = state.config.naming_pattern
      ? state.config.naming_pattern.replace("{hostname}", srv.hostname.toLowerCase().replace(/\./g, "-")).replace("{server_id}", srv.id)
      : `srv-${srv.hostname.toLowerCase().replace(/\./g, "-")}-pwd`;

    return {
      server_name: `${srv.name} (#${srv.id})`,
      hostname: srv.hostname,
      protection_mode: !operable
        ? "Sem Proteção (Desconectado)"
        : (manualSecret ? "Bind Manual Explícito" : (state.config.auto_convention ? "Convenção Automática" : "Sem Vínculo")),
      resolved_secret: operable ? (manualSecret || (state.config.auto_convention ? conventionSecret : "—")) : "—",
      status: operable && (manualSecret || state.config.auto_convention) ? "Protegido JIT (Zero DB)" : "Pendente"
    };
  });

  const accountRows = (state.config.accounts || []).map(acc => ({
    name: acc.name || "Usuário Microsoft",
    email: acc.email || "—",
    source: acc.source === "kraken_session" ? "Sessão Kraken (SSO)" : "Logon Microsoft Oficial",
    tenant: acc.tenant_id || "common",
    status: acc.id === state.config.active_account_id ? "✅ Ativa (Principal)" : "Conectada"
  }));

  const serverOptions = state.servers.map(srv => ({
    label: `${srv.name} (${srv.hostname})`,
    value: String(srv.id)
  }));

  const currentSelectedSrvId = state.bindForm.selected_server_id || (state.servers[0] ? String(state.servers[0].id) : "");
  const currentBoundSecret = (operable && state.config.server_bindings && state.config.server_bindings[currentSelectedSrvId]) || "";

  const secretSelectOptions = [
    { label: "-- Digite abaixo ou selecione um Secret do Cofre --", value: "" },
    ...state.secrets.map(s => ({ label: `${s.name} ${s.enabled === false ? "(desativado)" : ""}`, value: s.name }))
  ];

  const vaultSelectOptions = [
    { label: "-- Selecione um Key Vault detectado ou digite abaixo --", value: "" },
    ...state.discoveredVaults.map(v => ({
      label: `🔑 ${v.name} (${v.location || "Azure"})`,
      value: v.name
    }))
  ];

  const searchQuery = (state.secretsTable?.searchQuery || "").trim().toLowerCase();
  const allSecrets = state.secrets || [];
  const filteredSecrets = allSecrets.filter(s => {
    if (!searchQuery) return true;
    if (s.name && s.name.toLowerCase().includes(searchQuery)) return true;
    if (s.tags && typeof s.tags === "object") {
      for (const [k, v] of Object.entries(s.tags)) {
        if (k.toLowerCase().includes(searchQuery) || String(v).toLowerCase().includes(searchQuery)) {
          return true;
        }
      }
    }
    return false;
  });

  const pageSize = Number(state.secretsTable?.pageSize) || 10;
  const totalFiltered = filteredSecrets.length;
  const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize));
  const currentPage = Math.min(Math.max(1, state.secretsTable?.currentPage || 1), totalPages);
  const startIndex = (currentPage - 1) * pageSize;
  const pageSecrets = filteredSecrets.slice(startIndex, startIndex + pageSize);

  self.kraken.render({
    type: "Page",
    title: "Azure Key Vault Integration",
    description: "Gerenciamento seguro de credenciais de servidores em nuvem com resolução Just-in-Time (JIT) e zero armazenamento local.",
    children: [
      // Notification Alert
      ...(state.message.text ? [{
        type: "Alert",
        title: state.message.type === "success" ? "Operação Concluída" : (state.message.type === "info" ? "Informação" : "Aviso"),
        description: state.message.text,
        variant: state.message.type === "success" ? "success" : (state.message.type === "info" ? "info" : "destructive")
      }] : []),

      // Test Connection Result Alert
      ...(state.testResult ? [{
        type: "Alert",
        title: state.testResult.success ? "Conexão OK com Azure Key Vault" : "Falha na Conexão com Key Vault",
        description: state.testResult.message,
        variant: state.testResult.success ? "success" : "destructive"
      }] : []),

      // -------------------------------------------------------------
      // Section A: Microsoft Account Authentication Card
      // -------------------------------------------------------------
      {
        type: "Card",
        title: "Autenticação com Conta Microsoft",
        description: "Conecte sua conta Microsoft corporativa (Entra ID) ou pessoal para acessar segredos no Azure Key Vault.",
        children: [
          // Status Callout: Connected Account vs Not Connected
          ...(activeAcc ? [{
            type: "Alert",
            title: `Conectado à Microsoft como ${activeAcc.name} (${activeAcc.email})`,
            description: `Autenticação OAuth2 ativa (Tenant: ${activeAcc.tenant_id || "common"}). As senhas dos servidores serão consultadas sob demanda (Just-in-Time) usando esta conta, sem armazenar senhas no banco local do Kraken.`,
            variant: "success"
          }] : [{
            type: "Alert",
            title: "Nenhuma Conta Microsoft Conectada",
            description: "Você não possui uma conta Microsoft conectada no momento. Clique em 'Conectar Conta Microsoft' abaixo para autenticar na janela oficial da Microsoft.",
            variant: "info"
          }]),

          // Active Account Details Badges
          ...(activeAcc ? [{
            type: "FieldGroup",
            children: [
              {
                type: "Badge",
                label: `Conta Ativa: ${activeAcc.name} (${activeAcc.email})`,
                variant: "running"
              },
              {
                type: "Badge",
                label: `Origem: ${activeAcc.source === "kraken_session" ? "Sessão Kraken (SSO)" : "Logon Oficial Microsoft"}`,
                variant: "outline"
              },
              {
                type: "Badge",
                label: `Tenant ID: ${activeAcc.tenant_id || "common"}`,
                variant: "outline"
              }
            ]
          }] : []),

          // Device Code Active Card
          ...(state.deviceLogin.active ? [{
            type: "Card",
            title: "🔑 Autorização na Janela Oficial da Microsoft",
            description: "Siga os 2 passos abaixo. Assim que você aprovar na janela da Microsoft, o Kraken atualizará esta tela automaticamente:",
            children: [
              {
                type: "CustomShadowHtml",
                html: `
                  <div style="background: rgba(0, 120, 212, 0.08); border: 2px dashed #0078D4; border-radius: 8px; padding: 20px 24px; margin: 10px 0; text-align: center;">
                    <div style="font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #aaa; margin-bottom: 6px;">
                      Passo 1: Código de Autorização
                    </div>
                    <div style="font-size: 34px; font-weight: 800; font-family: monospace; letter-spacing: 5px; color: #38bdf8; user-select: all; margin: 6px 0 16px 0;">
                      ${state.deviceLogin.user_code}
                    </div>
                    <div style="font-size: 14px; margin-bottom: 16px; color: #eee;">
                      Passo 2: Clique no botão abaixo para abrir a janela da Microsoft (o código já é copiado automaticamente):
                    </div>
                    <a href="https://microsoft.com/devicelogin" 
                       target="_blank" 
                       rel="noopener noreferrer"
                       onclick="try { navigator.clipboard.writeText('${state.deviceLogin.user_code}'); } catch(e) {}"
                       style="display: inline-flex; align-items: center; gap: 10px; background: #0078D4; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 700; font-size: 15px; box-shadow: 0 4px 12px rgba(0,120,212,0.4);">
                      <svg width="20" height="20" viewBox="0 0 21 21" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <rect x="1" y="1" width="9" height="9" fill="#F25022"/>
                        <rect x="11" y="1" width="9" height="9" fill="#7FBA00"/>
                        <rect x="1" y="11" width="9" height="9" fill="#00A4EF"/>
                        <rect x="11" y="11" width="9" height="9" fill="#FFB900"/>
                      </svg>
                      <span>Copiar Código e Abrir Janela da Microsoft ↗</span>
                    </a>
                    <div style="font-size: 12px; color: #38bdf8; margin-top: 14px;">
                      🔄 Monitorando confirmação automaticamente em segundo plano...
                    </div>
                  </div>
                `
              },
              {
                type: "FieldGroup",
                children: [
                  {
                    type: "Button",
                    id: "btn-check-device-login",
                    title: state.deviceLogin.polling ? "Verificando na Microsoft..." : "Já Concluí na Janela (Verificar Agora)",
                    variant: "default",
                    disabled: state.deviceLogin.polling
                  },
                  {
                    type: "Button",
                    id: "btn-cancel-device-login",
                    title: "Cancelar",
                    variant: "outline"
                  }
                ]
              }
            ]
          }] : [
            {
              type: "FieldGroup",
              children: [
                {
                  type: "Button",
                  id: "btn-connect-microsoft-account",
                  title: state.loading ? "Gerando Código Seguro..." : (hasAccounts ? "➕ Adicionar Outra Conta Microsoft (Janela)" : "🔑 Conectar Conta Microsoft (Abre Janela)"),
                  variant: "default",
                  disabled: state.loading
                },
                ...(hasAccounts && state.config.accounts.length > 1 ? [{
                  type: "Button",
                  id: "btn-switch-account",
                  title: "Alternar Conta Ativa",
                  variant: "outline"
                }] : []),
                ...(hasAccounts ? [{
                  type: "Button",
                  id: "btn-remove-account",
                  title: "Desconectar Conta Microsoft",
                  variant: "destructive"
                }] : []),
                {
                  type: "Button",
                  id: "btn-clear-all-data",
                  title: "🧹 Limpar Todos os Dados e Desconectar",
                  variant: "outline"
                }
              ]
            }
          ]),

          // Connected Accounts Table
          ...(accountRows.length > 0 ? [{
            type: "Table",
            columns: [
              { key: "name", label: "Nome da Conta" },
              { key: "email", label: "E-mail / UPN" },
              { key: "source", label: "Método" },
              { key: "tenant", label: "Tenant ID" },
              { key: "status", label: "Status" }
            ],
            rows: accountRows
          }] : [])
        ]
      },

      // -------------------------------------------------------------
      // Metrics Overview Grid
      // -------------------------------------------------------------
      {
        type: "Grid",
        cols: 3,
        children: [
          {
            type: "StatCard",
            title: "Cofre Azure",
            value: operable ? (state.config.vault_name || "Conectado") : (state.config.vault_name ? `${state.config.vault_name} (Desconectado)` : "Pendente"),
            variant: operable ? "running" : "pending",
            description: operable ? `${state.config.vault_name}.vault.azure.net` : "Aguardando autenticação para conectar"
          },
          {
            type: "StatCard",
            title: "Conta Autenticada",
            value: activeAcc ? activeAcc.name : (state.config.auth_method === "service_principal" ? "Service Principal" : "Nenhuma"),
            variant: activeAcc || state.config.auth_method === "service_principal" ? "running" : "pending",
            description: activeAcc ? activeAcc.email : "Aguardando logon Microsoft"
          },
          {
            type: "StatCard",
            title: "Secrets no Key Vault",
            value: String(operable ? state.secrets.length : 0),
            variant: operable && state.secrets.length > 0 ? "running" : "outline",
            description: operable ? `${Object.keys(state.config.server_bindings || {}).length} binds manuais ativos` : "Nenhum secret disponível"
          }
        ]
      },

      // -------------------------------------------------------------
      // Section B: Key Vault Settings Card (With Auto-Discovery)
      // -------------------------------------------------------------
      {
        type: "Card",
        title: "Configuração do Cofre (Azure Key Vault)",
        description: "Selecione um dos cofres encontrados automaticamente na sua conta Microsoft ou digite o nome manualmente.",
        children: [
          {
            type: "Select",
            id: "cfg_auth_method",
            label: "Método de Autenticação",
            description: "Selecione como o Kraken deve se autenticar no Azure Key Vault.",
            value: state.config.auth_method,
            options: [
              { label: "Conta Microsoft Conectada (OAuth2 / Entra ID - Recomendado)", value: "user_account" },
              { label: "Service Principal (Client ID + Client Secret)", value: "service_principal" },
              { label: "Azure Managed Identity (IMDS 169.254.169.254)", value: "managed_identity" },
              { label: "Azure CLI Local (az account get-access-token)", value: "azure_cli" }
            ]
          },
          ...(state.discoveredVaults.length > 0 ? [
            {
              type: "Select",
              id: "cfg_discovered_vault_select",
              label: "Key Vaults Encontrados na sua Conta Microsoft",
              description: "Clique para escolher o cofre desejado automaticamente:",
              value: state.config.vault_name,
              options: vaultSelectOptions
            }
          ] : []),
          {
            type: "FieldGroup",
            children: [
              {
                type: "Input",
                id: "cfg_vault_name",
                label: "Nome do Key Vault (Vault Name)",
                placeholder: "ex: kv-infra-producao",
                value: state.config.vault_name,
                required: true
              },
              {
                type: "Input",
                id: "cfg_vault_url",
                label: "URL Completa do Vault (Opcional)",
                placeholder: "https://kv-infra-producao.vault.azure.net",
                value: state.config.vault_url
              }
            ]
          },
          ...(state.config.auth_method === "service_principal" ? [
            {
              type: "FieldGroup",
              children: [
                {
                  type: "Input",
                  id: "cfg_tenant_id",
                  label: "Directory (Tenant) ID",
                  placeholder: "00000000-0000-0000-0000-000000000000",
                  value: state.config.tenant_id,
                  required: true
                },
                {
                  type: "Input",
                  id: "cfg_client_id",
                  label: "Application (Client) ID",
                  placeholder: "00000000-0000-0000-0000-000000000000",
                  value: state.config.client_id,
                  required: true
                }
              ]
            },
            {
              type: "Input",
              id: "cfg_client_secret",
              label: "Client Secret",
              placeholder: state.config.client_secret ? "••••••••••••••••" : "Insira o Client Secret gerado no Entra ID",
              inputType: "password",
              value: state.config.client_secret
            }
          ] : []),
          {
            type: "FieldGroup",
            children: [
              {
                type: "Button",
                id: "btn-discover-vaults",
                title: state.discoveringVaults ? "Localizando na Azure..." : "🔍 Buscar Meus Key Vaults na Azure",
                variant: "outline",
                disabled: state.discoveringVaults || !activeAcc
              },
              {
                type: "Button",
                id: "btn-save-config",
                title: state.saving ? "Salvando..." : "Salvar Configuração do Vault",
                variant: "default",
                disabled: state.saving
              },
              {
                type: "Button",
                id: "btn-test-connection",
                title: state.loading ? "Consultando Azure..." : "Testar Conexão & Listar Secrets",
                variant: "outline",
                disabled: state.loading || !operable
              }
            ]
          }
        ]
      },

      // -------------------------------------------------------------
      // Section C: Azure Key Vault Secrets (Paginated Rows with Inline Mostrar and Copiar)
      // -------------------------------------------------------------
      ...(operable ? [{
        type: "Card",
        title: "Segredos Armazenados no Azure Key Vault",
        description: `Listagem completa dos segredos disponíveis no cofre '${state.config.vault_name || state.config.vault_url}'. Clique em Mostrar para revelar ou em Copiar para enviar à área de transferência com auto-limpeza em 30s.`,
        children: [
          // Filter Row & Page Size & Refresh
          {
            type: "FieldGroup",
            children: [
              {
                type: "Input",
                id: "secrets_search_input",
                label: "Filtrar Segredos (Busca Global)",
                placeholder: "Filtrar por nome ou tag em todos os segredos...",
                value: state.secretsTable.searchQuery,
                description: `Buscando entre o total de ${allSecrets.length} segredo(s) carregados do Azure Key Vault.`
              },
              {
                type: "Select",
                id: "secrets_page_size",
                label: "Segredos por Página",
                value: String(pageSize),
                options: [
                  { label: "10 por página", value: "10" },
                  { label: "25 por página", value: "25" },
                  { label: "50 por página", value: "50" },
                  { label: "100 por página", value: "100" }
                ],
                description: "Quantidade de registros visíveis por página."
              },
              {
                type: "Button",
                id: "btn-sync-secrets-all",
                title: state.loading ? "Sincronizando..." : "🔄 Atualizar Todos os Segredos",
                variant: "outline",
                disabled: state.loading
              }
            ]
          },

          // Active Clipboard Auto-clear Countdown Banner
          ...(state.clipboardNotice ? [{
            type: "Alert",
            title: "📋 Segredo Copiado para a Área de Transferência",
            description: `O segredo '${state.clipboardNotice.name}' foi copiado com sucesso! Por segurança, a área de transferência será limpa automaticamente em ${state.clipboardNotice.remainingSec}s.`,
            variant: "success"
          }] : []),

          // Pagination Controls
          ...(totalFiltered > 0 ? [{
            type: "FieldGroup",
            children: [
              {
                type: "Button",
                id: "btn-secrets-first-page",
                title: "⏮ Primeira",
                variant: "outline",
                disabled: currentPage <= 1
              },
              {
                type: "Button",
                id: "btn-secrets-prev-page",
                title: "◀ Anterior",
                variant: "outline",
                disabled: currentPage <= 1
              },
              {
                type: "Button",
                id: "btn-secrets-page-indicator",
                title: `Página ${currentPage} de ${totalPages} (Exibindo ${pageSecrets.length} de ${totalFiltered} encontrados)`,
                variant: "secondary",
                disabled: true
              },
              {
                type: "Button",
                id: "btn-secrets-next-page",
                title: "Próxima ▶",
                variant: "outline",
                disabled: currentPage >= totalPages
              },
              {
                type: "Button",
                id: "btn-secrets-last-page",
                title: "Última ⏭",
                variant: "outline",
                disabled: currentPage >= totalPages
              }
            ]
          }] : []),

          // Secrets Table (CustomShadowHtml): strictly 1-line 5-column responsive table
          // Col 1: Status dot (🟢 / 🔴)
          // Col 2: Secret Name + Tags
          // Col 3: Compact Masked Input (••••••••••••••••)
          // Col 4: Show / Hide Eye Button (👁️ / 🙈)
          // Col 5: Copy Button (📋 / ✅)
          ...(pageSecrets.length > 0 ? [{
            type: "CustomShadowHtml",
            html: renderSecretsTableHtml(pageSecrets)
          }] : [{
            type: "Alert",
            title: allSecrets.length === 0 ? "Nenhum segredo carregado" : "Nenhum segredo corresponde ao filtro",
            description: allSecrets.length === 0
              ? "Clique em 'Testar Conexão & Listar Secrets' acima para consultar os segredos do cofre."
              : `Nenhum dos ${allSecrets.length} segredos encontrados corresponde ao termo pesquisado.`,
            variant: "info"
          }])
        ]
      }] : []),

      // -------------------------------------------------------------
      // Section D: Bind Server to Azure Key Vault Secret (Main Page)
      // -------------------------------------------------------------
      {
        type: "Card",
        title: "Vincular Servidor Cadastrado a um Secret do Azure Key Vault (Bind JIT)",
        description: "Associe um servidor já cadastrado no Kraken a um secret do Azure Key Vault. A senha nunca fica salva no banco local nem residente em memória.",
        children: [
          {
            type: "FieldGroup",
            children: [
              {
                type: "Select",
                id: "bind_server_id",
                label: "Servidor Cadastrado no Kraken",
                description: "Escolha o servidor que terá a senha resolvida via Azure Key Vault.",
                value: currentSelectedSrvId,
                options: serverOptions,
                disabled: !operable
              },
              ...(state.secrets.length > 0 ? [{
                type: "Select",
                id: "bind_secret_select",
                label: "Secrets Encontrados no Cofre",
                description: "Selecione um secret existente no cofre para preencher automaticamente.",
                value: currentBoundSecret,
                options: secretSelectOptions,
                disabled: !operable
              }] : [])
            ]
          },
          {
            type: "FieldGroup",
            children: [
              {
                type: "Input",
                id: "bind_secret_name",
                label: "Nome do Secret no Azure Key Vault",
                placeholder: "ex: srv-10-4-83-8-pwd",
                value: state.bindForm.secret_name || currentBoundSecret,
                description: "Nome do secret no Azure Key Vault que contém a senha SSH ou chave privada deste servidor.",
                disabled: !operable
              },
              {
                type: "Input",
                id: "bind_new_secret_value",
                label: "Criar/Atualizar Valor da Senha no Azure KV (Opcional)",
                placeholder: "Deixe em branco se o secret já existir no Azure Key Vault",
                inputType: "password",
                value: "",
                description: "Se preenchido, envia a senha diretamente para o Azure Key Vault e descarta da memória imediatamente.",
                disabled: !operable
              }
            ]
          },
          {
            type: "FieldGroup",
            children: [
              {
                type: "Button",
                id: "btn-bind-server-secret",
                title: state.saving ? "Vinculando..." : "Salvar Bind (Servidor ↔ Secret Azure KV)",
                variant: "default",
                disabled: state.saving || state.servers.length === 0 || !operable
              },
              {
                type: "Button",
                id: "btn-test-jit-resolve",
                title: state.loading ? "Resolvendo JIT..." : "Testar Resolução JIT Efêmera",
                variant: "outline",
                disabled: state.loading || !operable
              },
              ...(currentBoundSecret ? [{
                type: "Button",
                id: "btn-unbind-server-secret",
                title: "Remover Bind Manual",
                variant: "destructive"
              }] : [])
            ]
          }
        ]
      },

      // -------------------------------------------------------------
      // Section D: Naming Convention & Auto Resolution
      // -------------------------------------------------------------
      {
        type: "Card",
        title: "Regras de Resolução e Convenção Automática",
        description: "Permite que servidores sem bind manual utilizem automaticamente segredos padronizados no Azure Key Vault.",
        children: [
          {
            type: "Checkbox",
            id: "cfg_auto_convention",
            label: "Habilitar convenção automática de nomenclatura para servidores sem vínculo explícito",
            checked: state.config.auto_convention
          },
          {
            type: "Input",
            id: "cfg_naming_pattern",
            label: "Padrão de Nome do Segredo no Key Vault",
            placeholder: "srv-{hostname}-pwd",
            value: state.config.naming_pattern,
            description: "Variáveis suportadas: {hostname} (IP/hostname com pontos trocados por hífens) e {server_id} (ID do servidor)."
          },
          {
            type: "FieldGroup",
            children: [
              {
                type: "Button",
                id: "btn-save-convention",
                title: "Salvar Regra de Convenção",
                variant: "secondary"
              }
            ]
          }
        ]
      },

      // -------------------------------------------------------------
      // Section E: Server Protection Status Table
      // -------------------------------------------------------------
      {
        type: "Card",
        title: "Servidores Cadastrados e Vínculos com Azure Key Vault",
        description: "Visão geral dos servidores registrados no Kraken e status de proteção Just-in-Time.",
        children: [
          {
            type: "Table",
            columns: [
              { key: "server_name", label: "Servidor no Kraken" },
              { key: "hostname", label: "Hostname / IP" },
              { key: "protection_mode", label: "Modo de Vínculo" },
              { key: "resolved_secret", label: "Secret no Azure KV" },
              { key: "status", label: "Proteção JIT" }
            ],
            rows: tableRows
          }
        ]
      }
    ]
  });
}

// -------------------------------------------------------------
// Web Worker Event Handlers
// -------------------------------------------------------------

// Start Connection Flow with Microsoft Official Device Login Window via Host Adapter
self.kraken.on("btn-connect-microsoft-account", async () => {
  stopPollingTimer();
  state.loading = true;
  state.message = { type: "", text: "" };
  renderUI();

  try {
    const res = await callBackendAction("auth.start_device_login", state.config);

    if (res && res.status === "success" && res.data && res.data.user_code) {
      state.deviceLogin = {
        active: true,
        user_code: res.data.user_code,
        device_code: res.data.device_code,
        verification_uri: "https://microsoft.com/devicelogin",
        message: res.data.message || "",
        polling: false,
        pollTimer: null,
        isChecking: false,
        completed: false
      };

      state.message = {
        type: "info",
        text: `Código ${res.data.user_code} gerado! Clique no botão azul abaixo para abrir a janela da Microsoft e colar o código.`
      };

      startPollingTimer();
    } else {
      const errText = res?.error || res?.data?.error_description || "Falha ao obter código de autenticação da Microsoft.";
      state.message = { type: "error", text: errText };
    }
  } catch (err) {
    state.message = {
      type: "error",
      text: "Erro ao iniciar autenticação: " + (err.message || err)
    };
  } finally {
    state.loading = false;
    renderUI();
  }
});

// Manual trigger for check Device Login completion
self.kraken.on("btn-check-device-login", async () => {
  await performPollCheck(false);
});

// Cancel Device Login
self.kraken.on("btn-cancel-device-login", () => {
  stopPollingTimer();
  state.deviceLogin.active = false;
  state.deviceLogin.completed = false;
  state.message = { type: "", text: "" };
  renderUI();
});

// Switch active account
self.kraken.on("btn-switch-account", async () => {
  if (state.config.accounts.length <= 1) return;

  const currentIdx = state.config.accounts.findIndex(a => a.id === state.config.active_account_id);
  const nextIdx = (currentIdx + 1) % state.config.accounts.length;
  state.config.active_account_id = state.config.accounts[nextIdx].id;

  state.message = {
    type: "success",
    text: `Conta Microsoft ativa alterada para: ${state.config.accounts[nextIdx].name} (${state.config.accounts[nextIdx].email})`
  };
  renderUI();
  await persistConfig();

  await discoverUserVaults(true);
  if (state.config.vault_name || state.config.vault_url) {
    await performTestConnection(true);
  }
});

// Disconnect Microsoft Account and clean credentials & secrets in memory and storage
self.kraken.on("btn-remove-account", async () => {
  const currentId = state.config.active_account_id;
  state.config.accounts = state.config.accounts.filter(a => a.id !== currentId);
  state.config.active_account_id = state.config.accounts.length > 0 ? state.config.accounts[0].id : "";

  // If no more accounts, clean vault secrets in memory and runtime
  if (state.config.accounts.length === 0) {
    state.secrets = [];
    state.discoveredVaults = [];
    state.testResult = null;
    state.config.vault_name = "";
    state.config.vault_url = "";
    state.config.tenant_id = "";
    state.config.server_bindings = {};
    state.config.auto_convention = false;
    state.bindForm.secret_name = "";
    state.revealedSecrets = {};
    state.secretVersions = {};
    state.copiedSecretName = "";
    if (state.copiedSecretTimeout) {
      clearTimeout(state.copiedSecretTimeout);
      state.copiedSecretTimeout = null;
    }
    if (state.clipboardTimerInterval) {
      clearInterval(state.clipboardTimerInterval);
      state.clipboardTimerInterval = null;
    }
    state.clipboardNotice = null;
    state.loadingSecretName = "";
    await idbClear();
  }

  state.message = {
    type: "info",
    text: "Conta Microsoft desconectada e dados do cofre limpos com sucesso."
  };
  renderUI();
  await persistConfig();
});

// Total Clean & Reset Button
self.kraken.on("btn-clear-all-data", async () => {
  state.config = {
    auth_method: "user_account",
    tenant_id: "",
    client_id: "",
    client_secret: "",
    vault_name: "",
    vault_url: "",
    auto_convention: false,
    naming_pattern: "srv-{hostname}-pwd",
    server_bindings: {},
    active_account_id: "",
    accounts: []
  };
  state.secrets = [];
  state.discoveredVaults = [];
  state.testResult = null;
  state.revealedSecrets = {};
  state.secretVersions = {};
  state.copiedSecretName = "";
  if (state.copiedSecretTimeout) {
    clearTimeout(state.copiedSecretTimeout);
    state.copiedSecretTimeout = null;
  }
  if (state.clipboardTimerInterval) {
    clearInterval(state.clipboardTimerInterval);
    state.clipboardTimerInterval = null;
  }
  state.clipboardNotice = null;
  state.loadingSecretName = "";
  state.bindForm = {
    selected_server_id: state.servers[0]?.id || "",
    secret_name: "",
    create_new_secretValue: ""
  };
  await idbClear();

  state.message = {
    type: "info",
    text: "Todos os dados locais e contas foram completamente limpos."
  };
  renderUI();
  await persistConfig();
});

// Synchronize inputs
self.kraken.on("cfg_auth_method", (payload) => {
  state.config.auth_method = payload.value;
  renderUI();
});

self.kraken.on("cfg_auto_convention", (payload) => {
  state.config.auto_convention = Boolean(payload.checked !== undefined ? payload.checked : payload.value);
  renderUI();
});

// Discovered vaults select handler
self.kraken.on("cfg_discovered_vault_select", async (payload) => {
  const selectedName = String(payload.value || "").trim();
  if (selectedName) {
    state.config.vault_name = selectedName;
    const found = state.discoveredVaults.find(v => v.name.toLowerCase() === selectedName.toLowerCase());
    if (found && found.url) {
      state.config.vault_url = found.url;
    } else {
      state.config.vault_url = `https://${selectedName}.vault.azure.net`;
    }
    await persistConfig();
    renderUI();
    await performTestConnection(false);
  }
});

self.kraken.on("btn-discover-vaults", async () => {
  await discoverUserVaults(false);
});

self.kraken.on("bind_server_id", (payload) => {
  const srvId = String(payload.value || "");
  state.bindForm.selected_server_id = srvId;
  state.bindForm.secret_name = (state.config.server_bindings && state.config.server_bindings[srvId]) || "";
  renderUI();
});

self.kraken.on("bind_secret_select", (payload) => {
  if (payload.value !== undefined) {
    state.bindForm.secret_name = payload.value;
    renderUI();
  }
});

// Save configuration button
self.kraken.on("btn-save-config", async (payload) => {
  state.saving = true;
  renderUI();

  try {
    const form = payload?.formData || payload || self.kraken.formData || {};
    if (form.cfg_vault_name !== undefined) state.config.vault_name = String(form.cfg_vault_name || "").trim();
    if (form.cfg_vault_url !== undefined) state.config.vault_url = String(form.cfg_vault_url || "").trim();
    if (form.cfg_auth_method !== undefined) state.config.auth_method = form.cfg_auth_method;
    if (form.cfg_tenant_id !== undefined) state.config.tenant_id = String(form.cfg_tenant_id || "").trim();
    if (form.cfg_client_id !== undefined) state.config.client_id = String(form.cfg_client_id || "").trim();
    if (form.cfg_client_secret && form.cfg_client_secret !== "••••••••••••••••") {
      state.config.client_secret = String(form.cfg_client_secret).trim();
    }

    await persistConfig();
    state.message = { type: "success", text: "Configuração do Azure Key Vault salva com sucesso!" };
  } catch (err) {
    state.message = { type: "error", text: "Erro ao salvar configuração: " + (err.message || err) };
  } finally {
    state.saving = false;
    renderUI();
  }
});

// Save convention pattern button
self.kraken.on("btn-save-convention", async (payload) => {
  const form = payload?.formData || payload || self.kraken.formData || {};
  if (form.cfg_naming_pattern) {
    state.config.naming_pattern = String(form.cfg_naming_pattern).trim();
  }
  await persistConfig();
  state.message = { type: "success", text: "Regra de convenção de segredos atualizada com sucesso!" };
  renderUI();
});

// Bind server to secret on main page
self.kraken.on("btn-bind-server-secret", async (payload) => {
  state.saving = true;
  state.message = { type: "", text: "" };
  renderUI();

  try {
    const form = payload?.formData || payload || self.kraken.formData || {};
    const srvId = String(form.bind_server_id || state.bindForm.selected_server_id || (state.servers[0]?.id ?? ""));
    const srv = state.servers.find(s => String(s.id) === srvId);
    const secretName = String(form.bind_secret_name || form.bind_secret_select || state.bindForm.secret_name || "").trim();
    let newSecretVal = String(form.bind_new_secret_value || "");

    if (!srvId) {
      state.message = { type: "error", text: "Selecione um servidor para vincular." };
      return;
    }
    if (!secretName) {
      state.message = { type: "error", text: "Informe o nome do Secret no Azure Key Vault para vincular ao servidor." };
      return;
    }

    if (newSecretVal.trim() !== "") {
      const putRes = await callBackendAction("put_secret", {
        config: state.config,
        name: secretName,
        value: newSecretVal,
        content_type: "ssh-password",
        tags: {
          server_id: srvId,
          hostname: srv ? srv.hostname : "",
          managed_by: "kraken-azure-keyvault"
        }
      });
      newSecretVal = "";
      if (self.kraken.formData) {
        delete self.kraken.formData.bind_new_secret_value;
      }

      if (!putRes || putRes.status === "error" || putRes.data?.error) {
        const errMsg = putRes?.error || putRes?.data?.error?.message || "Falha ao gravar segredo no Azure Key Vault.";
        state.message = { type: "error", text: errMsg };
        return;
      }
    }

    if (!state.config.server_bindings) {
      state.config.server_bindings = {};
    }
    state.config.server_bindings[srvId] = secretName;
    if (srv && srv.hostname) {
      state.config.server_bindings[srv.hostname] = secretName;
    }
    state.bindForm.selected_server_id = srvId;
    state.bindForm.secret_name = secretName;

    await persistConfig();
    state.message = {
      type: "success",
      text: `Servidor '${srv ? srv.name : srvId}' vinculado ao secret '${secretName}' no Azure Key Vault (resolução Just-in-Time ativa, zero armazenamento local)!`
    };
  } catch (err) {
    state.message = { type: "error", text: "Erro ao vincular servidor: " + (err.message || err) };
  } finally {
    state.saving = false;
    renderUI();
  }
});

// Unbind server secret on main page
self.kraken.on("btn-unbind-server-secret", async () => {
  const srvId = state.bindForm.selected_server_id;
  const srv = state.servers.find(s => String(s.id) === String(srvId));
  if (state.config.server_bindings) {
    delete state.config.server_bindings[srvId];
    if (srv && srv.hostname) {
      delete state.config.server_bindings[srv.hostname];
    }
  }
  state.bindForm.secret_name = "";
  await persistConfig();
  state.message = { type: "info", text: "Vínculo manual removido." };
  renderUI();
});

// Test ephemeral JIT secret resolution without keeping secret in memory
self.kraken.on("btn-test-jit-resolve", async (payload) => {
  state.loading = true;
  state.message = { type: "", text: "" };
  renderUI();

  try {
    const form = payload?.formData || payload || self.kraken.formData || {};
    const srvId = String(form.bind_server_id || state.bindForm.selected_server_id || (state.servers[0]?.id ?? ""));
    const srv = state.servers.find(s => String(s.id) === srvId) || { id: srvId, name: srvId, hostname: srvId };

    const res = await callBackendAction("credentials.resolve", {
      config: state.config,
      server_id: srv.id,
      hostname: srv.hostname,
      server_name: srv.name
    });

    if (res && res.data && (res.data.value || res.data.password)) {
      let secretVal = String(res.data.value || res.data.password);
      const len = secretVal.length;
      secretVal = "";
      if (res.data.value) res.data.value = "";
      if (res.data.password) res.data.password = "";

      state.message = {
        type: "success",
        text: `Resolução JIT concluída para '${srv.name}' (${srv.hostname}): Segredo obtido do Azure Key Vault (${len} caracteres) e descartado imediatamente da memória!`
      };
    } else {
      const errMsg = res?.error || res?.data?.error?.message || "Secret não encontrado no cofre ou sem permissão de leitura (Key Vault Secrets User).";
      state.message = { type: "error", text: `Falha ao resolver secret para '${srv.name}': ${errMsg}` };
    }
  } catch (err) {
    state.message = { type: "error", text: "Erro na resolução JIT: " + (err.message || err) };
  } finally {
    state.loading = false;
    renderUI();
  }
});

// Test connection & list secrets
async function performTestConnection(silentOnMissingVault, payload) {
  const form = payload?.formData || payload || self.kraken.formData || {};
  if (form.cfg_vault_name !== undefined && String(form.cfg_vault_name).trim() !== "") {
    state.config.vault_name = String(form.cfg_vault_name).trim();
  }
  if (form.cfg_vault_url !== undefined && String(form.cfg_vault_url).trim() !== "") {
    state.config.vault_url = String(form.cfg_vault_url).trim();
  }

  if (!isKeyVaultOperable()) {
    if (!silentOnMissingVault) {
      state.message = {
        type: "info",
        text: "Conecte uma conta Microsoft ou informe um Azure Key Vault antes de testar a conexão."
      };
      renderUI();
    }
    return;
  }

  state.loading = true;
  state.testResult = null;
  renderUI();

  try {
    await persistConfig();
    const res = await callBackendAction("test_connection", state.config);
    if (res && res.data && !res.data.error && res.status !== "error") {
      if (Array.isArray(res.data.value)) {
        state.secrets = res.data.value.map(item => {
          const parts = (item.id || "").replace(/\/+$/, "").split("/");
          return {
            name: parts[parts.length - 1] || "secret",
            id: item.id,
            enabled: item.attributes?.enabled ?? true,
            tags: item.tags || {}
          };
        });
      } else if (Array.isArray(res.data.secrets)) {
        state.secrets = res.data.secrets;
      }
      state.secretsTable.currentPage = 1;

      state.testResult = {
        success: true,
        message: `Conectado com sucesso ao cofre '${state.config.vault_name || state.config.vault_url}' (total de ${state.secrets.length} segredos listados).`
      };
    } else {
      const errMsg = res?.error || res?.data?.error?.message || res?.data?.error_description || "Falha na comunicação com o Azure Key Vault.";
      state.testResult = {
        success: false,
        message: errMsg
      };
    }
  } catch (err) {
    state.testResult = {
      success: false,
      message: "Erro ao testar conexão: " + (err.message || err)
    };
  } finally {
    state.loading = false;
    renderUI();
  }
}

self.kraken.on("btn-test-connection", (payload) => performTestConnection(false, payload));
self.kraken.on("btn-widget-test-conn", (payload) => performTestConnection(false, payload));
self.kraken.on("btn-sync-secrets", (payload) => performTestConnection(false, payload));
self.kraken.on("btn-sync-secrets-all", (payload) => performTestConnection(false, payload));

// Secrets Table: Global search filter
self.kraken.on("secrets_search_input", (payload) => {
  const q = String(payload.value !== undefined ? payload.value : (payload.formData?.secrets_search_input ?? "")).trim();
  state.secretsTable.searchQuery = q;
  state.secretsTable.currentPage = 1;
  renderUI();
});

// Secrets Table: Page size selection
self.kraken.on("secrets_page_size", (payload) => {
  const sz = parseInt(payload.value || "10", 10) || 10;
  state.secretsTable.pageSize = sz;
  state.secretsTable.currentPage = 1;
  renderUI();
});

// Secrets Table: Pagination Controls
self.kraken.on("btn-secrets-first-page", () => {
  state.secretsTable.currentPage = 1;
  renderUI();
});

self.kraken.on("btn-secrets-prev-page", () => {
  if (state.secretsTable.currentPage > 1) {
    state.secretsTable.currentPage--;
    renderUI();
  }
});

self.kraken.on("btn-secrets-next-page", () => {
  const q = (state.secretsTable.searchQuery || "").toLowerCase();
  const filtered = state.secrets.filter(s => {
    if (!q) return true;
    if (s.name && s.name.toLowerCase().includes(q)) return true;
    if (s.tags && typeof s.tags === "object") {
      for (const [k, v] of Object.entries(s.tags)) {
        if (k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q)) return true;
      }
    }
    return false;
  });
  const totalPages = Math.max(1, Math.ceil(filtered.length / state.secretsTable.pageSize));
  if (state.secretsTable.currentPage < totalPages) {
    state.secretsTable.currentPage++;
    renderUI();
  }
});

self.kraken.on("btn-secrets-last-page", () => {
  const q = (state.secretsTable.searchQuery || "").toLowerCase();
  const filtered = state.secrets.filter(s => {
    if (!q) return true;
    if (s.name && s.name.toLowerCase().includes(q)) return true;
    if (s.tags && typeof s.tags === "object") {
      for (const [k, v] of Object.entries(s.tags)) {
        if (k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q)) return true;
      }
    }
    return false;
  });
  state.secretsTable.currentPage = Math.max(1, Math.ceil(filtered.length / state.secretsTable.pageSize));
  renderUI();
});

// -------------------------------------------------------------
// Interactive Table Secret Actions: Mostrar & Copiar
// -------------------------------------------------------------

async function handleToggleShowSecret(secretName) {
  if (!state.revealedSecrets) state.revealedSecrets = {};
  if (!state.secretVersions) state.secretVersions = {};

  // If currently revealed and visible, clicking Ocultar hides it
  if (state.revealedSecrets[secretName] && !state.revealedSecrets[secretName].isMasked) {
    state.revealedSecrets[secretName].isMasked = true;
    renderUI();
    return;
  }

  // If already in memory (e.g. from previous copy or fetch), reveal immediately on 1st click!
  if (state.revealedSecrets[secretName] && state.revealedSecrets[secretName].value) {
    state.revealedSecrets[secretName].isMasked = false;
    state.secretVersions[secretName] = (state.secretVersions[secretName] || 0) + 1;
    renderUI();
    return;
  }

  // Not in memory yet -> fetch from Azure Key Vault
  state.loadingSecretName = secretName;
  renderUI();

  try {
    const res = await callBackendAction("get_secret", {
      config: state.config,
      secret_name: secretName
    });

    if (res && res.data && !res.data.error && res.status !== "error") {
      const secretVal = res.data.value !== undefined ? res.data.value : (res.data.secret || "");
      state.revealedSecrets[secretName] = {
        value: secretVal,
        isMasked: false
      };
      state.secretVersions[secretName] = (state.secretVersions[secretName] || 0) + 1;
    } else {
      const errMsg = res?.error || res?.data?.error?.message || res?.data?.error_description || "Falha ao consultar valor do secret no Azure Key Vault.";
      state.message = {
        type: "error",
        text: `Erro ao buscar secret '${secretName}': ${errMsg}`
      };
    }
  } catch (err) {
    state.message = {
      type: "error",
      text: `Erro ao buscar secret '${secretName}': ${err.message || err}`
    };
  } finally {
    state.loadingSecretName = "";
    renderUI();
  }
}

async function handleCopySecret(secretName) {
  if (!state.revealedSecrets) state.revealedSecrets = {};
  if (!state.secretVersions) state.secretVersions = {};

  let secretVal = "";
  if (state.revealedSecrets[secretName] && state.revealedSecrets[secretName].value) {
    secretVal = state.revealedSecrets[secretName].value;
  } else {
    state.copyLoadingSecret = secretName;
    renderUI();

    try {
      const res = await callBackendAction("get_secret", {
        config: state.config,
        secret_name: secretName
      });

      if (res && res.data && !res.data.error && res.status !== "error") {
        secretVal = res.data.value !== undefined ? res.data.value : (res.data.secret || "");
        state.revealedSecrets[secretName] = {
          value: secretVal,
          isMasked: true // keep masked in textfield unless user also clicked Mostrar
        };
      } else {
        const errMsg = res?.error || res?.data?.error?.message || "Falha ao obter secret.";
        state.message = { type: "error", text: `Erro ao obter secret '${secretName}': ${errMsg}` };
        state.copyLoadingSecret = "";
        renderUI();
        return;
      }
    } catch (err) {
      state.message = { type: "error", text: `Erro ao obter secret '${secretName}': ${err.message || err}` };
      state.copyLoadingSecret = "";
      renderUI();
      return;
    } finally {
      state.copyLoadingSecret = "";
    }
  }

  // Attempt writing to clipboard
  try {
    if (self.navigator && self.navigator.clipboard && self.navigator.clipboard.writeText) {
      self.navigator.clipboard.writeText(secretVal)
        .then(() => self.kraken.log("Secret copiado para área de transferência."))
        .catch((e) => self.kraken.log("Aviso de escrita no clipboard: " + e));
    }
  } catch (_) {}

  // Visual feedback: button changes to "✅ Copiado!" for 3 seconds
  state.copiedSecretName = secretName;
  renderUI();

  if (state.copiedSecretTimeout) {
    clearTimeout(state.copiedSecretTimeout);
  }
  state.copiedSecretTimeout = setTimeout(() => {
    if (state.copiedSecretName === secretName) {
      state.copiedSecretName = "";
      renderUI();
    }
  }, 3000);
}

// Server detail tab: save binding
self.kraken.on("btn-save-server-binding", async (payload) => {
  state.saving = true;
  renderUI();

  try {
    const ctx = self.kraken.params || self.kraken.context || {};
    const serverId = String(ctx.server_id || ctx.id || "srv-01");
    const form = payload?.formData || payload || self.kraken.formData || {};
    const selectedSecret = String(form.server_tab_custom_secret || form.server_tab_secret_name || "").trim();

    if (!state.config.server_bindings) {
      state.config.server_bindings = {};
    }

    if (selectedSecret) {
      state.config.server_bindings[serverId] = selectedSecret;
    } else {
      delete state.config.server_bindings[serverId];
    }

    await persistConfig();
    state.message = {
      type: "success",
      text: selectedSecret
        ? `Servidor vinculado ao secret '${selectedSecret}' com sucesso!`
        : "Vínculo manual removido."
    };
  } catch (err) {
    state.message = { type: "error", text: "Erro ao salvar vínculo: " + (err.message || err) };
  } finally {
    state.saving = false;
    renderUI();
  }
});

self.kraken.on("btn-refresh-tab-secrets", async () => {
  await performTestConnection(false);
});

// Startup initialization
(async () => {
  await loadConfig();
  detectKrakenUser();
  await loadMonitoredServers();
  renderUI();

  // Run initial discoveries sequentially with settling delays to avoid Wazero instantiation races
  if (state.config.accounts && state.config.accounts.length > 0) {
    try {
      await discoverUserVaults(true);
    } catch (_) {}
  }

  if (isKeyVaultOperable()) {
    try {
      await new Promise(r => setTimeout(r, 150));
      await performTestConnection(true);
    } catch (_) {}
  }
})();
