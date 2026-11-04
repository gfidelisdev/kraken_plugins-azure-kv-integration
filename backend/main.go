package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
	"unsafe"
)

// Default public Microsoft Azure CLI Client ID (supports Device Code Flow out-of-the-box for Entra ID & Key Vault)
const DefaultAzurePublicClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

//go:wasmimport kraken kraken_kv_get
func hostKVGet(keyPtr, keyLen, outPtr, maxOutLen uint32) uint32

//go:wasmimport kraken kraken_kv_set
func hostKVSet(keyPtr, keyLen, valPtr, valLen uint32) uint32

func wasmKVGet(key string) string {
	if key == "" {
		return ""
	}
	scopedKey := key
	if !strings.HasPrefix(scopedKey, "com.kraken.azure-keyvault:") {
		scopedKey = "com.kraken.azure-keyvault:" + key
	}
	keyBytes := []byte(scopedKey)
	outBuf := make([]byte, 512*1024)
	n := hostKVGet(
		uint32(uintptr(unsafe.Pointer(&keyBytes[0]))),
		uint32(len(keyBytes)),
		uint32(uintptr(unsafe.Pointer(&outBuf[0]))),
		uint32(len(outBuf)),
	)
	if n == 0 {
		rawKeyBytes := []byte(key)
		n = hostKVGet(
			uint32(uintptr(unsafe.Pointer(&rawKeyBytes[0]))),
			uint32(len(rawKeyBytes)),
			uint32(uintptr(unsafe.Pointer(&outBuf[0]))),
			uint32(len(outBuf)),
		)
		if n == 0 {
			return ""
		}
	}
	return string(outBuf[:n])
}

func wasmKVSet(key, val string) error {
	if key == "" {
		return fmt.Errorf("empty key")
	}
	scopedKey := key
	if !strings.HasPrefix(scopedKey, "com.kraken.azure-keyvault:") {
		scopedKey = "com.kraken.azure-keyvault:" + key
	}
	keyBytes := []byte(scopedKey)
	valBytes := []byte(val)
	var valPtr uint32
	if len(valBytes) > 0 {
		valPtr = uint32(uintptr(unsafe.Pointer(&valBytes[0])))
	}
	rc := hostKVSet(
		uint32(uintptr(unsafe.Pointer(&keyBytes[0]))),
		uint32(len(keyBytes)),
		valPtr,
		uint32(len(valBytes)),
	)
	if rc != 0 {
		return fmt.Errorf("kraken_kv_set failed with code %d", rc)
	}
	return nil
}

// Request defines the standard Kraken plugin execution request via Stdin
type Request struct {
	Action   string          `json:"action"`
	Payload  json.RawMessage `json:"payload"`
	PluginID string          `json:"plugin_id"`
}

// Response defines the standard Kraken plugin response via Stdout
type Response struct {
	Status string      `json:"status"` // "success", "error", "needs_host_adapter"
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// MicrosoftAccount represents a connected Microsoft Entra/Account
type MicrosoftAccount struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	TenantID     string `json:"tenant_id,omitempty"`
	Source       string `json:"source"` // "kraken_session" | "device_login"
	Token        string `json:"token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
}

// Config defines the Azure Key Vault and binding configuration
type Config struct {
	AuthMethod      string             `json:"auth_method"` // "user_account", "service_principal", "managed_identity", "azure_cli"
	TenantID        string             `json:"tenant_id,omitempty"`
	ClientID        string             `json:"client_id,omitempty"`
	ClientSecret    string             `json:"client_secret,omitempty"`
	VaultName       string             `json:"vault_name"` // e.g. "my-company-kv"
	VaultURL        string             `json:"vault_url,omitempty"`
	AutoConvention  bool               `json:"auto_convention"`          // e.g. srv-{hostname}-pwd
	NamingPattern   string             `json:"naming_pattern,omitempty"` // default: "srv-{hostname}-pwd"
	ServerBindings  map[string]string  `json:"server_bindings,omitempty"`
	ActiveAccountID string             `json:"active_account_id,omitempty"`
	Accounts        []MicrosoftAccount `json:"accounts,omitempty"`
}

func wipeString(s *string) {
	if s == nil {
		return
	}
	*s = ""
}

func loadPersistedConfig() Config {
	var cfg Config
	raw := wasmKVGet("azure_kv_config")
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	if cfg.ServerBindings == nil {
		cfg.ServerBindings = make(map[string]string)
	}
	return cfg
}

func mergeWithPersistedConfig(incoming *Config) Config {
	persisted := loadPersistedConfig()
	if incoming == nil {
		return persisted
	}
	if strings.TrimSpace(incoming.VaultName) != "" {
		persisted.VaultName = strings.TrimSpace(incoming.VaultName)
	}
	if strings.TrimSpace(incoming.VaultURL) != "" {
		persisted.VaultURL = strings.TrimSpace(incoming.VaultURL)
	}
	if strings.TrimSpace(incoming.AuthMethod) != "" {
		persisted.AuthMethod = strings.TrimSpace(incoming.AuthMethod)
	}
	if strings.TrimSpace(incoming.TenantID) != "" {
		persisted.TenantID = strings.TrimSpace(incoming.TenantID)
	}
	if strings.TrimSpace(incoming.ClientID) != "" {
		persisted.ClientID = strings.TrimSpace(incoming.ClientID)
	}
	if strings.TrimSpace(incoming.ClientSecret) != "" {
		persisted.ClientSecret = strings.TrimSpace(incoming.ClientSecret)
	}
	if strings.TrimSpace(incoming.ActiveAccountID) != "" {
		persisted.ActiveAccountID = strings.TrimSpace(incoming.ActiveAccountID)
	}
	if len(incoming.Accounts) > 0 {
		persisted.Accounts = incoming.Accounts
	}
	if len(incoming.ServerBindings) > 0 {
		if persisted.ServerBindings == nil {
			persisted.ServerBindings = make(map[string]string)
		}
		for k, v := range incoming.ServerBindings {
			persisted.ServerBindings[k] = v
		}
	}
	return persisted
}

func getVaultBaseURL(cfg *Config) string {
	if cfg.VaultURL != "" {
		u := strings.TrimSpace(cfg.VaultURL)
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "https://" + u
		}
		return strings.TrimRight(u, "/")
	}
	name := strings.TrimSpace(cfg.VaultName)
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimPrefix(name, "http://")
	name = strings.TrimSuffix(name, ".vault.azure.net")
	name = strings.TrimRight(name, "/")
	return fmt.Sprintf("https://%s.vault.azure.net", name)
}

func getEffectiveClientID(cfg *Config) string {
	if cfg != nil && strings.TrimSpace(cfg.ClientID) != "" {
		return strings.TrimSpace(cfg.ClientID)
	}
	return DefaultAzurePublicClientID
}

func getEffectiveTenantID(cfg *Config) string {
	if cfg != nil && strings.TrimSpace(cfg.TenantID) != "" {
		return strings.TrimSpace(cfg.TenantID)
	}
	return "common"
}

func resolveSecretName(cfg *Config, serverID, hostname string) string {
	if cfg.ServerBindings != nil {
		if mapped, ok := cfg.ServerBindings[serverID]; ok && mapped != "" {
			return mapped
		}
		if mapped, ok := cfg.ServerBindings[hostname]; ok && mapped != "" {
			return mapped
		}
	}

	if cfg.AutoConvention {
		pattern := cfg.NamingPattern
		if pattern == "" {
			pattern = "srv-{hostname}-pwd"
		}
		cleanHost := strings.ToLower(strings.TrimSpace(hostname))
		cleanHost = strings.ReplaceAll(cleanHost, ".", "-")
		cleanHost = strings.ReplaceAll(cleanHost, ":", "-")

		resolved := strings.ReplaceAll(pattern, "{hostname}", cleanHost)
		resolved = strings.ReplaceAll(resolved, "{server_id}", serverID)
		return resolved
	}

	return ""
}

func getActiveAccount(cfg *Config) *MicrosoftAccount {
	if cfg == nil || len(cfg.Accounts) == 0 {
		return nil
	}
	for i := range cfg.Accounts {
		if cfg.Accounts[i].ID == cfg.ActiveAccountID {
			return &cfg.Accounts[i]
		}
	}
	return &cfg.Accounts[0]
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// buildAuthTokenScript generates a bash snippet that sets $AKV_TOKEN according to the configured AuthMethod
func buildAuthTokenScript(cfg *Config) (string, error) {
	method := strings.TrimSpace(cfg.AuthMethod)
	if method == "" {
		method = "user_account"
	}

	switch method {
	case "user_account":
		acc := getActiveAccount(cfg)
		if acc == nil {
			return "", fmt.Errorf("Nenhuma conta Microsoft conectada. Clique em 'Conectar Conta Microsoft' primeiro.")
		}
		tok := strings.TrimSpace(acc.AccessToken)
		if tok == "" {
			tok = strings.TrimSpace(acc.Token)
		}
		refreshTok := strings.TrimSpace(acc.RefreshToken)
		tenant := acc.TenantID
		if tenant == "" {
			tenant = getEffectiveTenantID(cfg)
		}
		clientID := getEffectiveClientID(cfg)

		now := time.Now().Unix()
		if refreshTok != "" && (tok == "" || (acc.ExpiresAt > 0 && acc.ExpiresAt <= now+120)) {
			return fmt.Sprintf(`AKV_REFRESH_JSON=$(curl -s -X POST %s --data-urlencode 'grant_type=refresh_token' --data-urlencode %s --data-urlencode %s --data-urlencode 'scope=https://vault.azure.net/.default openid profile email offline_access')
AKV_TOKEN=$(printf '%%s' "$AKV_REFRESH_JSON" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -z "$AKV_TOKEN" ]; then AKV_TOKEN=%s; fi`,
				shellQuote(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenant))),
				shellQuote("client_id="+clientID),
				shellQuote("refresh_token="+refreshTok),
				shellQuote(tok),
			), nil
		}

		if tok == "" {
			return "", fmt.Errorf("A conta Microsoft selecionada (%s) não possui um token OAuth2 ativo. Reconecte a conta na janela da Microsoft.", acc.Email)
		}
		return fmt.Sprintf("AKV_TOKEN=%s", shellQuote(tok)), nil

	case "service_principal":
		tenant := strings.TrimSpace(cfg.TenantID)
		clientID := strings.TrimSpace(cfg.ClientID)
		clientSecret := strings.TrimSpace(cfg.ClientSecret)
		if tenant == "" || clientID == "" || clientSecret == "" {
			return "", fmt.Errorf("Para Service Principal, preencha Tenant ID, Client ID e Client Secret.")
		}
		return fmt.Sprintf(`AKV_SP_JSON=$(curl -s -X POST %s --data-urlencode 'grant_type=client_credentials' --data-urlencode %s --data-urlencode %s --data-urlencode 'scope=https://vault.azure.net/.default')
AKV_TOKEN=$(printf '%%s' "$AKV_SP_JSON" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -z "$AKV_TOKEN" ]; then printf '%%s' "$AKV_SP_JSON"; exit 0; fi`,
			shellQuote(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenant))),
			shellQuote("client_id="+clientID),
			shellQuote("client_secret="+clientSecret),
		), nil

	case "managed_identity":
		return `AKV_MI_JSON=$(curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net')
AKV_TOKEN=$(printf '%s' "$AKV_MI_JSON" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -z "$AKV_TOKEN" ]; then printf '{"error":{"code":"ManagedIdentityError","message":"Falha ao obter token via Azure IMDS (169.254.169.254)"}}'; exit 0; fi`, nil

	case "azure_cli":
		return `AKV_TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv 2>/dev/null | tr -d '\r\n')
if [ -z "$AKV_TOKEN" ]; then printf '{"error":{"code":"AzureCLIError","message":"Falha ao obter token via Azure CLI (az account get-access-token)"}}'; exit 0; fi`, nil

	default:
		return "", fmt.Errorf("Método de autenticação desconhecido: %s", method)
	}
}

// buildARMTokenScript generates a bash snippet that sets $ARM_TOKEN for Azure Resource Manager operations
func buildARMTokenScript(cfg *Config) (string, error) {
	method := strings.TrimSpace(cfg.AuthMethod)
	if method == "" {
		method = "user_account"
	}

	switch method {
	case "user_account":
		acc := getActiveAccount(cfg)
		if acc == nil {
			return "", fmt.Errorf("Nenhuma conta Microsoft conectada.")
		}
		refreshTok := strings.TrimSpace(acc.RefreshToken)
		tenant := acc.TenantID
		if tenant == "" {
			tenant = getEffectiveTenantID(cfg)
		}
		clientID := getEffectiveClientID(cfg)

		if refreshTok != "" {
			return fmt.Sprintf(`ARM_TOKEN_JSON=$(curl -s -X POST %s --data-urlencode 'grant_type=refresh_token' --data-urlencode %s --data-urlencode %s --data-urlencode 'scope=https://management.azure.com/user_impersonation')
ARM_TOKEN=$(printf '%%s' "$ARM_TOKEN_JSON" | grep -o '"access_token"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')`,
				shellQuote(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenant))),
				shellQuote("client_id="+clientID),
				shellQuote("refresh_token="+refreshTok),
			), nil
		}
		tok := strings.TrimSpace(acc.AccessToken)
		if tok == "" {
			tok = strings.TrimSpace(acc.Token)
		}
		return fmt.Sprintf("ARM_TOKEN=%s", shellQuote(tok)), nil

	case "service_principal":
		tenant := strings.TrimSpace(cfg.TenantID)
		clientID := strings.TrimSpace(cfg.ClientID)
		clientSecret := strings.TrimSpace(cfg.ClientSecret)
		return fmt.Sprintf(`ARM_SP_JSON=$(curl -s -X POST %s --data-urlencode 'grant_type=client_credentials' --data-urlencode %s --data-urlencode %s --data-urlencode 'scope=https://management.azure.com/.default')
ARM_TOKEN=$(printf '%%s' "$ARM_SP_JSON" | grep -o '"access_token"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')`,
			shellQuote(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenant))),
			shellQuote("client_id="+clientID),
			shellQuote("client_secret="+clientSecret),
		), nil

	case "managed_identity":
		return `ARM_MI_JSON=$(curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F')
ARM_TOKEN=$(printf '%s' "$ARM_MI_JSON" | grep -o '"access_token"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')`, nil

	case "azure_cli":
		return `ARM_TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv 2>/dev/null | tr -d '\r\n')`, nil

	default:
		return "", fmt.Errorf("Método desconhecido: %s", method)
	}
}

func main() {
	var req Request
	data, err := io.ReadAll(os.Stdin)
	if err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &req)
	}

	var resp Response

	switch req.Action {

	// -------------------------------------------------------------
	// 0. Scoped KV Store Operations (for self.kraken.kv.get / set)
	// -------------------------------------------------------------
	case "kv_get":
		var key string
		if err := json.Unmarshal(req.Payload, &key); err != nil {
			var keyObj struct {
				Key string `json:"key"`
			}
			_ = json.Unmarshal(req.Payload, &keyObj)
			key = keyObj.Key
		}
		val := wasmKVGet(strings.TrimSpace(key))
		out, _ := json.Marshal(val)
		os.Stdout.Write(out)
		return

	case "kv_set":
		var kvPayload struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(req.Payload, &kvPayload); err != nil || kvPayload.Key == "" {
			resp = Response{Status: "error", Error: "kv_set requires {key, value}"}
			break
		}
		var valStr string
		if err := json.Unmarshal(kvPayload.Value, &valStr); err != nil {
			valStr = string(kvPayload.Value)
		}
		if err := wasmKVSet(strings.TrimSpace(kvPayload.Key), valStr); err != nil {
			resp = Response{Status: "error", Error: err.Error()}
			break
		}
		resp = Response{Status: "success", Data: map[string]string{"status": "ok"}}

	// -------------------------------------------------------------
	// 0b. List Monitored Hosts in Kraken
	// -------------------------------------------------------------
	case "get_hosts", "hosts.list":
		resp = Response{
			Status: "needs_host_adapter",
			Data: map[string]interface{}{
				"operation": "hosts.list",
			},
		}

	// -------------------------------------------------------------
	// 1. Start Microsoft Device Login via Host Adapter (cURL)
	// -------------------------------------------------------------
	case "auth.start_device_login":
		var cfg Config
		_ = json.Unmarshal(req.Payload, &cfg)
		cfg = mergeWithPersistedConfig(&cfg)

		tenant := getEffectiveTenantID(&cfg)
		clientID := getEffectiveClientID(&cfg)

		curlCmd := fmt.Sprintf(
			"curl -s -X POST %s --data-urlencode %s --data-urlencode 'scope=https://vault.azure.net/.default openid profile email offline_access'",
			shellQuote(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", url.PathEscape(tenant))),
			shellQuote("client_id="+clientID),
		)

		resp = Response{
			Status: "needs_host_adapter",
			Data: map[string]interface{}{
				"operation": "hosts.exec",
				"host":      "localhost",
				"cmd":       curlCmd,
			},
		}

	// -------------------------------------------------------------
	// 2. Poll Microsoft Device Login Token via Host Adapter
	// -------------------------------------------------------------
	case "auth.poll_device_login":
		var pollReq struct {
			Config     Config `json:"config"`
			DeviceCode string `json:"device_code"`
		}
		_ = json.Unmarshal(req.Payload, &pollReq)
		cfg := mergeWithPersistedConfig(&pollReq.Config)

		tenant := getEffectiveTenantID(&cfg)
		clientID := getEffectiveClientID(&cfg)

		curlCmd := fmt.Sprintf(
			"curl -s -X POST %s --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' --data-urlencode %s --data-urlencode %s",
			shellQuote(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenant))),
			shellQuote("client_id="+clientID),
			shellQuote("device_code="+strings.TrimSpace(pollReq.DeviceCode)),
		)

		resp = Response{
			Status: "needs_host_adapter",
			Data: map[string]interface{}{
				"operation": "hosts.exec",
				"host":      "localhost",
				"cmd":       curlCmd,
			},
		}

	// -------------------------------------------------------------
	// 2b. Auto-Discover Key Vaults of Connected Microsoft Account
	// -------------------------------------------------------------
	case "list_user_vaults":
		var cfg Config
		_ = json.Unmarshal(req.Payload, &cfg)
		cfg = mergeWithPersistedConfig(&cfg)

		armScript, armErr := buildARMTokenScript(&cfg)
		if armErr != nil {
			resp = Response{Status: "error", Error: armErr.Error()}
			break
		}

		discoverCmd := fmt.Sprintf(`%s
if [ -z "$ARM_TOKEN" ]; then
  ARM_ERR=$(printf '%%s' "$ARM_TOKEN_JSON" | grep -o '"error_description"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*"error_description"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
  if [ -z "$ARM_ERR" ]; then
    ARM_ERR=$(printf '%%s' "$ARM_TOKEN_JSON" | grep -o '"error"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
  fi
  if [ -z "$ARM_ERR" ]; then
    ARM_ERR="Não foi possível obter token ARM para listar cofres."
  fi
  printf '{"error":{"message":"%%s"}}' "$ARM_ERR"
  exit 0
fi

SUBS_JSON=$(curl -s -H "Authorization: Bearer $ARM_TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01")
SUB_IDS=$(printf '%%s' "$SUBS_JSON" | grep -o '"subscriptionId"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"subscriptionId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

ALL_ITEMS_ACC=""

if [ -n "$SUB_IDS" ]; then
  for sub in $SUB_IDS; do
    VAULTS_JSON=$(curl -s -H "Authorization: Bearer $ARM_TOKEN" "https://management.azure.com/subscriptions/$sub/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01")
    VITEMS=$(printf '%%s' "$VAULTS_JSON" | tr -d '\r\n' | sed -n 's/.*"value"[[:space:]]*:[[:space:]]*\(\[[^]]*\]\).*/\1/p')
    if [ -n "$VITEMS" ] && [ "$VITEMS" != "[]" ]; then
      CLEAN_ITEMS=$(printf '%%s' "$VITEMS" | sed -e 's/^\[//' -e 's/\]$//')
      if [ -n "$ALL_ITEMS_ACC" ]; then
        ALL_ITEMS_ACC="$ALL_ITEMS_ACC, $CLEAN_ITEMS"
      else
        ALL_ITEMS_ACC="$CLEAN_ITEMS"
      fi
    fi
  done
fi

printf '{"subscriptions":%%s,"vaults":[%%s]}' "$SUBS_JSON" "$ALL_ITEMS_ACC"
`, armScript)

		resp = Response{
			Status: "needs_host_adapter",
			Data: map[string]interface{}{
				"operation": "hosts.exec",
				"host":      "localhost",
				"cmd":       discoverCmd,
			},
		}

	// -------------------------------------------------------------
	// 3. Test Connection / List Secrets via Host Adapter
	// -------------------------------------------------------------
	case "test_connection", "list_secrets", "vault.list_secrets", "vault.test_connection":
		var cfg Config
		_ = json.Unmarshal(req.Payload, &cfg)
		cfg = mergeWithPersistedConfig(&cfg)

		if strings.TrimSpace(cfg.VaultName) == "" && strings.TrimSpace(cfg.VaultURL) == "" {
			resp = Response{Status: "error", Error: "Informe ou selecione um Azure Key Vault antes de testar ou listar segredos."}
			break
		}

		authScript, authErr := buildAuthTokenScript(&cfg)
		if authErr != nil {
			resp = Response{Status: "error", Error: authErr.Error()}
			break
		}

		vaultURL := getVaultBaseURL(&cfg)
		paginationCmd := fmt.Sprintf(`%s
VAULT_BASE_URL=%s

if [ -z "$AKV_TOKEN" ]; then
  printf '{"error":{"message":"Falha ao obter token de autenticação para o Azure Key Vault."}}\n'
  exit 0
fi

if command -v python3 >/dev/null 2>&1; then
python3 - "$AKV_TOKEN" "$VAULT_BASE_URL" << 'PYEOF'
import sys, json, urllib.request

token = sys.argv[1]
vault_url = sys.argv[2]
url = f"{vault_url}/secrets?api-version=7.4&maxresults=25"
all_secrets = []

while url:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as r:
            data = json.loads(r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        sys.stdout.write(e.read().decode('utf-8', errors='ignore'))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": {"message": str(e)}}))
        sys.exit(0)

    val = data.get("value", [])
    if isinstance(val, list):
        all_secrets.extend(val)
    url = data.get("nextLink")

print(json.dumps({"value": all_secrets}))
PYEOF
elif command -v jq >/dev/null 2>&1; then
  CUR_URL="$VAULT_BASE_URL/secrets?api-version=7.4&maxresults=25"
  ALL_ITEMS="[]"
  while [ -n "$CUR_URL" ]; do
    RESP=$(curl -s -H "Authorization: Bearer $AKV_TOKEN" "$CUR_URL")
    if printf '%%s' "$RESP" | jq -e '.error' >/dev/null 2>&1; then
      printf '%%s' "$RESP"
      exit 0
    fi
    ITEMS=$(printf '%%s' "$RESP" | jq -c '.value // []')
    ALL_ITEMS=$(jq -c -n --argjson a "$ALL_ITEMS" --argjson b "$ITEMS" '$a + $b')
    CUR_URL=$(printf '%%s' "$RESP" | jq -r '.nextLink // empty')
  done
  printf '{"value":%%s}\n' "$ALL_ITEMS"
else
  CUR_URL="$VAULT_BASE_URL/secrets?api-version=7.4&maxresults=25"
  ALL_ITEMS=""
  while [ -n "$CUR_URL" ]; do
    RESP=$(curl -s -H "Authorization: Bearer $AKV_TOKEN" "$CUR_URL")
    if printf '%%s' "$RESP" | grep -q '"error"[[:space:]]*:'; then
      printf '%%s' "$RESP"
      exit 0
    fi
    INNER=$(printf '%%s' "$RESP" | sed -n 's/.*"value"[[:space:]]*:[[:space:]]*\[\(.*\)\]\(,"nextLink".*\)*}.*/\1/p')
    if [ -n "$INNER" ]; then
      if [ -n "$ALL_ITEMS" ]; then
        ALL_ITEMS="$ALL_ITEMS, $INNER"
      else
        ALL_ITEMS="$INNER"
      fi
    fi
    CUR_URL=$(printf '%%s' "$RESP" | grep -o '"nextLink"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*"nextLink"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
  done
  printf '{"value":[%%s]}\n' "$ALL_ITEMS"
fi`,
			authScript,
			shellQuote(vaultURL),
		)

		resp = Response{
			Status: "needs_host_adapter",
			Data: map[string]interface{}{
				"operation": "hosts.exec",
				"host":      "localhost",
				"cmd":       paginationCmd,
			},
		}

	// -------------------------------------------------------------
	// 4. Create / Update Secret in Azure Key Vault (put_secret)
	// -------------------------------------------------------------
	case "put_secret", "vault.put_secret":
		var putReq struct {
			Config      Config            `json:"config"`
			Name        string            `json:"name"`
			Value       string            `json:"value"`
			ContentType string            `json:"content_type"`
			Tags        map[string]string `json:"tags"`
		}
		if err := json.Unmarshal(req.Payload, &putReq); err != nil {
			resp = Response{Status: "error", Error: "Payload inválido para criar segredo: " + err.Error()}
			break
		}
		defer wipeString(&putReq.Value)

		cfg := mergeWithPersistedConfig(&putReq.Config)
		secretName := strings.TrimSpace(putReq.Name)
		if secretName == "" {
			resp = Response{Status: "error", Error: "O nome do segredo é obrigatório."}
			break
		}
		if strings.TrimSpace(putReq.Value) == "" {
			resp = Response{Status: "error", Error: "O valor do segredo não pode ser vazio."}
			break
		}

		authScript, authErr := buildAuthTokenScript(&cfg)
		if authErr != nil {
			resp = Response{Status: "error", Error: authErr.Error()}
			break
		}

		bodyMap := map[string]interface{}{
			"value": putReq.Value,
		}
		if putReq.ContentType != "" {
			bodyMap["contentType"] = putReq.ContentType
		} else {
			bodyMap["contentType"] = "ssh-password"
		}
		if len(putReq.Tags) > 0 {
			bodyMap["tags"] = putReq.Tags
		}
		bodyJSON, _ := json.Marshal(bodyMap)
		b64Body := base64.StdEncoding.EncodeToString(bodyJSON)

		vaultURL := getVaultBaseURL(&cfg)
		targetURL := fmt.Sprintf("%s/secrets/%s?api-version=7.4", vaultURL, url.PathEscape(secretName))

		cmd := fmt.Sprintf("%s\nprintf '%%s' %s | base64 -d | curl -s -X PUT -H \"Authorization: Bearer $AKV_TOKEN\" -H 'Content-Type: application/json' --data-binary @- %s",
			authScript,
			shellQuote(b64Body),
			shellQuote(targetURL),
		)

		resp = Response{
			Status: "needs_host_adapter",
			Data: map[string]interface{}{
				"operation": "hosts.exec",
				"host":      "localhost",
				"cmd":       cmd,
			},
		}

	// -------------------------------------------------------------
	// 5. Just-In-Time (JIT) Secret Resolution / On-Demand Secret Fetch
	// -------------------------------------------------------------
	case "get_secret", "vault.get_secret", "credentials.resolve", "vault.resolve_secret":
		var resolveReq struct {
			Config          Config `json:"config"`
			ServerID        any    `json:"server_id"`
			ServerName      string `json:"server_name"`
			Hostname        string `json:"hostname"`
			HostURL         string `json:"host_url"`
			Username        string `json:"username"`
			SSHUser         string `json:"ssh_user"`
			SecretReference string `json:"secret_reference"`
			SecretName      string `json:"secret_name"`
			Name            string `json:"name"`
		}
		if err := json.Unmarshal(req.Payload, &resolveReq); err != nil {
			resp = Response{Status: "error", Error: "Invalid resolve payload: " + err.Error()}
			break
		}

		cfg := mergeWithPersistedConfig(&resolveReq.Config)
		serverIDStr := fmt.Sprintf("%v", resolveReq.ServerID)
		if resolveReq.ServerID == nil || serverIDStr == "<nil>" || serverIDStr == "0" {
			serverIDStr = ""
		}

		hostname := resolveReq.Hostname
		if hostname == "" && resolveReq.HostURL != "" {
			h := resolveReq.HostURL
			h = strings.TrimPrefix(h, "ssh://")
			if atIdx := strings.LastIndex(h, "@"); atIdx >= 0 {
				h = h[atIdx+1:]
			}
			if colIdx := strings.Index(h, ":"); colIdx >= 0 {
				h = h[:colIdx]
			}
			hostname = h
		}
		if hostname == "" {
			hostname = resolveReq.ServerName
		}

		secretName := strings.TrimSpace(resolveReq.SecretName)
		if secretName == "" {
			secretName = strings.TrimSpace(resolveReq.Name)
		}
		if secretName == "" {
			secretName = strings.TrimSpace(resolveReq.SecretReference)
		}
		if secretName == "" {
			secretName = resolveSecretName(&cfg, serverIDStr, hostname)
		}
		if strings.Contains(secretName, "/secrets/") {
			parts := strings.Split(secretName, "/secrets/")
			secretName = parts[len(parts)-1]
		}

		if secretName == "" {
			resp = Response{
				Status: "error",
				Error:  fmt.Sprintf("Nenhum secret especificado ou vinculado ao servidor '%s'.", hostname),
			}
			break
		}

		authScript, authErr := buildAuthTokenScript(&cfg)
		if authErr != nil {
			resp = Response{Status: "error", Error: authErr.Error()}
			break
		}

		vaultURL := getVaultBaseURL(&cfg)
		targetURL := fmt.Sprintf("%s/secrets/%s?api-version=7.4", vaultURL, url.PathEscape(secretName))

		cmd := fmt.Sprintf("%s\ncurl -s -H \"Authorization: Bearer $AKV_TOKEN\" %s",
			authScript,
			shellQuote(targetURL),
		)

		resp = Response{
			Status: "needs_host_adapter",
			Data: map[string]interface{}{
				"operation": "hosts.exec",
				"host":      "localhost",
				"cmd":       cmd,
			},
		}

	default:
		resp = Response{
			Status: "error",
			Error:  fmt.Sprintf("Ação desconhecida: %s", req.Action),
		}
	}

	out, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(out)
}
