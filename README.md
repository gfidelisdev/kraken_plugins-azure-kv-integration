# Azure Key Vault Integration — Plugin para Kraken Admin Tool

Plugin oficial para o **Kraken Admin Tool** que integra a gestão de senhas e credenciais de acesso a servidores com o **Microsoft Azure Key Vault**, eliminando completamente a necessidade de persistir senhas em bancos de dados locais.

---

## 🔒 Princípios de Segurança

1. **Zero Local Database Persistence**:
   - As senhas dos servidores monitorados **NUNCA** são gravadas na base de dados SQLite/PostgreSQL local do Kraken, mesmo que criptografadas.
   - O Kraken mantém apenas o apontamento lógico (`server_id` ➔ `azure_secret_name`) ou resolve dinamicamente por convenção de hostname.

2. **Just-in-Time (JIT) Secret Resolution**:
   - Quando o Kraken precisa abrir uma sessão SSH ou despachar um comando administrativo para um servidor, o plugin intercepta o handshake através da permissão `credentials:resolve`.
   - O segredo é consultado em tempo real via API REST do Azure Key Vault.

3. **Memory Wiping (Zero Retention)**:
   - A credencial é entregue de forma efêmera (`ephemeral: true`) para o conector SSH e, em seguida, os buffers de memória no Go WASM e no host são sobrescritos com zeros (`wipeBytes`), evitando extrações de memória (*heap inspection*).

---

## 👤 Autenticação Microsoft & Gestão de Contas

O plugin verifica automaticamente o estado da sessão do usuário no Kraken:

1. **Detecção Automática da Sessão Kraken**:
   - Ao acessar o plugin, o sistema verifica se a conta conectada ao Kraken é uma **Conta Microsoft** (Microsoft Entra ID, Office 365, Outlook/Hotmail).
   - Se for, o plugin vincula e tenta utilizar essa identidade automaticamente para acessar o Azure Key Vault via SSO.

2. **Solicitação de Logon na Microsoft (para Sessões Locais/Não-Microsoft)**:
   - Caso o usuário tenha feito login no Kraken usando credenciais locais (`admin`) ou provedores que não sejam Microsoft, o plugin exibe um painel de onboarding orientando a realização do login.
   - O logon é feito via **Device Code Flow da Microsoft (RFC 8628)**:
     - O sistema exibe um código temporário e o endereço `https://microsoft.com/devicelogin`.
     - O usuário autoriza a conta Microsoft desejada no navegador sem sair do Kraken.

3. **Multi-Account (Adicionar Outra Conta Microsoft)**:
   - Mesmo que o usuário já esteja logado com uma conta Microsoft, o plugin oferece a ação **"➕ Conectar Outra Conta Microsoft"**.
   - Isso permite acessar cofres localizados em outros tenants ou sob contas corporativas/pessoais diferentes da usada no login do Kraken.
   - O usuário pode facilmente alternar entre as contas conectadas diretamente pela interface.

---

## 🚀 Métodos de Autenticação Suportados

| Modo | Descrição | Cenário Típico |
|---|---|---|
| **Conta Microsoft do Usuário (Recomendado)** | Utiliza a conta Microsoft da sessão do Kraken ou conta conectada via Device Login | Administradores acessando cofres com suas identidades individuais (RBAC delegado). |
| **Service Principal (Client Credentials)** | Utiliza `Tenant ID`, `Client ID` e `Client Secret` via OAuth2 v2.0 endpoint | Ambientes autônomos/headless, servidores fora do Azure ou pipelines automatizados. |
| **Azure Managed Identity** | Consulta o endpoint local de metadados da instância (IMDS: `http://169.254.169.254`) | Kraken instalado em Máquinas Virtuais (VMs), AKS (Kubernetes) ou Azure Container Instances. |
| **Azure CLI / Host Environment** | Utiliza o token ativo da sessão Azure CLI (`az account get-access-token`) ou variável `AZURE_ACCESS_TOKEN` | Ambientes de desenvolvimento local e laboratórios com login prévio via terminal. |

---

## 🔑 Permissões Necessárias no Azure (RBAC)

Para que a conta ou Service Principal consulte os segredos, é necessária a seguinte atribuição no Azure Key Vault:

- **Key Vault Secrets User** (Leitura de valores de segredos)
- Ou, em caso de políticas de acesso legadas (*Vault Access Policies*): Permissão de `Secret: Get, List`.

---

## 🛠️ Modos de Associação de Senhas (Bind)

### 1. Vínculo Manual Explícito (Server Tab)
- Ao acessar a tela de detalhes de qualquer servidor no Kraken, a aba **Azure Key Vault Bind** exibe os segredos disponíveis no cofre.
- Permite associar o servidor a um secret específico com um clique.

### 2. Convenção Automática por Hostname
- Servidores recém-cadastrados podem obter senhas automaticamente sem configuração manual.
- Padrão customizável: `srv-{hostname}-pwd` (ex: servidor `db01.prod.internal` busca o segredo `srv-db01-prod-internal-pwd`).
- Variáveis dinâmicas suportadas:
  - `{hostname}`: Hostname ou endereço do servidor (com pontos convertidos para hífens).
  - `{server_id}`: Identificador interno do servidor no Kraken.

---

## 📦 Instalação e Empacotamento

### Instalação Direta via Pasta
No Kraken, acesse **Configurações > Plugins > Instalar Plugin > Opção 3: Pasta Local Descompactada** e informe o caminho desta pasta:
```text
/home/gfidelis/Code/kraken-plugins/azure-kv-integration
```

### Empacotar como `.zip`
```bash
zip -r azure-kv-plugin.zip plugin.json README.md icon.svg frontend/ backend/
```
