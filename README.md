# FISTA SIGS - Sistema Integrado de Gestão Segura

Este protótipo funcional foi desenvolvido para demonstrar mecanismos críticos de segurança (Acessos, Logs e Backups) para a infraestrutura digital do FISTA. O sistema utiliza uma estética de **SOC (Security Operations Center)** para facilitar a monitorização em tempo real de eventos de segurança.

## 🚀 Funcionalidades Principais
- **Autenticação Multi-Fator (MFA/TOTP):** Proteção obrigatória para todos os utilizadores.
- **RBAC (Role-Based Access Control):** Controlo rigoroso de permissões por perfil.
- **Audit Stream Imutável:** Registo JSONL de todas as ações críticas para monitorização em tempo real.
- **Elevação de Privilégios:** Fluxo de pedido e aprovação justificado com expiração automática.
- **Vault Cifrado (Backups):** Cifragem AES (Fernet) de backups com verificação de integridade SHA-256.

## 🛠️ Instalação e Execução

### 1. Preparação do Ambiente
```powershell
# Criar ambiente virtual
python -m venv venv

# Ativar ambiente
venv\Scripts\activate

# Instalar dependências
pip install -r requirements.txt
```

### 2. Execução
```powershell
python app.py
```
**Nota Crítica:** No primeiro arranque (ou após apagar a `fista.db`), o terminal irá exibir os **MFA Secrets**. Tens de copiar estes códigos para um gerador como o [totp.app](https://totp.app/) para conseguires fazer login.

## 👥 Utilizadores de Teste (Demo)

| Username | Password | Role |
| :--- | :--- | :--- |
| `admin.it` | `PasswordForte123!` | ADMIN_IT (Acesso Total) |
| `developer.it` | `Developer123!` | ADMIN_IT (Acesso Total) |
| `operations.it` | `Operations123!` | STAFF_OPERACIONAL (Restrito) |
| `coordenacao` | `Coordenacao123!` | COORDENACAO (Gestor) |
| `backups.operator` | `Backups123!` | BACKUP_OPERATOR (Cofre) |

## 🧪 Testes Unitários
Para validar a integridade dos mecanismos de segurança (RBAC, Logs, Status Check), executa:
```powershell
python tests.py
```

## ⚠️ Limitações do Protótipo (Contexto Académico)
Como este sistema é um protótipo para fins de demonstração académica, possui as seguintes limitações:
1. **Simulação de Imutabilidade:** O ficheiro `audit.log.jsonl` é gerado em modo *append-only* pela aplicação. Num sistema real, deve ser protegido pelo SO (`chattr +a`) ou enviado para um servidor de logs remoto (Syslog/SIEM).
2. **Gestão de Chaves:** A chave de cifragem (`backup.key`) é guardada localmente. Em produção, deveria ser utilizado um HSM ou um serviço de gestão de chaves (como AWS KMS ou HashiCorp Vault).
3. **Persistência de Sessão:** A elevação de privilégios é imediata devido à verificação na DB em cada pedido, o que pode aumentar a carga na base de dados em sistemas de larga escala.
4. **MFA:** Utiliza o protocolo padrão TOTP. Não está integrado com serviços externos (Okta/Auth0) ou cartões físicos por razões de portabilidade do protótipo.
5. **Criptografia:** O backup é uma cópia cifrada do ficheiro SQLite. Em bases de dados de produção (PostgreSQL/MySQL), seriam utilizadas ferramentas nativas de *dump* com *streaming* de cifragem.

## 📂 Estrutura do Projeto
- `app.py`: Servidor central e lógica de segurança.
- `tests.py`: Bateria de testes de segurança.
- `audit.log.jsonl`: Registo histórico (gerado ao correr).
- `fista.db`: Base de dados local (gerada ao correr).
- `static/`: Estética SIGS/SOC (CSS).
- `templates/`: Interface web.
