# FISTA SIGS - Sistema Integrado de Gestão Segura

## 1. Introdução
O **FISTA SIGS** (Sistema Integrado de Gestão Segura) é uma solução de gestão de infraestrutura crítica desenhada para a mitigação de riscos operacionais e garantia da integridade de dados na organização FISTA. O protótipo implementa controlos de segurança multicamada, fundamentados no modelo de **Privilégio Mínimo** e em arquiteturas **Zero Trust**.

## 2. Pilares de Segurança Implementados

### 2.1. Autenticação e Gestão de Identidades (IAM)
- **MFA (Multi-Factor Authentication):** Implementação de protocolo TOTP (Time-based One-Time Password) via RFC 6238, garantindo que a comprometação de credenciais estáticas (password) não resulte em acesso não autorizado.
- **Revogação Imediata:** Mecanismo de verificação de estado de conta em tempo real (*request-time validation*), assegurando que a revogação de privilégios ou suspensão de conta tenha efeito imediato sobre sessões ativas.

### 2.2. Controlo de Acesso (RBAC & Elevation)
- **Role-Based Access Control (RBAC):** Definição estrita de matrizes de permissão por cargo, segregando funções administrativas, operacionais e de gestão de dados.
- **Just-In-Time Elevation:** Workflow de pedido de elevação de privilégios com obrigatoriedade de justificação de negócio e aprovação delegada, com expiração temporal automática (*TTL*) para evitar a acumulação de privilégios residuais.

### 2.3. Auditoria e Monitorização (Audit Trail)
- **Audit Logging Imutável:** Registo de eventos críticos em formato JSONL (*Append-only*), capturando metadados como timestamps (UTC), origem de rede (IP), ator, ação e resultado da operação.
- **Interface SIGS Console:** Painel de monitorização para visualização de métricas de segurança e fluxo de eventos em tempo real.

### 2.4. Proteção de Dados (Data-at-Rest)
- **Vaulting & Cifragem:** Procedimentos de backup cifrados com algoritmo **AES-256 (Fernet)**. 
- **Verificação de Integridade:** Geração e validação de hashes criptográficas **SHA-256** para cada volume de backup, prevenindo a adulteração de dados ou ataques de substituição de ficheiros.

## 3. Ambiente Operacional e Deployment

### 3.1. Requisitos de Sistema
- Python 3.x
- Bibliotecas: Flask, bcrypt, pyotp, cryptography, sqlite3.

### 3.2. Procedimento de Instalação e Execução
Para executar o protótipo, siga os passos abaixo no terminal:

```powershell
# Clonar o repositório
git clone https://github.com/IGE-123016/FISTA-SIGS
cd FISTA-SIGS

# Inicialização do Ambiente Virtual
python -m venv venv
.\venv\Scripts\activate

# Instalação de Dependências
pip install -r requirements.txt

# Execução do Servidor
py app.py
```

Após a execução, aceda no browser ao endereço indicado na CLI (geralmente `http://127.0.0.1:5000`). 

**Nota sobre MFA:** A autenticação requer o uso de uma ferramenta de terceiros (ex: [https://totp.app/](https://totp.app/)) para gerar as chaves de acesso dinâmicas, utilizando o código MFA (Secret) fornecido no terminal durante o arranque do sistema.

## 4. Credenciais de Teste e Provisionamento Inicial

| Username | Função (Role) | Perfil de Acesso |
| :--- | :--- | :--- |
| `admin.it` | ADMIN_IT | Administração Global e IAM |
| `developer.it` | ADMIN_IT | Administração Global e IAM |
| `operations.it` | STAFF_OPERACIONAL | Visualização Operacional Limitada |
| `coordenacao` | COORDENACAO | Aprovação de Pedidos e Gestão |
| `backups.operator`| BACKUP_OPERATOR | Gestão de Backups e Encriptação |

*Nota: Os segredos TOTP para aprovisionamento de autenticadores MFA são gerados dinamicamente e apresentados via stdout no primeiro arranque do sistema.*

## 5. Garantia de Qualidade e Conformidade
O sistema inclui uma bateria de testes automatizados para validação dos perímetros de segurança e lógica de controlo de acessos:
```powershell
python tests.py
```

## 6. Limitações Técnicas e Recomendações de Hardening
Para efeitos de implementação em ambiente de produção, devem considerar-se os seguintes pontos:
1. **Logs Remotos:** Implementar o envio de logs para um servidor centralizado (SIEM/Syslog) via TLS para evitar a eliminação local de provas em caso de comprometação do nó.
2. **Gestão de Segredos:** Migrar chaves de cifragem (`backup.key`) e chaves de sessão para um serviço de KMS (*Key Management Service*) ou Vault dedicado.
3. **Comunicação Segura:** Obrigatória a utilização de TLS/SSL (HTTPS) em frente ao servidor WSGI para proteção de dados em trânsito.
4. **Imutabilidade de SO:** Recomenda-se a utilização de atributos de sistema de ficheiros (ex: `chattr +a` em Linux) para garantir a integridade física dos logs de auditoria.
