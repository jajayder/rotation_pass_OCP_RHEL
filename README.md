# aplic-user-password-rotation (RHEL / pwsh)

Versão da automação que roda os scripts `.ps1` no **RHEL via `pwsh`** (PowerShell Core),
usando o bastion **OCBASTIOCPD2** no lugar do antigo host Windows `10.83.103.61`.

Descobre `aplic-user-*` em Secrets Opaque dos clusters OpenShift DEV/HMG, consulta a
expiração no AD, troca as senhas usando a senha atual capturada e atualiza somente
`data.password` de todos os Secrets do mesmo usuário.

## O que muda em relação à versão Windows/WinRM

No RHEL, com `pwsh`, **não existem** o módulo `ActiveDirectory` (`Get-ADUser`) nem o
namespace `System.DirectoryServices.AccountManagement` (`ValidateCredentials` /
`ChangePassword`) — ambos são Windows-only. Por isso:

- Os três `.ps1` foram reescritos sobre **LDAP** usando
  `System.DirectoryServices.Protocols`, que é cross-platform:
  - `ad_get_user_expiry.ps1` → busca LDAP de `msDS-UserPasswordExpiryTimeComputed` e
    `userAccountControl` (mesma regra de dias / never-expires / disabled).
  - `ad_validate_password.ps1` → bind LDAP como o próprio usuário com a senha candidata.
  - `ad_change_password.ps1` → `modify` de `unicodePwd` (delete antiga + add nova) sobre
    **LDAPS**, após bind com a senha antiga (troca self-service, não reset).
- `ansible.windows.win_powershell` foi trocado por `ansible.builtin.command: pwsh -File ...`.
- Os scripts devolvem **JSON** no stdout; o playbook faz `from_json`.
- Segredos (senhas, bind do AD) vão por **variável de ambiente**, nunca no argv.
- O inventário passou de WinRM/Kerberos para **SSH** no bastion RHEL.

## Requisitos

- AAP com Execution Environment contendo:
  - `kubernetes.core`, `community.okd`, `community.general`
  - Python Kubernetes client
- Bastion **OCBASTIOCPD2** (RHEL) com:
  - `pwsh` instalado (PowerShell 7+). Confirme o caminho em `pwsh_bin` (padrão `/usr/bin/pwsh`).
  - Acesso de rede ao AD via **LDAPS (porta 636)** — obrigatório para a troca de senha.
- Credencial **Machine** do AAP (SSH) para o OCBASTIOCPD2.
- Conta de serviço LDAP de **leitura** no AD para a consulta de expiração.
- SMTP acessível pelo Execution Environment.

## Survey / credenciais

Além do OCP, forneça a conta de serviço LDAP de leitura (não versione no Git):

```yaml
ocp_user: string
ocp_pass: string (senha)
ad_read_user: string            # ex.: svc-ldap-read@scl.corp
ad_read_pass: string (senha)
```

`ad_read_user`/`ad_read_pass` alimentam `ldap_bind_user`/`ldap_bind_password` em
`group_vars/vars.yml`. Validar e trocar senha usam a própria senha do usuário, não essa conta.

## Conexão LDAP (`group_vars/vars.yml`)

```yaml
ldap_server: "{{ ad_domain }}"   # FQDN de um DC ou o domínio (round-robin). Ex.: dc01.scl.corp
ldap_port: 636
ldap_use_ssl: true
ldap_validate_certs: false       # true + CA do AD no trust do RHEL para validar o certificado
```

## Regra de rotação

- `0..10` dias: troca automática.
- `< 0`: senha expirada, somente alerta.
- `> 10`: não altera.
- `PasswordNeverExpires=True` (ou conta desabilitada): ignora e alerta.
- Nenhuma senha dos Secrets válida no AD: `SENHA NÃO COMPATÍVEL`.

## Observação OpenShift

OpenShift usa OAuth2, então o projeto usa `community.okd.openshift_auth` para transformar
usuário/senha do Survey em token e usa esse token nas operações `kubernetes.core`.
As tarefas de OCP continuam com `delegate_to: localhost` (rodam no EE); apenas as tarefas
de AD rodam no bastion RHEL via `pwsh`.

## Segurança

Tarefas que manipulam senhas/tokens usam `no_log: true`. As senhas trafegam por variável de
ambiente para os scripts, fora da linha de comando. O relatório nunca contém senha.

## Execução

```bash
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventory/hosts.yml site.yml \
  -e ocp_user=... -e ocp_pass=... -e ad_read_user=... -e ad_read_pass=...
```

No AAP: aponte o Job Template para o projeto, use o Survey para `ocp_user`/`ocp_pass` e a
conta LDAP de leitura (`ad_read_user`/`ad_read_pass`), e anexe a credencial Machine (SSH)
do OCBASTIOCPD2.

## Teste rápido dos scripts no bastion

Dá para validar cada `.ps1` direto no OCBASTIOCPD2 (sem o Ansible):

```bash
export AD_BIND_USER='svc-ldap-read@scl.corp'
export AD_BIND_PASSWORD='***'
pwsh -NoProfile -File files/ad_get_user_expiry.ps1 \
  -Username aplic-user-exemplo -Domain scl.corp -Server dc01.scl.corp \
  -Port 636 -UseSsl true -ValidateCerts false
```

Deve imprimir uma linha JSON com `status`, `days_remaining` e `expiration_date`.
