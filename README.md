# aplic-user-password-rotation (AAP 2.7 / RHEL / openldap)

Automação de rotação das senhas dos `aplic-user-*` usados em Secrets dos clusters OpenShift.

## Fluxo

1. **Prepara o bastion RHEL (OCBASTIOCPD2)**: confere `ldapsearch`/`ldapmodify`/`python3` e
   copia o `files/ad_ldap.sh` para um diretório temporário privado (removido no final).
   **Não usa mais pwsh**: é o mesmo método do `exp-usu.sh` (openldap-clients).
2. **Tokens dos clusters**: lê a credencial do AAP com os tokens e associa cada token ao
   cluster pelo `label` definido em `vars/clusters.yml`. Cluster sem token entra no relatório.
3. **Descoberta**: lista todos os Secrets `Opaque` de todos os namespaces que tenham as chaves
   `username` e `password` com usuário começando por `aplic-user-`. O mesmo usuário pode
   aparecer em vários Secrets/clusters e é processado uma única vez.
4. **Consulta no AD** (bind de leitura com `ad_user`/`ad_pass`): data de expiração da senha e
   se a opção *"O usuário não pode alterar a senha"* está ativa.
5. **Regra**:

   | Situação no AD | Ação |
   |---|---|
   | senha expirada | não altera, **alerta para troca manual** |
   | vence em 0..10 dias | **troca automática** |
   | vence em mais de 10 dias | não altera |
   | "nunca expira" / conta desabilitada | não altera, informa |
   | vence em até 10 dias, mas o usuário **não pode trocar a senha** | não altera, **alerta para troca manual** |

6. **Troca** (sem conta de serviço com permissão de reset): valida as senhas encontradas
   nos Secrets fazendo bind como o próprio usuário. Com a senha válida, faz a **troca
   self-service** (`unicodePwd` delete antiga + add nova, via LDAPS). Se o AD negar a troca
   (`insufficientAccessRights`), o status é *USUÁRIO NÃO PODE TROCAR A SENHA*.
7. **Secrets**: antes da troca no AD, a senha nova é **pré-gravada** em
   `data.password-pendente` de todos os Secrets do usuário. Após a troca, `data.password` é
   atualizado e a chave pendente removida (JSON Patch, 3 tentativas). Se o AD recusar a troca,
   a pendência é removida. Se a execução cair no meio, a próxima execução encontra a
   pendência, valida no AD e **conclui sozinha** (status *ATUALIZADO (troca anterior concluída)*).
8. **E-mail**: clusters consultados, usuários encontrados e onde estão, usuários alterados e
   a lista de **ação manual** (expiradas, não pode trocar, senha não confere, bloqueio, falhas).
   O assunto ganha `- ACAO MANUAL NECESSARIA` quando há pendências.

## Credenciais no AAP

| Variável | Origem | Uso |
|---|---|---|
| `ad_user` / `ad_pass` | credencial do AAP | SSH no bastion RHEL **e** bind LDAP de leitura no AD |
| `ocp_tokens` | credencial do AAP (tipo customizado) | tokens dos clusters, por label |

Formatos aceitos para `ocp_tokens` (objeto, lista ou o mesmo em texto JSON/YAML):

```yaml
ocp_tokens: {"OCPD2": "sha256~...", "OCPH2": "sha256~..."}
# ou
ocp_tokens: [{"label": "OCPD2", "token": "sha256~..."}, {"label": "OCPH2", "token": "sha256~..."}]
```

Se a credencial usar outro nome de variável, ajuste `ocp_tokens_var` em `group_vars/vars.yml`.
Os tokens **não são revogados** ao final da execução (são da credencial, e revogar quebraria
as próximas execuções).

Exemplo de *Credential Type* customizado:

```yaml
# Input configuration
fields:
  - id: ocp_tokens
    type: string
    label: Tokens OCP (JSON {"LABEL": "token"})
    secret: true
    multiline: true
required: [ocp_tokens]

# Injector configuration
extra_vars:
  ocp_tokens: '{{ ocp_tokens }}'
```

O token precisa permitir `list` de Secrets em todos os namespaces e `patch` nos Secrets.

## Pré-requisitos no bastion OCBASTIOCPD2

- `openldap-clients` (`ldapsearch`, `ldapmodify`) e `python3`: `dnf install openldap-clients python3`.
  `iconv`/`base64` já vêm no RHEL. **pwsh não é mais necessário.**
- Acesso ao DC via **LDAPS (636)**, obrigatório para a troca de senha. Por padrão usa o DC
  fixo `ocinfradcsp2.scl.corp` (`ldap_server`), o mesmo do `exp-usu.sh`.
- Acesso SMTP a partir do bastion (o e-mail sai dele) e `python3.12` (`mail_python_interpreter`).

No Linux, a validação do certificado LDAPS é controlada pela `libldap`:
`ldap_validate_certs: false` → `LDAPTLS_REQCERT=never`; `true` → exige a CA do AD no trust do
RHEL (`/etc/pki/ca-trust/source/anchors` + `update-ca-trust`).

## Segurança

- Senhas vão para o script por **STDIN** (JSON, dentro do payload do módulo, coberto por
  `no_log`), nunca no argv nem em variáveis de ambiente. No bastion, o `ad_ldap.sh` grava cada
  senha num arquivo `0600` em diretório `0700` na RAM (`/dev/shm`) e usa `ldap* -y <arquivo>`.
  O LDIF da troca vai por **pipe** (nunca em `/tmp`), e tudo é apagado na saída, mesmo em erro.
  O `exp-usu.sh` original expunha as senhas no `ps` (`$1/$2`, `ldapmodify -w`), gravava
  `/tmp/change-pass.ldif` e imprimia a senha nova.
- Loops nunca iteram sobre listas com senha: o Ansible imprime o item do loop a partir de `-v`
  (até em tasks puladas). Testado com `-vvv`: nenhuma senha no log nem no e-mail.
- A senha nova é pré-gravada no Secret antes de valer no AD (ver Fluxo, item 7).
- Para proteger contra bloqueio de conta, são testadas no máximo `max_password_candidates`
  (padrão 3) senhas distintas por usuário, das mais repetidas nos Secrets para as menos
  repetidas, parando na primeira válida.
- O relatório nunca contém senha. `rotation_debug: true` mostra o retorno dos scripts
  (status/erros, sem senhas).

## Atenção: `SECRET_UPDATE_FAILED` / resultado incerto

Se a senha foi trocada no AD e algum Secret falhou ao atualizar (mesmo após 3 tentativas), o
relatório marca **FALHA AO ATUALIZAR SECRET**. A senha nova está preservada em
`data.password-pendente`: **reexecute o job** e ele conclui automaticamente. O mesmo vale para
timeout durante o `ldapmodify` (*resultado incerto*): a pendência é mantida e a próxima execução
descobre se a troca foi aplicada.

## Teste manual do script no bastion

```bash
export AD_DOMAIN=scl.corp AD_SERVER=ocinfradcsp2.scl.corp LDAPTLS_REQCERT=never
read -rs P   # digite a senha (não fica no histórico nem no ps)
printf '{"bind_user":"SEU_USUARIO","bind_password":"%s"}' "$P" | ./files/ad_ldap.sh expiry aplic-user-exemplo
unset P
```
Modos: `expiry` (consulta), `validate` (`{"password": ...}`) e `change`
(`{"old_password": ..., "new_password": ...}`).

Saída esperada: uma linha JSON com `status`, `days_remaining`, `expiration_date` e `can_change`.

## Execução fora do AAP

```bash
ansible-galaxy collection install kubernetes.core community.general
ansible-playbook -i inventory/hosts.yml site.yml \
  -e ad_user=... -e ad_pass=... -e '{"ocp_tokens": {"OCPD2": "sha256~...", "OCPH2": "sha256~..."}}'
```
