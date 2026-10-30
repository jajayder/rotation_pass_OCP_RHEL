# aplic-user-password-rotation (AAP 2.7 / RHEL / pwsh)

Automação de rotação das senhas dos `aplic-user-*` usados em Secrets dos clusters OpenShift.

## Fluxo

1. **Prepara o bastion RHEL (OCBASTIOCPD2)**: copia os `.ps1` para um diretório temporário,
   confere o `pwsh` e se o .NET consegue carregar a `libldap` (ver "Pré-requisitos").
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
7. **Secrets**: após a troca no AD, atualiza somente `data.password` de **todos** os Secrets
   daquele usuário (JSON Patch, com 3 tentativas).
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

- `pwsh` 7.4+ (`pwsh_bin`, padrão `/usr/bin/pwsh`).
- Pacote `openldap` (libldap). O .NET do pwsh procura `libldap-2.5.so.0`, mas o RHEL 9
  traz `libldap.so.2`. **O playbook resolve isso sozinho e sem root**: cria o symlink no
  diretório temporário e usa `LD_LIBRARY_PATH`. A task "Verificar carregamento do LDAP no
  pwsh" falha cedo se isso não funcionar.
- Acesso ao AD via **LDAPS (636)**, obrigatório para a troca de senha.
- Acesso SMTP a partir do bastion (o e-mail sai dele) e `python3.12` (`mail_python_interpreter`).

No Linux, a validação do certificado LDAPS é controlada pela `libldap`:
`ldap_validate_certs: false` → `LDAPTLS_REQCERT=never`; `true` → exige a CA do AD no trust do
RHEL (`/etc/pki/ca-trust/source/anchors` + `update-ca-trust`).

## Segurança

- Senhas vão para os scripts por **STDIN** (dentro do payload do módulo, coberto por
  `no_log`), nunca no argv nem em variáveis de ambiente.
- Para proteger contra bloqueio de conta, são testadas no máximo `max_password_candidates`
  (padrão 3) senhas distintas por usuário, das mais repetidas nos Secrets para as menos
  repetidas, parando na primeira válida.
- O relatório nunca contém senha. `rotation_debug: true` mostra o retorno dos scripts
  (status/erros, sem senhas).

## Atenção: `SECRET_UPDATE_FAILED`

Se a senha foi trocada no AD e algum Secret falhou ao atualizar (mesmo após 3 tentativas), o
relatório marca **FALHA AO ATUALIZAR SECRET**. A nova senha só existe na execução, então a
correção é manual: redefinir a senha do usuário e atualizar o(s) Secret(s).

## Teste manual dos scripts no bastion

```bash
mkdir -p /tmp/ldapcompat && ln -sf /usr/lib64/libldap.so.2 /tmp/ldapcompat/libldap-2.5.so.0
export LD_LIBRARY_PATH=/tmp/ldapcompat LDAPTLS_REQCERT=never

echo '{"bind_user":"SEU_USUARIO","bind_password":"***"}' | \
  pwsh -NoProfile -File files/ad_get_user_expiry.ps1 \
    -Username aplic-user-exemplo -Domain scl.corp -Server scl.corp -Port 636
```

Saída esperada: uma linha JSON com `status`, `days_remaining`, `expiration_date` e `can_change`.

## Execução fora do AAP

```bash
ansible-galaxy collection install kubernetes.core community.okd community.general
ansible-playbook -i inventory/hosts.yml site.yml \
  -e ad_user=... -e ad_pass=... -e '{"ocp_tokens": {"OCPD2": "sha256~...", "OCPH2": "sha256~..."}}'
```
