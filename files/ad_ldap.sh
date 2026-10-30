#!/usr/bin/env bash
# =============================================================================
# ad_ldap.sh — Consulta/validação/troca de senha no AD direto no RHEL
#              (openldap-clients + python3). Substitui os .ps1/pwsh.
#
# Mesmo método do exp-usu.sh (ldapsearch + ldapmodify de unicodePwd via LDAPS)
# e mesmo contrato JSON dos antigos ad_get_user_expiry.ps1 /
# ad_validate_password.ps1 / ad_change_password.ps1.
#
# Uso:  ad_ldap.sh <modo> <usuario>       (segredos SEMPRE via stdin, em JSON)
#   expiry    stdin {"bind_user": "...", "bind_password": "..."}
#             -> {"status","days_remaining","expiration_date","can_change",
#                 "can_change_detail","error"}
#             status: ROTATE | NOT_DUE | PASSWORD_EXPIRED | PASSWORD_NEVER_EXPIRES |
#                     AD_ACCOUNT_DISABLED | AD_LOOKUP_FAILED
#   validate  stdin {"password": "..."}
#             -> {"valid","reason","error"}
#             reason: OK | INVALID | LOCKED | EXPIRED | MUST_CHANGE | DISABLED |
#                     ACCOUNT_EXPIRED | LOGON_RESTRICTED | ERROR
#   change    stdin {"old_password": "...", "new_password": "..."}
#             -> {"changed","reason","error","uncertain","verified"}
#             reason: OK | CANT_CHANGE | POLICY | INVALID_OLD_PASSWORD | UNWILLING | ERROR
#             uncertain=true: a falha aconteceu DURANTE o ldapmodify (timeout/rede);
#             a troca PODE ter sido aplicada no AD.
#
# Configuração (variáveis de ambiente, sem segredos):
#   AD_DOMAIN       obrigatório   ex.: scl.corp
#   AD_SERVER       obrigatório   ex.: ocinfradcsp2.scl.corp
#   AD_PORT         padrão 636
#   AD_USE_SSL      padrão true   (a troca exige LDAPS)
#   AD_BASE_DN      padrão derivado do domínio (DC=scl,DC=corp)
#   AD_TIMEOUT      padrão 20 (s)
#   AD_ROTATE_MIN / AD_ROTATE_MAX   janela de troca (padrão 0 / 10)
#   LDAPTLS_REQCERT / LDAPTLS_CACERT   validação do certificado (libldap)
#
# Segurança: senhas nunca vão em argv (ps/proc) — só stdin; o bind usa -y <arquivo>
# em diretório 0700 na RAM (/dev/shm) apagado na saída; o LDIF da troca vai por
# pipe. A saída nunca contém senha. Sempre sai com rc=0 e uma linha JSON
# (o playbook decide pelo conteúdo), exceto uso incorreto (rc=2).
# =============================================================================
set -uo pipefail
umask 077

MODO="${1:-}"
USUARIO="${2:-}"

# ----------------------------------------------------------------- saída JSON
# emit chave tipo:valor ...   (tipos: s=string i=int b=bool n=null)
emit() {
  python3 -I -c '
import sys, os, json
a = [os.fsencode(x).decode("utf-8", "replace") for x in sys.argv[1:]]
o = {}
for k, v in zip(a[0::2], a[1::2]):
    t, _, val = v.partition(":")
    o[k] = None if t == "n" else (val == "true" if t == "b" else (int(val) if t == "i" else val))
sys.stdout.write(json.dumps(o) + "\n")
' "$@"
}

# Falha genérica no formato do modo atual
falha() {
  local msg="$1"
  case "$MODO" in
    expiry)   emit status s:AD_LOOKUP_FAILED days_remaining s:N/A expiration_date n: \
                   can_change n: can_change_detail n: error "s:$msg" ;;
    validate) emit valid b:false reason s:ERROR error "s:$msg" ;;
    change)   emit changed b:false reason s:ERROR error "s:$msg" uncertain b:false ;;
  esac
  exit 0
}

case "$MODO" in
  expiry|validate|change) ;;
  *) echo "Uso: $0 expiry|validate|change <usuario>  (segredos em JSON no stdin)" >&2; exit 2 ;;
esac

[[ "$USUARIO" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || falha "Nome de usuario invalido: use apenas sAMAccountName."
[[ -n "${AD_DOMAIN:-}" && -n "${AD_SERVER:-}" ]] || falha "AD_DOMAIN/AD_SERVER nao definidos."
for b in ldapsearch ldapmodify iconv base64 python3 mktemp; do
  command -v "$b" >/dev/null 2>&1 || falha "Comando ausente no bastion: $b (dnf install openldap-clients python3)."
done

AD_PORT="${AD_PORT:-636}"
AD_USE_SSL="${AD_USE_SSL:-true}"
AD_TIMEOUT="${AD_TIMEOUT:-20}"
AD_ROTATE_MIN="${AD_ROTATE_MIN:-0}"
AD_ROTATE_MAX="${AD_ROTATE_MAX:-10}"
if [[ -z "${AD_BASE_DN:-}" ]]; then
  AD_BASE_DN="DC=${AD_DOMAIN//./,DC=}"
fi
if [[ "$AD_USE_SSL" == "true" ]]; then URI="ldaps://${AD_SERVER}:${AD_PORT}"; else URI="ldap://${AD_SERVER}:${AD_PORT}"; fi
[[ "$MODO" == change && "$AD_USE_SSL" != "true" ]] && falha "Troca de senha exige LDAPS. Defina ldap_use_ssl=true."

# ------------------------------------------- diretório privado + limpeza
TMPBASE=/dev/shm
[[ -d "$TMPBASE" && -w "$TMPBASE" ]] || TMPBASE="${TMPDIR:-/tmp}"
TMPD="$(mktemp -d "$TMPBASE/adldap.XXXXXXXX")" || falha "Falha ao criar diretorio temporario."
limpar() {
  local f
  for f in "$TMPD"/*; do [[ -f "$f" ]] && : >"$f"; done
  rm -rf -- "$TMPD"
}
trap limpar EXIT
trap 'exit 130' INT TERM
ERR="$TMPD/err"

# ------------------------------------- segredos: JSON do stdin -> arquivos 0600
# (o valor nunca passa por argv nem por variável de ambiente)
le_segredos() {
  python3 -I -c '
import sys, json, os
try:
    d = json.loads(sys.stdin.read() or "{}")
except ValueError:
    sys.exit(3)
for k in sys.argv[2:]:
    v = d.get(k) or ""
    if not isinstance(v, str) or "\n" in v or "\r" in v:
        sys.exit(4)
    with open(os.path.join(sys.argv[1], k), "w", encoding="utf-8") as f:
        f.write(v)
' "$TMPD" "$@"
}

bind_name() { # UPN, DOMINIO\usuario ou sAMAccountName -> como o AD aceita no simple bind
  if [[ "$1" == *@* || "$1" == *\\* ]]; then printf '%s' "$1"; else printf '%s@%s' "$1" "$AD_DOMAIN"; fi
}

LDAP_OPTS=(-x -H "$URI" -o "nettimeout=${AD_TIMEOUT}")
detalhe_erro() { tr -s '\r\n\t' '   ' <"$ERR" 2>/dev/null | sed 's/^ *//; s/ *$//' | cut -c1-300; }

motivo_bind() { # sub-código "data XXX" do erro 49 -> reason (mesmo mapa do .ps1)
  case "$(detalhe_erro)" in
    *"data 52e"*|*"data 525"*) echo INVALID ;;
    *"data 775"*) echo LOCKED ;;
    *"data 532"*) echo EXPIRED ;;
    *"data 773"*) echo MUST_CHANGE ;;
    *"data 533"*) echo DISABLED ;;
    *"data 701"*) echo ACCOUNT_EXPIRED ;;
    *"data 530"*|*"data 531"*) echo LOGON_RESTRICTED ;;
    *) echo INVALID ;;
  esac
}

FILTRO="(&(objectCategory=person)(objectClass=user)(sAMAccountName=${USUARIO}))"

# =================================================================== expiry
if [[ "$MODO" == expiry ]]; then
  le_segredos bind_user bind_password || falha "JSON de entrada invalido."
  BIND_USER="$(<"$TMPD/bind_user")"
  [[ -n "$BIND_USER" && -s "$TMPD/bind_password" ]] || falha "Credencial de bind do AD nao informada (ad_user/ad_pass)."

  # nTSecurityDescriptor só com a DACL (controle SD_FLAGS=4), para detectar
  # "O usuario nao pode alterar a senha" sem exigir privilégio de leitura da SACL.
  busca() {
    ldapsearch "${LDAP_OPTS[@]}" -D "$(bind_name "$BIND_USER")" -y "$TMPD/bind_password" \
      -LLL -o ldif_wrap=no -b "$AD_BASE_DN" "$@" "$FILTRO" \
      msDS-UserPasswordExpiryTimeComputed userAccountControl nTSecurityDescriptor 2>"$ERR"
  }
  SAIDA="$(busca -E '1.2.840.113556.1.4.801=::MAMCAQQ=')"; RC=$?
  if [[ $RC -ne 0 ]] && grep -qi "extension" "$ERR"; then
    SAIDA="$(busca)"; RC=$?   # openldap antigo sem controle genérico
  fi
  if [[ $RC -ne 0 ]]; then
    falha "Falha no bind/consulta LDAP (rc=$RC): $(detalhe_erro)"
  fi

  printf '%s\n' "$SAIDA" | python3 -I -c '
import sys, json, base64, struct, uuid
from datetime import datetime, timezone, timedelta

rmin, rmax = int(sys.argv[1]), int(sys.argv[2])
dn = None; raw = None; uac = 0; sd = None
for l in sys.stdin.read().splitlines():
    k = l.lower()
    if dn is None and (l.startswith("dn: ") or l.startswith("dn:: ")):
        dn = l
    elif k.startswith("msds-userpasswordexpirytimecomputed: "):
        raw = int(l.split(": ", 1)[1])
    elif k.startswith("useraccountcontrol: "):
        uac = int(l.split(": ", 1)[1])
    elif k.startswith("ntsecuritydescriptor:: "):
        sd = base64.b64decode(l.split(":: ", 1)[1])

r = {"status": "AD_LOOKUP_FAILED", "days_remaining": "N/A", "expiration_date": None,
     "can_change": None, "can_change_detail": None, "error": None}

def fim():
    sys.stdout.write(json.dumps(r) + "\n"); sys.exit(0)

if dn is None:
    r["error"] = "Usuario %s nao encontrado no AD." % sys.argv[3]; fim()

# "User cannot change password" = ACE de NEGACAO (Everyone/SELF) no direito
# estendido Change Password (ab721a53-...). O bit PASSWD_CANT_CHANGE do UAC nao é gravado pelo AD.
def troca_negada(sd):
    alvo = uuid.UUID("ab721a53-1e2f-11d0-9819-00aa0040529b").bytes_le
    off = struct.unpack_from("<I", sd, 16)[0]
    if off == 0:
        return False
    n = struct.unpack_from("<H", sd, off + 4)[0]
    pos = off + 8
    for _ in range(n):
        tipo = sd[pos]; tam = struct.unpack_from("<H", sd, pos + 2)[0]
        if tipo == 0x06:  # ACCESS_DENIED_OBJECT_ACE
            flags = struct.unpack_from("<I", sd, pos + 8)[0]; p = pos + 12; obj = None
            if flags & 1: obj = sd[p:p + 16]; p += 16
            if flags & 2: p += 16
            rev, cnt = sd[p], sd[p + 1]
            auth = int.from_bytes(sd[p + 2:p + 8], "big")
            subs = [struct.unpack_from("<I", sd, p + 8 + 4 * i)[0] for i in range(cnt)]
            sid = "S-%d-%d" % (rev, auth) + "".join("-%d" % s for s in subs)
            if obj == alvo and sid in ("S-1-1-0", "S-1-5-10"):
                return True
        pos += tam
    return False

if sd:
    try:
        neg = troca_negada(sd)
        r["can_change"] = not neg
        if neg:
            r["can_change_detail"] = "Opcao \"O usuario nao pode alterar a senha\" ativa no AD."
    except Exception as e:
        r["can_change_detail"] = "Nao foi possivel interpretar a DACL: %s" % e
else:
    r["can_change_detail"] = "nTSecurityDescriptor nao retornado (sem permissao de leitura da DACL)."

if uac & 0x0002:
    r.update(status="AD_ACCOUNT_DISABLED", error="Conta desabilitada no AD."); fim()
if uac & 0x10000:
    r.update(status="PASSWORD_NEVER_EXPIRES", error="Conta com \"A senha nunca expira\"."); fim()
if raw is None:
    r["error"] = "AD nao retornou msDS-UserPasswordExpiryTimeComputed."; fim()
if raw >= 9223372036854775807:
    r.update(status="PASSWORD_NEVER_EXPIRES", error="Politica de senha sem expiracao."); fim()
if raw == 0:
    r.update(status="PASSWORD_EXPIRED", days_remaining=-1,
             error="Senha marcada para troca obrigatoria no proximo logon (pwdLastSet=0)."); fim()
try:
    exp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=raw // 10)
except OverflowError:
    r.update(status="PASSWORD_NEVER_EXPIRES", error="Data de expiracao fora do intervalo."); fim()
seg = (exp - datetime.now(timezone.utc)).total_seconds()
dias = int(seg // 86400)
r["days_remaining"] = dias
r["expiration_date"] = exp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
if seg < 0:
    r.update(status="PASSWORD_EXPIRED", error="Senha expirada em %s." % r["expiration_date"])
elif rmin <= dias <= rmax:
    r["status"] = "ROTATE"
else:
    r["status"] = "NOT_DUE"
fim()
' "$AD_ROTATE_MIN" "$AD_ROTATE_MAX" "$USUARIO" || falha "Falha ao interpretar o retorno do LDAP."
  exit 0
fi

# ================================================================= validate
if [[ "$MODO" == validate ]]; then
  le_segredos password || falha "JSON de entrada invalido."
  [[ -s "$TMPD/password" ]] || falha "Senha candidata nao informada."
  # Só o bind importa; a busca no rootDSE é mínima.
  ldapsearch "${LDAP_OPTS[@]}" -D "$(bind_name "$USUARIO")" -y "$TMPD/password" \
    -LLL -s base -b "" "(objectClass=*)" 1.1 >/dev/null 2>"$ERR"
  RC=$?
  if [[ $RC -eq 0 ]]; then
    emit valid b:true reason s:OK error n:
  elif [[ $RC -eq 49 ]]; then
    emit valid b:false reason "s:$(motivo_bind)" error n:
  else
    emit valid b:false reason s:ERROR error "s:Erro LDAP rc=$RC: $(detalhe_erro)"
  fi
  exit 0
fi

# =================================================================== change
le_segredos old_password new_password || falha "JSON de entrada invalido."
[[ -s "$TMPD/old_password" && -s "$TMPD/new_password" ]] || falha "Senha atual/nova nao informadas."
cmp -s "$TMPD/old_password" "$TMPD/new_password" && falha "Senha nova igual a atual."
UPN="$(bind_name "$USUARIO")"

motivo_troca() { # rc -> reason/mensagem (mesmo mapa do .ps1)
  case "$1" in
    50) echo "CANT_CHANGE|AD negou a troca da propria senha (insufficientAccessRights). Verifique a opcao 'O usuario nao pode alterar a senha'." ;;
    19) echo "POLICY|Politica de senha do AD recusou a troca (idade minima, historico ou complexidade)." ;;
    53) echo "UNWILLING|AD recusou a operacao (unwillingToPerform)." ;;
    49) echo "INVALID_OLD_PASSWORD|Senha atual invalida." ;;
    *)  echo "ERROR|Erro LDAP rc=$1." ;;
  esac
}

# 1) bind com a senha atual + DN do usuário (sempre em base64 -> "dn::" no LDIF)
SAIDA="$(ldapsearch "${LDAP_OPTS[@]}" -D "$UPN" -y "$TMPD/old_password" \
          -LLL -o ldif_wrap=no -b "$AD_BASE_DN" "$FILTRO" 1.1 2>"$ERR")"
RC=$?
if [[ $RC -ne 0 ]]; then
  IFS='|' read -r R M <<<"$(motivo_troca "$RC")"
  emit changed b:false reason "s:$R" error "s:$M $(detalhe_erro)" uncertain b:false
  exit 0
fi
DN_B64="$(printf '%s\n' "$SAIDA" | python3 -I -c '
import sys, base64
for l in sys.stdin.read().splitlines():
    if l.startswith("dn:: "): print(l[5:].strip()); break
    if l.startswith("dn: "): print(base64.b64encode(l[4:].strip().encode()).decode()); break
')"
[[ -n "$DN_B64" ]] || falha "Usuario $USUARIO nao encontrado em $AD_BASE_DN."

# 2) unicodePwd = "senha" em UTF-16LE, base64 (lido do arquivo; nada em argv)
OLD_B64="$( { printf '"'; cat "$TMPD/old_password"; printf '"'; } | iconv -f UTF-8 -t UTF-16LE | base64 -w0)" \
  || falha "Falha ao codificar a senha atual."
NEW_B64="$( { printf '"'; cat "$TMPD/new_password"; printf '"'; } | iconv -f UTF-8 -t UTF-16LE | base64 -w0)" \
  || falha "Falha ao codificar a senha nova."

# 3) troca self-service (delete antiga + add nova), LDIF por pipe
printf 'dn:: %s\nchangetype: modify\ndelete: unicodePwd\nunicodePwd:: %s\n-\nadd: unicodePwd\nunicodePwd:: %s\n-\n\n' \
       "$DN_B64" "$OLD_B64" "$NEW_B64" \
  | ldapmodify "${LDAP_OPTS[@]}" -D "$UPN" -y "$TMPD/old_password" >/dev/null 2>"$ERR"
RC=$?
OLD_B64=""; NEW_B64=""
if [[ $RC -ne 0 ]]; then
  IFS='|' read -r R M <<<"$(motivo_troca "$RC")"
  # rede/timeout durante o modify (-1/255) ou erro desconhecido: resultado incerto
  INCERTO=false; [[ "$R" == ERROR ]] && INCERTO=true
  emit changed b:false reason "s:$R" error "s:$M $(detalhe_erro)" uncertain "b:$INCERTO"
  exit 0
fi

# 4) confirmação: bind com a senha nova no mesmo DC
if ldapsearch "${LDAP_OPTS[@]}" -D "$UPN" -y "$TMPD/new_password" \
     -LLL -s base -b "" "(objectClass=*)" 1.1 >/dev/null 2>"$ERR"; then
  emit changed b:true reason s:OK error n: uncertain b:false verified b:true
else
  emit changed b:true reason s:OK error "s:Troca aceita, mas o bind de confirmacao falhou: $(detalhe_erro)" \
       uncertain b:false verified b:false
fi
exit 0
