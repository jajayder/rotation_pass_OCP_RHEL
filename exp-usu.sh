#!/bin/bash

DC="ocinfradcsp2.scl.corp"
BASE_DN="DC=scl,DC=corp"

USUARIO="$1"
SENHA_ATUAL="$2"

if [ -z "$USUARIO" ] || [ -z "$SENHA_ATUAL" ]; then
    echo "Uso: $0 <usuario> <senha_atual>"
    exit 1
fi

if ! klist >/dev/null 2>&1; then
    echo "Ticket Kerberos não encontrado."
    exit 1
fi

LDAP_RESULT=$(ldapsearch -LLL -Y GSSAPI \
  -H "ldap://${DC}" \
  -b "$BASE_DN" \
  "(sAMAccountName=${USUARIO})" \
  dn \
  pwdLastSet \
  msDS-UserPasswordExpiryTimeComputed 2>/dev/null)

USER_DN=$(echo "$LDAP_RESULT" | awk -F': ' '/^dn:/ {print $2}')
EXPIRA=$(echo "$LDAP_RESULT" | awk -F': ' '/msDS-UserPasswordExpiryTimeComputed/ {print $2}')

if [ -z "$USER_DN" ]; then
    echo "Usuário não encontrado."
    exit 1
fi

if [ -z "$EXPIRA" ]; then
    echo "Não foi possível obter a data de expiração."
    exit 1
fi

DIAS=$(python3 - <<EOF
from datetime import datetime, timezone, timedelta

v=int("$EXPIRA")

if v == 9223372036854775807:
    print(99999)
else:
    base=datetime(1601,1,1,tzinfo=timezone.utc)
    exp=base + timedelta(microseconds=v//10)
    agora=datetime.now().astimezone()
    print((exp.astimezone()-agora).days)
EOF
)

if [ "$DIAS" -lt 0 ]; then
    echo "Senha expirada, verifique!"
    exit 1
fi

if [ "$DIAS" -gt 10 ]; then
    echo "Dias restantes para expiração: $DIAS"
    exit 0
fi

echo "Senha expira em $DIAS dia(s)."
echo "Gerando nova senha..."

NOVA_SENHA=$(python3 - <<'EOF'
import secrets
import string

especiais='!@#%^&*_-+='

while True:
    senha = (
        secrets.choice(string.ascii_uppercase) +
        secrets.choice(string.ascii_lowercase) +
        secrets.choice(string.digits) +
        secrets.choice(especiais)
    )

    chars = string.ascii_letters + string.digits + especiais

    for _ in range(8):
        senha += secrets.choice(chars)

    senha = ''.join(secrets.SystemRandom().sample(senha, len(senha)))

    if len(senha) == 12:
        print(senha)
        break
EOF
)

OLD_B64=$(printf '"%s"' "$SENHA_ATUAL" | \
iconv -f UTF-8 -t UTF-16LE | base64 -w0)

NEW_B64=$(printf '"%s"' "$NOVA_SENHA" | \
iconv -f UTF-8 -t UTF-16LE | base64 -w0)

cat > /tmp/change-pass.ldif <<EOF
dn: $USER_DN
changetype: modify
delete: unicodePwd
unicodePwd:: $OLD_B64
-
add: unicodePwd
unicodePwd:: $NEW_B64
EOF

ldapmodify \
  -H "ldaps://${DC}:636" \
  -D "${USUARIO}@scl.corp" \
  -w "$SENHA_ATUAL" \
  -f /tmp/change-pass.ldif

RC=$?

rm -f /tmp/change-pass.ldif

if [ $RC -eq 0 ]; then
    echo
    echo "======================================="
    echo "SENHA ALTERADA COM SUCESSO"
    echo "======================================="
    echo "Usuário      : $USUARIO"
    echo "Dias Restantes: $DIAS"
    echo "Nova Senha   : $NOVA_SENHA"
else
    echo
    echo "Falha ao alterar a senha."
    exit 1
fi