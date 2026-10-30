#Requires -Version 7
<#
  Consulta no AD (LDAP/LDAPS) a expiracao da senha de um usuario e se ele pode
  trocar a propria senha. Roda no RHEL via pwsh (System.DirectoryServices.Protocols).

  Credencial de bind (conta de leitura = ad_user/ad_pass do AAP):
    - preferencialmente via STDIN em JSON: {"bind_user":"...","bind_password":"..."}
    - alternativa para teste manual: variaveis AD_BIND_USER / AD_BIND_PASSWORD

  Saida: uma linha JSON no stdout com
    status          ROTATE | NOT_DUE | PASSWORD_EXPIRED | PASSWORD_NEVER_EXPIRES |
                    AD_ACCOUNT_DISABLED | AD_LOOKUP_FAILED
    days_remaining  inteiro ou 'N/A'
    expiration_date 'yyyy-MM-dd HH:mm:ss' ou null
    can_change      true | false | null (null = nao foi possivel determinar)
    error           mensagem ou null
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$Username,
    [Parameter(Mandatory = $true)] [string]$Domain,
    [Parameter(Mandatory = $true)] [string]$Server,
    [int]$Port = 636,
    # Strings "true"/"false": parametros [bool] com -File convertem qualquer texto em $true.
    [string]$UseSsl = 'true',
    [string]$ValidateCerts = 'false',
    [int]$RotateMinDays = 0,
    [int]$RotateMaxDays = 10
)

$ErrorActionPreference = 'Stop'

function Write-Result($obj) {
    Write-Output ($obj | ConvertTo-Json -Compress -Depth 6)
}

function Read-Secrets {
    if ([Console]::IsInputRedirected) {
        $raw = [Console]::In.ReadToEnd()
        if (-not [string]::IsNullOrWhiteSpace($raw)) { return ($raw | ConvertFrom-Json) }
    }
    return [pscustomobject]@{ bind_user = $env:AD_BIND_USER; bind_password = $env:AD_BIND_PASSWORD }
}

function ConvertTo-BindName([string]$User, [string]$Dom) {
    # Aceita UPN (user@dominio), DOMINIO\user ou apenas o sAMAccountName.
    if ($User -like '*@*' -or $User -like '*\*') { return $User }
    return "$User@$Dom"
}

function Escape-LdapFilter([string]$Value) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Value.ToCharArray()) {
        switch ($c) {
            '\' { [void]$sb.Append('\5c') }
            '*' { [void]$sb.Append('\2a') }
            '(' { [void]$sb.Append('\28') }
            ')' { [void]$sb.Append('\29') }
            ([char]0) { [void]$sb.Append('\00') }
            default { [void]$sb.Append($c) }
        }
    }
    return $sb.ToString()
}

# Parser binario da DACL (formato self-relative do Windows). As classes
# System.Security.AccessControl.* nao funcionam no Linux, por isso o parse manual.
function Test-ChangePasswordDenied([byte[]]$Sd) {
    $changePwdGuid = [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'
    $denySids = @('S-1-1-0', 'S-1-5-10')   # Everyone, SELF
    $daclOffset = [BitConverter]::ToUInt32($Sd, 16)
    if ($daclOffset -eq 0) { return $false }   # sem DACL
    $aceCount = [BitConverter]::ToUInt16($Sd, $daclOffset + 4)
    $pos = $daclOffset + 8
    for ($i = 0; $i -lt $aceCount; $i++) {
        $aceType = $Sd[$pos]
        $aceSize = [BitConverter]::ToUInt16($Sd, $pos + 2)
        if ($aceType -eq 0x06) {   # ACCESS_DENIED_OBJECT_ACE_TYPE
            $flags = [BitConverter]::ToUInt32($Sd, $pos + 8)
            $p = $pos + 12
            $objType = $null
            if ($flags -band 1) { $objType = [Guid]::new([byte[]]$Sd[$p..($p + 15)]); $p += 16 }
            if ($flags -band 2) { $p += 16 }
            # SID: rev(1) count(1) authority(6, big-endian) subauthorities(4 cada, little-endian)
            $subCount = $Sd[$p + 1]
            $auth = [uint64]0
            for ($k = 0; $k -lt 6; $k++) { $auth = ($auth -shl 8) + $Sd[$p + 2 + $k] }
            $subs = for ($k = 0; $k -lt $subCount; $k++) { [BitConverter]::ToUInt32($Sd, $p + 8 + 4 * $k) }
            $sid = "S-$($Sd[$p])-$auth" + $(if ($subCount -gt 0) { '-' + ($subs -join '-') } else { '' })
            if ($objType -eq $changePwdGuid -and $denySids -contains $sid) { return $true }
        }
        $pos += $aceSize
    }
    return $false
}

$result = [ordered]@{
    status = 'AD_LOOKUP_FAILED'; days_remaining = 'N/A'; expiration_date = $null
    can_change = $null; can_change_detail = $null; error = $null
}
$conn = $null

try {
    $secrets = Read-Secrets
    if ([string]::IsNullOrEmpty($secrets.bind_user) -or [string]::IsNullOrEmpty($secrets.bind_password)) {
        throw "Credencial de bind do AD nao informada (ad_user/ad_pass)."
    }

    Add-Type -AssemblyName System.DirectoryServices.Protocols | Out-Null

    $baseDn = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)
    $cred = New-Object System.Net.NetworkCredential((ConvertTo-BindName $secrets.bind_user $Domain), $secrets.bind_password)
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection(
        $identifier, $cred, [System.DirectoryServices.Protocols.AuthType]::Basic)
    $conn.SessionOptions.ProtocolVersion = 3
    if ($UseSsl -eq 'true') {
        $conn.SessionOptions.SecureSocketLayer = $true
        # No Linux a validacao do certificado e controlada pela libldap (LDAPTLS_REQCERT,
        # definido pelo playbook). O callback abaixo so e suportado no Windows.
        if ($IsWindows -and $ValidateCerts -ne 'true') {
            $conn.SessionOptions.VerifyServerCertificate = { param($c, $cert) return $true }
        }
    }
    $conn.Bind()

    $filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$(Escape-LdapFilter $Username)))"
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        [string[]]@('distinguishedName', 'msDS-UserPasswordExpiryTimeComputed', 'userAccountControl', 'pwdLastSet'))
    $resp = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($req)
    if ($resp.Entries.Count -eq 0) { throw "Usuario '$Username' nao encontrado no AD." }
    $entry = $resp.Entries[0]

    # ---- Pode trocar a propria senha? ("User cannot change password") ----
    # O flag PASSWD_CANT_CHANGE do userAccountControl NAO e gravado pelo AD; a opcao
    # e implementada por ACEs de NEGACAO (Everyone / SELF) no direito estendido
    # "Change Password" do objeto. Lemos apenas a DACL do nTSecurityDescriptor.
    try {
        $sdReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $entry.DistinguishedName, '(objectClass=*)',
            [System.DirectoryServices.Protocols.SearchScope]::Base, [string[]]@('nTSecurityDescriptor'))
        [void]$sdReq.Controls.Add((New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(
            [System.DirectoryServices.Protocols.SecurityMasks]::Dacl)))
        $sdResp = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($sdReq)
        $sdEntry = $sdResp.Entries[0]
        if ($sdEntry.Attributes.Contains('nTSecurityDescriptor')) {
            $bytes = [byte[]]($sdEntry.Attributes['nTSecurityDescriptor'].GetValues([byte[]])[0])
            $denied = Test-ChangePasswordDenied $bytes
            $result.can_change = -not $denied
            if ($denied) { $result.can_change_detail = "Opcao 'O usuario nao pode alterar a senha' ativa no AD." }
        }
        else {
            $result.can_change_detail = 'nTSecurityDescriptor nao retornado (sem permissao de leitura da DACL).'
        }
    }
    catch {
        $result.can_change_detail = "Nao foi possivel ler a DACL: $($_.Exception.Message)"
    }

    # ---- Expiracao ----
    $uac = 0
    if ($entry.Attributes.Contains('userAccountControl')) {
        $uac = [int64]($entry.Attributes['userAccountControl'].GetValues([string])[0])
    }
    $ACCOUNTDISABLE = 0x0002
    $DONT_EXPIRE_PASSWORD = 0x10000

    if (($uac -band $ACCOUNTDISABLE) -ne 0) {
        $result.status = 'AD_ACCOUNT_DISABLED'
        $result.error = 'Conta desabilitada no AD.'
        Write-Result $result; exit 0
    }
    if (($uac -band $DONT_EXPIRE_PASSWORD) -ne 0) {
        $result.status = 'PASSWORD_NEVER_EXPIRES'
        $result.error = "Conta com 'A senha nunca expira'."
        Write-Result $result; exit 0
    }

    $rawExpiry = [int64]0
    if ($entry.Attributes.Contains('msDS-UserPasswordExpiryTimeComputed')) {
        $rawExpiry = [int64]($entry.Attributes['msDS-UserPasswordExpiryTimeComputed'].GetValues([string])[0])
    }
    if ($rawExpiry -eq [int64]::MaxValue) {
        $result.status = 'PASSWORD_NEVER_EXPIRES'
        $result.error = 'Politica de senha sem expiracao.'
        Write-Result $result; exit 0
    }
    if ($rawExpiry -eq 0) {
        # pwdLastSet = 0: troca obrigatoria no proximo logon.
        $result.status = 'PASSWORD_EXPIRED'
        $result.days_remaining = -1
        $result.error = 'Senha marcada para troca obrigatoria no proximo logon (pwdLastSet=0).'
        Write-Result $result; exit 0
    }

    $expiry = [DateTime]::FromFileTime($rawExpiry)
    $secondsRemaining = ($expiry - (Get-Date)).TotalSeconds
    $daysRemaining = [int][Math]::Floor($secondsRemaining / 86400)

    $result.days_remaining = $daysRemaining
    $result.expiration_date = $expiry.ToString('yyyy-MM-dd HH:mm:ss')
    if ($secondsRemaining -lt 0) {
        $result.status = 'PASSWORD_EXPIRED'
        $result.error = "Senha expirada em $($result.expiration_date)."
    }
    elseif ($daysRemaining -ge $RotateMinDays -and $daysRemaining -le $RotateMaxDays) {
        $result.status = 'ROTATE'
    }
    else {
        $result.status = 'NOT_DUE'
    }
    Write-Result $result
    exit 0
}
catch {
    $result.status = 'AD_LOOKUP_FAILED'
    $result.error = $_.Exception.Message
    Write-Result $result
    exit 0
}
finally {
    if ($null -ne $conn) { $conn.Dispose() }
}
