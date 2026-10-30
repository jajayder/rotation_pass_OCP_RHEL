#Requires -Version 7
<#
  Valida uma senha candidata (vinda de um Secret) fazendo bind LDAP como o proprio usuario.

  Senha candidata:
    - preferencialmente via STDIN em JSON: {"password":"..."}
    - alternativa para teste manual: variavel AD_USER_PASSWORD

  Saida (JSON): valid (bool), reason, error
    reason: OK | INVALID | LOCKED | EXPIRED | MUST_CHANGE | DISABLED | ACCOUNT_EXPIRED |
            LOGON_RESTRICTED | ERROR
  Cada senha errada conta como tentativa invalida na politica de bloqueio do AD.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$Username,
    [Parameter(Mandatory = $true)] [string]$Domain,
    [Parameter(Mandatory = $true)] [string]$Server,
    [int]$Port = 636,
    [string]$UseSsl = 'true',
    [string]$ValidateCerts = 'false'
)

$ErrorActionPreference = 'Stop'

function Write-Result($obj) {
    Write-Output ($obj | ConvertTo-Json -Compress -Depth 4)
}

function Read-Secrets {
    if ([Console]::IsInputRedirected) {
        $raw = [Console]::In.ReadToEnd()
        if (-not [string]::IsNullOrWhiteSpace($raw)) { return ($raw | ConvertFrom-Json) }
    }
    return [pscustomobject]@{ password = $env:AD_USER_PASSWORD }
}

# Sub-codigos do AD retornados em "data XXX" no erro 49 (invalidCredentials).
function Get-AdBindReason([string]$ServerMessage) {
    if ($ServerMessage -match 'data\s+([0-9a-fA-F]+)') {
        switch ($Matches[1].ToLower()) {
            '52e' { return 'INVALID' }
            '525' { return 'INVALID' }          # usuario nao encontrado
            '775' { return 'LOCKED' }
            '532' { return 'EXPIRED' }
            '773' { return 'MUST_CHANGE' }
            '533' { return 'DISABLED' }
            '701' { return 'ACCOUNT_EXPIRED' }
            '530' { return 'LOGON_RESTRICTED' }
            '531' { return 'LOGON_RESTRICTED' }
        }
    }
    return 'INVALID'
}

$conn = $null
try {
    $password = (Read-Secrets).password
    if ([string]::IsNullOrEmpty($password)) { throw "Senha candidata nao informada." }

    Add-Type -AssemblyName System.DirectoryServices.Protocols | Out-Null

    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)
    $upn = if ($Username -like '*@*') { $Username } else { "$Username@$Domain" }
    $cred = New-Object System.Net.NetworkCredential($upn, $password)
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection(
        $identifier, $cred, [System.DirectoryServices.Protocols.AuthType]::Basic)
    $conn.SessionOptions.ProtocolVersion = 3
    if ($UseSsl -eq 'true') {
        $conn.SessionOptions.SecureSocketLayer = $true
        if ($IsWindows -and $ValidateCerts -ne 'true') {
            $conn.SessionOptions.VerifyServerCertificate = { param($c, $cert) return $true }
        }
    }

    try {
        $conn.Bind()
        Write-Result @{ valid = $true; reason = 'OK'; error = $null }
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        if ($_.Exception.ErrorCode -eq 49) {
            $reason = Get-AdBindReason $_.Exception.ServerErrorMessage
            # EXPIRED / MUST_CHANGE: a senha confere, mas o AD exige troca (nao e o fluxo
            # automatico: a regra manda alertar senha expirada).
            Write-Result @{ valid = $false; reason = $reason; error = $null }
        }
        else {
            Write-Result @{ valid = $false; reason = 'ERROR'; error = $_.Exception.Message }
        }
    }
    exit 0
}
catch {
    Write-Result @{ valid = $false; reason = 'ERROR'; error = $_.Exception.Message }
    exit 0
}
finally {
    if ($null -ne $conn) { $conn.Dispose() }
}
