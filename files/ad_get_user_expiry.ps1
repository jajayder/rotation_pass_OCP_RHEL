[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [Parameter(Mandatory=$true)]
    [string]$Server,

    [int]$Port = 636,

    # Strings "true"/"false" vindas do Ansible. Parametros [bool] com -File
    # sao perigosos: qualquer string nao-vazia vira $true. Por isso usamos string.
    [string]$UseSsl = 'true',

    [string]$ValidateCerts = 'false'
)

$ErrorActionPreference = 'Stop'

function Write-Result($obj) {
    Write-Output ($obj | ConvertTo-Json -Compress -Depth 6)
}

$useSslBool = ($UseSsl -eq 'true')
$validateCertsBool = ($ValidateCerts -eq 'true')
$conn = $null

try {
    $bindUser = $env:AD_BIND_USER
    $bindPassword = $env:AD_BIND_PASSWORD
    if ([string]::IsNullOrEmpty($bindUser) -or [string]::IsNullOrEmpty($bindPassword)) {
        throw "AD_BIND_USER/AD_BIND_PASSWORD nao definidos no ambiente."
    }

    Add-Type -AssemblyName System.DirectoryServices.Protocols | Out-Null

    # Base DN derivado do dominio: scl.corp -> DC=scl,DC=corp
    $baseDn = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','

    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)
    $cred = New-Object System.Net.NetworkCredential($bindUser, $bindPassword)
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection(
        $identifier,
        $cred,
        [System.DirectoryServices.Protocols.AuthType]::Basic
    )
    $conn.SessionOptions.ProtocolVersion = 3
    if ($useSslBool) {
        $conn.SessionOptions.SecureSocketLayer = $true
        if (-not $validateCertsBool) {
            $conn.SessionOptions.VerifyServerCertificate = { param($connection, $certificate) return $true }
        }
    }
    $conn.Bind()

    $attrs = @('msDS-UserPasswordExpiryTimeComputed', 'userAccountControl')
    $filter = "(&(objectClass=user)(sAMAccountName=$Username))"
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $baseDn,
        $filter,
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        $attrs
    )
    $resp = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($req)

    if ($resp.Entries.Count -eq 0) {
        throw "Usuario '$Username' nao encontrado no AD."
    }
    $entry = $resp.Entries[0]

    $uac = 0
    if ($entry.Attributes.Contains('userAccountControl')) {
        $uac = [int64]($entry.Attributes['userAccountControl'].GetValues([string])[0])
    }
    $ACCOUNTDISABLE = 0x0002
    $DONT_EXPIRE_PASSWORD = 0x10000

    if (($uac -band $ACCOUNTDISABLE) -ne 0) {
        Write-Result @{ status = 'AD_ACCOUNT_DISABLED'; days_remaining = 'N/A'; expiration_date = $null; error = $null }
        exit 0
    }

    if (($uac -band $DONT_EXPIRE_PASSWORD) -ne 0) {
        Write-Result @{ status = 'PASSWORD_NEVER_EXPIRES'; days_remaining = 'N/A'; expiration_date = $null; error = $null }
        exit 0
    }

    $rawExpiry = [int64]0
    if ($entry.Attributes.Contains('msDS-UserPasswordExpiryTimeComputed')) {
        $rawExpiry = [int64]($entry.Attributes['msDS-UserPasswordExpiryTimeComputed'].GetValues([string])[0])
    }

    # Valores especiais documentados pelo AD para ausencia/nao expiracao.
    if ($rawExpiry -eq 0) {
        Write-Result @{ status = 'PASSWORD_EXPIRED'; days_remaining = -1; expiration_date = $null; error = $null }
        exit 0
    }

    if ($rawExpiry -eq [int64]::MaxValue) {
        Write-Result @{ status = 'PASSWORD_NEVER_EXPIRES'; days_remaining = 'N/A'; expiration_date = $null; error = $null }
        exit 0
    }

    $expiry = [DateTime]::FromFileTime($rawExpiry)
    $now = Get-Date
    $secondsRemaining = ($expiry - $now).TotalSeconds
    $daysRemaining = [Math]::Floor($secondsRemaining / 86400)

    if ($secondsRemaining -lt 0) {
        $status = 'PASSWORD_EXPIRED'
    }
    elseif ($daysRemaining -le 10) {
        $status = 'ROTATE'
    }
    else {
        $status = 'NOT_DUE'
    }

    Write-Result @{
        status          = $status
        days_remaining  = [int]$daysRemaining
        expiration_date = $expiry.ToString('yyyy-MM-dd HH:mm:ss')
        error           = $null
    }
    exit 0
}
catch {
    Write-Result @{ status = 'AD_LOOKUP_FAILED'; days_remaining = 'N/A'; expiration_date = $null; error = ($_.Exception.Message) }
    exit 0
}
finally {
    if ($null -ne $conn) { $conn.Dispose() }
}
