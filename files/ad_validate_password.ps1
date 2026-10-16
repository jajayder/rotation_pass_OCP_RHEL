[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [Parameter(Mandatory=$true)]
    [string]$Server,

    [int]$Port = 636,

    [string]$UseSsl = 'true',

    [string]$ValidateCerts = 'false'
)

$ErrorActionPreference = 'Stop'

function Write-Result($obj) {
    Write-Output ($obj | ConvertTo-Json -Compress -Depth 4)
}

$useSslBool = ($UseSsl -eq 'true')
$validateCertsBool = ($ValidateCerts -eq 'true')
$conn = $null

try {
    # A senha candidata chega por variavel de ambiente (fora do argv).
    $password = $env:AD_USER_PASSWORD
    if ([string]::IsNullOrEmpty($password)) {
        throw "AD_USER_PASSWORD nao definido no ambiente."
    }

    Add-Type -AssemblyName System.DirectoryServices.Protocols | Out-Null

    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)

    # Bind como o proprio usuario (UPN). Se o bind funciona, a senha e valida.
    $upn = if ($Username -like '*@*') { $Username } else { "$Username@$Domain" }
    $cred = New-Object System.Net.NetworkCredential($upn, $password)
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

    try {
        $conn.Bind()
        Write-Result @{ valid = $true; error = $null }
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        # 49 = invalidCredentials: senha simplesmente nao confere (nao e erro).
        if ($_.Exception.ErrorCode -eq 49) {
            Write-Result @{ valid = $false; error = $null }
        }
        else {
            Write-Result @{ valid = $false; error = ($_.Exception.Message) }
        }
    }
    exit 0
}
catch {
    Write-Result @{ valid = $false; error = ($_.Exception.Message) }
    exit 0
}
finally {
    if ($null -ne $conn) { $conn.Dispose() }
}
