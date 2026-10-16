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
    # Senhas antiga/nova chegam por variavel de ambiente (fora do argv).
    $oldPassword = $env:AD_OLD_PASSWORD
    $newPassword = $env:AD_NEW_PASSWORD
    if ([string]::IsNullOrEmpty($oldPassword) -or [string]::IsNullOrEmpty($newPassword)) {
        throw "AD_OLD_PASSWORD/AD_NEW_PASSWORD nao definidos no ambiente."
    }

    # O AD so aceita alteracao de senha (unicodePwd) sobre conexao criptografada.
    if (-not $useSslBool) {
        throw "Troca de senha exige conexao criptografada (LDAPS). Defina ldap_use_ssl=true."
    }

    Add-Type -AssemblyName System.DirectoryServices.Protocols | Out-Null

    $baseDn = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)

    # Bind como o proprio usuario com a senha ANTIGA: valida a senha atual e
    # habilita a troca self-service (change, nao reset).
    $upn = if ($Username -like '*@*') { $Username } else { "$Username@$Domain" }
    $cred = New-Object System.Net.NetworkCredential($upn, $oldPassword)
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection(
        $identifier,
        $cred,
        [System.DirectoryServices.Protocols.AuthType]::Basic
    )
    $conn.SessionOptions.ProtocolVersion = 3
    $conn.SessionOptions.SecureSocketLayer = $true
    if (-not $validateCertsBool) {
        $conn.SessionOptions.VerifyServerCertificate = { param($connection, $certificate) return $true }
    }

    try {
        $conn.Bind()
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        if ($_.Exception.ErrorCode -eq 49) {
            throw "Senha atual invalida para '$Username'."
        }
        throw
    }

    # Localizar o DN do usuario.
    $filter = "(&(objectClass=user)(sAMAccountName=$Username))"
    $searchReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $baseDn,
        $filter,
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        @('distinguishedName')
    )
    $searchResp = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($searchReq)
    if ($searchResp.Entries.Count -eq 0) {
        throw "Usuario '$Username' nao encontrado no dominio '$Domain'."
    }
    $userDn = $searchResp.Entries[0].DistinguishedName

    # Troca de senha = delete(senha antiga) + add(senha nova) em unicodePwd,
    # ambas em UTF-16LE entre aspas.
    $oldBytes = [System.Text.Encoding]::Unicode.GetBytes('"' + $oldPassword + '"')
    $newBytes = [System.Text.Encoding]::Unicode.GetBytes('"' + $newPassword + '"')

    $delMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
    $delMod.Name = 'unicodePwd'
    $delMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
    [void]$delMod.Add($oldBytes)

    $addMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
    $addMod.Name = 'unicodePwd'
    $addMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
    [void]$addMod.Add($newBytes)

    $modReq = New-Object System.DirectoryServices.Protocols.ModifyRequest
    $modReq.DistinguishedName = $userDn
    [void]$modReq.Modifications.Add($delMod)
    [void]$modReq.Modifications.Add($addMod)

    [void]$conn.SendRequest($modReq)

    Write-Result @{ changed = $true; error = $null }
    exit 0
}
catch {
    Write-Result @{ changed = $false; error = ($_.Exception.Message) }
    exit 0
}
finally {
    if ($null -ne $conn) { $conn.Dispose() }
}
