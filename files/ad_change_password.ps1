#Requires -Version 7
<#
  Troca a senha do PROPRIO usuario no AD (change self-service, nao reset):
  bind com a senha atual e modify de unicodePwd (delete antiga + add nova) via LDAPS.
  Nao exige conta de servico com permissao de reset.

  Senhas:
    - preferencialmente via STDIN em JSON: {"old_password":"...","new_password":"..."}
    - alternativa para teste manual: AD_OLD_PASSWORD / AD_NEW_PASSWORD

  Saida (JSON): changed (bool), reason, error
    reason: OK | CANT_CHANGE | POLICY | INVALID_OLD_PASSWORD | UNWILLING | ERROR
      CANT_CHANGE = AD negou o direito "Change Password" ao usuario
                    ("O usuario nao pode alterar a senha").
      POLICY      = politica de senha recusou (idade minima, historico, complexidade).
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
    return [pscustomobject]@{ old_password = $env:AD_OLD_PASSWORD; new_password = $env:AD_NEW_PASSWORD }
}

function Escape-LdapFilter([string]$Value) {
    return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29')
}

function Get-ChangeFailure([int]$Code, [string]$Message) {
    switch ($Code) {
        50 { return @{ reason = 'CANT_CHANGE'; error = "AD negou a troca da propria senha (insufficientAccessRights). Verifique a opcao 'O usuario nao pode alterar a senha'. $Message" } }
        19 { return @{ reason = 'POLICY'; error = "Politica de senha do AD recusou a troca (idade minima, historico ou complexidade). $Message" } }
        53 { return @{ reason = 'UNWILLING'; error = "AD recusou a operacao (unwillingToPerform). $Message" } }
        49 { return @{ reason = 'INVALID_OLD_PASSWORD'; error = "Senha atual invalida. $Message" } }
        default { return @{ reason = 'ERROR'; error = "Erro LDAP $Code. $Message" } }
    }
}

$conn = $null
try {
    $secrets = Read-Secrets
    $oldPassword = $secrets.old_password
    $newPassword = $secrets.new_password
    if ([string]::IsNullOrEmpty($oldPassword) -or [string]::IsNullOrEmpty($newPassword)) {
        throw "Senha atual/nova nao informadas."
    }
    # O AD so aceita alteracao de unicodePwd sobre conexao criptografada.
    if ($UseSsl -ne 'true') {
        throw "Troca de senha exige LDAPS. Defina ldap_use_ssl=true."
    }

    Add-Type -AssemblyName System.DirectoryServices.Protocols | Out-Null

    $baseDn = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)
    $upn = if ($Username -like '*@*') { $Username } else { "$Username@$Domain" }
    $cred = New-Object System.Net.NetworkCredential($upn, $oldPassword)
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection(
        $identifier, $cred, [System.DirectoryServices.Protocols.AuthType]::Basic)
    $conn.SessionOptions.ProtocolVersion = 3
    $conn.SessionOptions.SecureSocketLayer = $true
    if ($IsWindows -and $ValidateCerts -ne 'true') {
        $conn.SessionOptions.VerifyServerCertificate = { param($c, $cert) return $true }
    }

    try {
        $conn.Bind()
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        $f = Get-ChangeFailure $_.Exception.ErrorCode $_.Exception.ServerErrorMessage
        Write-Result @{ changed = $false; reason = $f.reason; error = $f.error }
        exit 0
    }

    $filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$(Escape-LdapFilter $Username)))"
    $searchReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]::Subtree, [string[]]@('distinguishedName'))
    $searchResp = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($searchReq)
    if ($searchResp.Entries.Count -eq 0) { throw "Usuario '$Username' nao encontrado no dominio '$Domain'." }
    $userDn = $searchResp.Entries[0].DistinguishedName

    # unicodePwd: valor entre aspas, em UTF-16LE.
    $delMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
    $delMod.Name = 'unicodePwd'
    $delMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
    [void]$delMod.Add([System.Text.Encoding]::Unicode.GetBytes('"' + $oldPassword + '"'))

    $addMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
    $addMod.Name = 'unicodePwd'
    $addMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
    [void]$addMod.Add([System.Text.Encoding]::Unicode.GetBytes('"' + $newPassword + '"'))

    $modReq = New-Object System.DirectoryServices.Protocols.ModifyRequest
    $modReq.DistinguishedName = $userDn
    [void]$modReq.Modifications.Add($delMod)
    [void]$modReq.Modifications.Add($addMod)

    try {
        [void]$conn.SendRequest($modReq)
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        $resp = $_.Exception.Response
        $code = if ($null -ne $resp) { [int]$resp.ResultCode } else { -1 }
        $msg = if ($null -ne $resp) { $resp.ErrorMessage } else { $_.Exception.Message }
        $f = Get-ChangeFailure $code $msg
        Write-Result @{ changed = $false; reason = $f.reason; error = $f.error }
        exit 0
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        $f = Get-ChangeFailure $_.Exception.ErrorCode $_.Exception.ServerErrorMessage
        Write-Result @{ changed = $false; reason = $f.reason; error = $f.error }
        exit 0
    }

    Write-Result @{ changed = $true; reason = 'OK'; error = $null }
    exit 0
}
catch {
    Write-Result @{ changed = $false; reason = 'ERROR'; error = $_.Exception.Message }
    exit 0
}
finally {
    if ($null -ne $conn) { $conn.Dispose() }
}
