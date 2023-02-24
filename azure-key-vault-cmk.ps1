$InformationPreference = 'Continue'

# Base ciphertrust Url
function Get-CiphertrustApiUrl {
    return "https://the ciphertrust manager IP/api/v1/"
}

# Call the login endpoint of the Thales ciphertrust appliance
function Login-Ciphertrust {
    param (
        [Parameter(Mandatory=$true)]
        [string]$username,
        [Parameter(Mandatory=$true)]
        [securestring]$password
    )
    $uri = "$(Get-CiphertrustApiUrl)auth/tokens"

    $body = @{
        grant_type = "password"
        username = $username
        password = ($password | ConvertFrom-SecureString -AsPlainText)
    }

    $params = @{
        Method = "POST"
        Uri = $uri
        Body = $body | ConvertTo-Json
        ContentType = "application/json"
        UseBasicParsing = $true
        SkipCertificateCheck = $true
    }

    $response = Invoke-WebRequest @params

    $content = $response.Content | ConvertFrom-Json
    return @{
        access_token = $content.jwt
        refresh_token = $content.refresh_token
    }
}

# Use the refresh token to refresh the credentials and get a new access token from the ciphertrust appliance
function Refresh-CiphertrustAuthToken {
    param (
        [Parameter(Mandatory=$true)]
        [string]$refresh_token
    )
    $uri = "$(Get-CiphertrustApiUrl)auth/tokens"

    $body = @{
        grant_type = "refresh_token"
        refresh_token = $refresh_token
    }

    $params = @{
        Method = "POST"
        Uri = $uri
        Body = $body | ConvertTo-Json
        ContentType = "application/json"
        UseBasicParsing = $true
        SkipCertificateCheck = $true
    }

    $response = Invoke-WebRequest @params

    $content = $response.Content | ConvertFrom-Json
    return @{
        access_token = $content.jwt
        refresh_token = $refresh_token
    }
}

# Create a new RSA key in ciphertrust
function New-CiphertrustKey {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ckmKeyName,
        [Parameter(Mandatory=$true)]
        [int]$keyStrength,
        [Parameter(Mandatory=$true)]
        [string]$accessToken
    )
    $uri = "$(Get-CiphertrustApiUrl)vault/keys2"

    $body = @{
        name = $ckmKeyName
        algorithm = "RSA"
        size = $keyStrength
        usageMask = 60 # encrypt, decrypt, wrap, unwrap key usage
    }

    $params = @{
        Headers = @{ Authorization = "Bearer $($accessToken)" }
        ContentType = "application/json"
        Body = $body | ConvertTo-Json
        Method = "POST"
        Uri = $uri
        UseBasicParsing = $true
        SkipCertificateCheck = $true
    }

    $createdKey = Invoke-WebRequest @params
    return $createdKey | ConvertFrom-Json
}

# Function to get the key ID of a key stored in the ciphertrust appliance using the key name
function Get-CiphertrustKeyId {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ckmKeyName,
        [Parameter(Mandatory=$true)]
        [string]$accessToken
    )
    $uri = "$(Get-CiphertrustApiUrl)vault/keys2?name=$($ckmKeyName)"

    $params = @{
        Headers = @{
            Authorization = "Bearer $($accessToken)"
        }
        ContentType = "application/json"
        Method = "GET"
        Uri = $uri
        UseBasicParsing = $true
        SkipCertificateCheck = $true
    }

    $response = Invoke-WebRequest @params
    $keys = $response.Content | ConvertFrom-Json
    if ($keys.resources.count -gt 1)
    {
        Write-Warning "More than one key found with name $ckmKeyName, returning the first"
    }
    return $keys.resources[0]
}

# Function to get the private key of a key stored in the ciphertrust appliance, wrapped by another key
function Get-CiphertrustWrappedPrivateKey {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ckmKeyNameToWrap,
        [Parameter(Mandatory=$true)]
        [string]$wrapKeyId,
        [Parameter(Mandatory=$true)]
        [string]$accessToken
    )

    $keyInfo = Get-CiphertrustKeyId -ckmKeyName $ckmKeyNameToWrap -accessToken $token.access_token

    $uri = "$(Get-CiphertrustApiUrl)vault/keys2/$($keyInfo.id)/export"

    # Create the request for exporting the wrapped private key in compliance with AzKeyault's needs
    $body = @{
        format = "pkcs8"
        wrappingMethod = "encrypt"
        wrapKeyIDType= "id"
        wrapKeyName = $wrapKeyId
        wrappingEncryptionAlgo = "rsa/rsaaeskeywrappadding"
        wrapRSAAES = @{
            aesKeySize = 256
            padding = "oaep"
        };
        pemWrap = $false
    }

    $params = @{
        Headers = @{ Authorization = "Bearer $($accessToken)" }
        ContentType = "application/json"
        body = $body | ConvertTo-Json
        Method = "POST"
        Uri = $uri
        UseBasicParsing = $true
        SkipCertificateCheck = $true
    }

    $response = Invoke-WebRequest @params
    return $response.Content | ConvertFrom-Json
}

# Function for uploading the Azure key vault rsa-hsm public key to the ciphertrust appliance
function Import-CiphertrustPubKek {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ckmKeyName,
        [Parameter(Mandatory=$true)]
        [string]$pubKEK,
        [Parameter(Mandatory=$true)]
        [string]$accessToken
    )
    $uri = "$(Get-CiphertrustApiUrl)vault/keys2"

    $body = @{
        "algorithm" = "rsa";
        "format" = "pkcs8";
        "generateKeyId" = $true;
        "material" = $kekPubKey;
        "name" = $ckmKeyName;
        "objectType" = "Public Key";
        "unexportable" = $false;
        "usageMask" = 127
    }

    $params = @{
        Headers = @{
            Authorization = "Bearer $($accessToken)"
        }
        Body = $body | ConvertTo-Json
        ContentType = "application/json"
        Method = "POST"
        Uri = $uri
        UseBasicParsing = $true
        SkipCertificateCheck = $true
    }

    $response = Invoke-WebRequest @params
    return $response.Content | ConvertFrom-Json
}


# Set stuff up in Azure
$vaultName = "your premium key vault name"
$AzureKvKeyName = "the name of the key in the azure key vault"
$ckmKeyName = "the name of the key in the ciphertrust appliance. This is the secret key that will give you legal compliance"

$checkKekExistance = @{
    VaultName = $vaultName;
    Name = $AzureKvKeyName;
}

$kek = Get-AzKeyVaultKey @checkKekExistance

if ($null -eq $kek) {

    $createKekParams = @{
        VaultName = $vaultName;
        Name = $AzureKvKeyName;
        Destination = "HSM";
        Size = 2048;
        KeyOps = "import";
    }

    Add-AzKeyVaultKey @createKekParams
}

# Download PEM file
$getKekPublic = @{
    VaultName = $vaultName;
    Name = $AzureKvKeyName;
    OutFile = "$AzureKvKeyName.pem"
}

Get-AzKeyVaultKey @getKekPublic

# Log in to ciphertrust
$token = Login-Ciphertrust -username "admin" -password ("your password for the cipher trust manager" | ConvertTo-SecureString -AsPlainText -Force)

# If you need to refresh
# Refresh-CiphertrustAuthToken -refresh_token $token.refresh_token

$keyInfo = Get-CiphertrustKeyId -ckmKeyName $ckmKeyName -accessToken $token.access_token
if ($null -eq $keyInfo) {
    $keyInfo = New-CiphertrustKey -ckmKeyName $ckmKeyName -keyStrength 2048 -accessToken $token.access_token
}

$kekKeyInfo = Get-CiphertrustKeyId -ckmKeyName $AzureKvKeyName -accessToken $token.access_token
if ($null -eq $kekKeyInfo) {
    $kekPubKey = Get-Content "$AzureKvKeyName.pem" -Raw
    $kekKeyInfo = Import-CiphertrustPubKek -ckmKeyName $AzureKvKeyName -pubKEK $kekPubKey -accessToken $token.access_token
}

$wrapped = Get-CiphertrustWrappedPrivateKey -ckmKeyNameToWrap $ckmKeyName -wrapKeyId $kekKeyInfo.id -accessToken $token.access_token

$keyInfo = Get-AzKeyVaultKey -VaultName $vaultName -Name $AzureKvKeyName

$jwt_material = @{
    "schema_version" = "1.0.0";
    "header"= @{
      "kid" = $keyInfo.Id;
      "alg" = "dir";
      "enc" = "CKM_RSA_AES_KEY_WRAP";
    }
    "ciphertext" = $wrapped.material;
    "generator" = "Whatever you want to call this"
}

Write-Information "Removing old material byok file"
$filename = "my_kek_response_material.byok"
Remove-Item $filename -ErrorAction SilentlyContinue

Write-Information "Writing new byok file"
$jwt_material | ConvertTo-Json -Depth 10 | Out-File $filename

$byokParams = @{
    VaultName = $vaultName;
    Name = $AzureKvKeyName;
    KeyFilePath = $filename;
    Destination = 'HSM';
}

Add-AzKeyVaultKey @byokParams