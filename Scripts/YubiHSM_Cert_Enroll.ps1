param (
    [string]$Algorithm = 'RSA2048', 
    [string]$KeyID = '0x0002',    
    [string]$KeyName = 'MyKey1',
    [string]$WorkDirectory = (Get-Item .).FullName,
    [string]$Domain = '1', 
    [string]$AuthKeyID = '0x0001',
    [parameter(Mandatory=$true)]
    [string]$AuthPW = "",
    [string]$CAcertificate = 'TestCACert.pem',
    [string]$CAPrivateKey = 'TestCAKey.pem',
    [string]$CAPrivateKeyPW = '',
    [string]$PKCS11Config = 'sun_yubihsm2_pkcs11.conf',
    [string]$Dname = '',
    [string]$LogFile = (Join-Path -Path $WorkDirectory -ChildPath 'YubiHSM_PKCS11_Enroll.log'),
    [switch]$Quiet
)

[securestring]$SAuthPW = ConvertTo-SecureString $AuthPW -AsPlainText -Force
Remove-Variable AuthPW
if ($CAPrivateKeyPW -ne '') {
    [securestring]$SCAPrivateKeyPW=ConvertTo-SecureString $CAPrivateKeyPW -AsPlainText -Force
    Remove-Variable CAPrivateKeyPW
}
[securestring]$SStorePW = ConvertTo-SecureString $($AuthKeyID.Replace("0x","") + $(ConvertFrom-SecureString $SAuthPW -AsPlainText)) -AsPlainText -Force
$PEMext = '.pem'
$DERext = '.der'
$Template_cert = Join-Path -Path $WorkDirectory -ChildPath 'template_cert'
$SignedCert = Join-Path -Path $WorkDirectory -ChildPath 'Signed_cert'
$CSR = Join-Path -Path $WorkDirectory -ChildPath 'YHSM2-Sig1.csr'
$PKCS11ConfFile = Join-Path -Path $WorkDirectory -ChildPath $PKCS11Config
$CACert = Join-Path -Path $WorkDirectory -ChildPath $CAcertificate
$CAKey = Join-Path -Path $WorkDirectory -ChildPath $CAPrivateKey 

function PrintMessages {
    param (
        [String]$Messages,
        [bool]$Silent
    )
	if ( $Silent -eq $false ) {
        Write-Output $Messages    
    }
}

function PrintErrorAndExit {
    param (
        $FunctionFailed,
        $ErrorCode
    )
    Write-host -ForegroundColor Red "${FunctionFailed}: failed with exit code $ErrorCode"
    Write-host -ForegroundColor Red "See $logfile for more information"
    Cleanup
    exit 1
}

function ConvertToDER {
    param (
        $Infile,
        $Outfile
    )
    openssl x509 -in $Infile -out $Outfile -outform DER 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "ConvertToDER" -ErrorCode $LASTEXITCODE  
	    Write-Output "openssl: convert $Infile to DER format failed"
    }
}

function DeleteOpaque {
     param (
        [securestring]$Password,
        $AuthKey_ID,
        $Key_ID
    )
    yubihsm-shell -p $(ConvertFrom-SecureString $Password -AsPlainText) --authkey=$AuthKey_ID -a delete-object -i $Key_ID -t opaque 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "DeleteOpaque" -ErrorCode $LASTEXITCODE 
    }
}

function PutOpaque {
        param (
        [securestring]$Password,
        $AuthKey_ID,
        $Key_ID,
        $Key_Name,
        $Domains,
        $Infile
    )
    yubihsm-shell -p $(ConvertFrom-SecureString $Password -AsPlainText) --authkey=$AuthKey_ID -a put-opaque -i $Key_ID -d $Domains -l $Key_Name -A opaque-x509-certificate --in $Infile 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "PutOpaque" -ErrorCode $LASTEXITCODE 
    }
}

function SignAttestationCertificate {
    param (
        [securestring]$Password,
        $AuthKey_ID,
        $Key_ID,
        $Outfile
    )
    yubihsm-shell -p $(ConvertFrom-SecureString $Password -AsPlainText) --authkey=$AuthKey_ID -a sign-attestation-certificate -i $KeyID --attestation-id 0 --out $Outfile 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "SignAttestationCertificate" -ErrorCode $LASTEXITCODE 
    }
}

function Cleanup {
    Remove-Item -Path "$Template_cert$PEMext" 2>&1 >> $null
    Remove-Item -Path "$Template_cert$DERext" 2>&1 >> $null
    Remove-Item -Path "$SignedCert$PEMext" 2>&1 >> $null
    Remove-Item -Path "$SignedCert$DERext" 2>&1 >> $null
    Remove-Item -Path "$CSR" 2>&1 >> $null
}

function GenerateKeyPair {
    param (
        [securestring]$Password,
        $AuthKey_ID,
        $Algo,
        $Key_name,
        $Domains,
        $Key_ID
    )
    yubihsm-shell -p $(ConvertFrom-SecureString $Password -AsPlainText) --authkey=$AuthKey_ID -a generate-asymmetric-key -c sign-pkcs,sign-pss,sign-attestation-certificate -A $Algo -l $Key_name -d $Domains -i $Key_ID 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "GenerateKeyPair" -ErrorCode $LASTEXITCODE 
    }
}

function CreateAndExportCSR {
    param (
        $KeyAlias,
        $CSRFile,
        $PKCS11ConfigFile,
        [securestring]$StorePassword,
        $D_name
    )
    if ( $D_name -eq '') {
        keytool -certreq -alias "$KeyAlias" -sigalg SHA256withRSA -file "$CSRFile" -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerarg "$PKCS11ConfigFile" -storepass $(ConvertFrom-SecureString $StorePassword -AsPlainText) -v 2>&1 >> $Logfile
    } else {
        keytool -certreq -alias "$KeyAlias" -sigalg SHA256withRSA -file "$CSRFile" -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerarg "$PKCS11ConfigFile" -storepass $(ConvertFrom-SecureString $StorePassword -AsPlainText) -dname "$D_name" -v 2>&1 >> $Logfile
    }
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "CreateAndExportCSR" -ErrorCode $LASTEXITCODE 
    }
}

function SignCertificate {
    param (
        $CSRFile,
        $CA_Cert,
        $CA_Key,
        [securestring]$CAPrivateKeyPassword,
        $SignedCertFile
    )
    if ( $null -eq $CAPrivateKeyPassword) {
        openssl x509 -req -in "$CSRFile" -CA "$CA_Cert" -CAkey "$CA_Key" -CAcreateserial -out "$SignedCert$PEMext" -days 500 -sha256 2>&1 >> $Logfile
    } else {
        openssl x509 -req -in "$CSRFile" -CA "$CA_Cert" -CAkey "$CA_Key" -CAcreateserial -out "$SignedCert$PEMext" -days 500 -sha256 -passin "pass:$(ConvertFrom-SecureString $CAPrivateKeyPassword -AsPlainText)" 2>&1 >> $Logfile
    }
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "SignCertificate" -ErrorCode $LASTEXITCODE 
    }
}

##### Main program #####

# Add start date and time to the log file
Write-Output "Started $((Get-Date).ToString())" 2>&1 >> $Logfile

# Generate the RSA key-pair
PrintMessages -Messages "Generate the RSA key-pair" -Silent $Quiet
GenerateKeyPair -Password $SAuthPW -AuthKey_ID "$AuthKeyID" -Algo "$Algorithm" -Key_name "$KeyName" -Domains "$Domain" -Key_ID "$KeyID"

# Create a template certificate
PrintMessages -Messages  "Creating a template certificate" -Silent $Quiet
SignAttestationCertificate -Password $SAuthPW -AuthKey_ID "$AuthKeyID" -Key_ID "$KeyID" -Outfile "$Template_cert$PEMext"

# Convert to DER format
PrintMessages -Messages "Convert template certificate to DER format" -Silent $Quiet
ConvertToDER -Infile "$Template_cert$PEMext" -Outfile "$Template_cert$DERext"

# Import template certificate
PrintMessages -Messages "Import template certificate" $Quiet
PutOpaque -Password $SAuthPW -AuthKey_ID "$AuthKeyID" -Key_ID "$KeyID" -Key_Name "$KeyName" -Domains "$Domain" -Infile "$Template_cert$DERext"

# Create and export the CSR
PrintMessages -Messages  "Create and export a CSR" -Silent $Quiet
CreateAndExportCSR -KeyAlias "$KeyName" -CSRFile "$CSR" -PKCS11ConfigFile "$PKCS11ConfFile" -StorePassword $SStorePW -D_name "$Dname"

# Sign the Java code signing certificate
# This step uses OpenSSL CA as an example
PrintMessages -Messages  "Sign the Java code signing certificate" -Silent $Quiet
SignCertificate -CSRFile "$CSR" -CA_Cert "$CACert" -CA_Key "$CAKey" -SignedCertFile "$SignedCert$PEMext" -CAPrivateKeyPassword $SCAPrivateKeyPW

# Delete the template certificate on YubiHSM"
PrintMessages -Messages  "Delete the template certificate on YubiHSM" -Silent $Quiet
DeleteOpaque -Password $SAuthPW -AuthKey_ID "$AuthKeyID" -Key_ID "$KeyID"

# Convert signed certificate to DER format
PrintMessages -Messages  "Convert signed certificate to DER format" -Silent $Quiet
ConvertToDER -Infile "$SignedCert$PEMext" -Outfile "$SignedCert$DERext"

# Import the Java code signing certificate
PrintMessages -Messages "Import the Java code signing certificate" -Silent $Quiet
PutOpaque -Password $SAuthPW -AuthKey_ID "$AuthKeyID" -Key_ID "$KeyID" -Key_Name "$KeyName" -Domains "$Domain" -Infile "$SignedCert$DERext"

# Remove temporary files
PrintMessages -Messages "Remove temporary files" $Quiet
Cleanup 