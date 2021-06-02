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
    [switch]$CreateCSR, 
	[switch]$ImportCert,
	[string]$CSRfile = '',
	[string]$SignedCert = '',
    [switch]$Quiet
)

function GenerateCSRName {
    $CSRFileName=$('YHSM2-Sig1.' + (Get-Date -format 'yyyyMMdd_HHmmss') + '.csr')
    $CSRFullPath = Join-Path -Path $WorkDirectory -ChildPath $CSRFileName
    $i=0
    while (Test-Path $CSRFullPath -PathType leaf)
    {
        $i+=1
        $CSRFileName=$('YHSM2-Sig1.' + (Get-Date -format 'yyyyMMdd_HHmmss_') + $i + '.csr')
        $CSRFullPath = Join-Path -Path $WorkDirectory -ChildPath $CSRFileName
    }
    return $CSRFullPath
}

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
        $Password,
        $AuthKey_ID,
        $Key_ID
    )
    yubihsm-shell -p "$Password" --authkey=$AuthKey_ID -a delete-object -i $Key_ID -t opaque 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "DeleteOpaque" -ErrorCode $LASTEXITCODE 
    }
}

function PutOpaque {
    param (
        $Password,
        $AuthKey_ID,
        $Key_ID,
        $Key_Name,
        $Domains,
        $Infile
    )
    yubihsm-shell -p "$Password" --authkey=$AuthKey_ID -a put-opaque -i $Key_ID -d $Domains -l $Key_Name -A opaque-x509-certificate --in $Infile 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "PutOpaque" -ErrorCode $LASTEXITCODE 
    }
}

function SignAttestationCertificate {
    param (
        $Password,
        $AuthKey_ID,
        $Key_ID,
        $Outfile
    )
    yubihsm-shell -p "$Password" --authkey=$AuthKey_ID -a sign-attestation-certificate -i $KeyID --attestation-id 0 --out $Outfile 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "SignAttestationCertificate" -ErrorCode $LASTEXITCODE 
    }
}

function Cleanup {
    Remove-Item -Path "$TemplateCertPem" 2>&1 >> $null
    Remove-Item -Path "$TemplateCertDer" 2>&1 >> $null
    Remove-Item -Path "$SignedCertDer" 2>&1 >> $null
}

function GenerateKeyPair {
    param (
        $Password,
        $AuthKey_ID,
        $Algo,
        $Key_name,
        $Domains,
        $Key_ID
    )
    yubihsm-shell -p "$Password" --authkey=$AuthKey_ID -a generate-asymmetric-key -c sign-pkcs,sign-pss,sign-attestation-certificate -A $Algo -l $Key_name -d $Domains -i $Key_ID 2>&1 >> $Logfile
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "GenerateKeyPair" -ErrorCode $LASTEXITCODE 
    }
}

function CreateAndExportCSR {
    param (
        $KeyAlias,
        $CSRFile,
        $PKCS11ConfigFile,
        $StorePassword,
        $D_name
    )
    if ( $D_name -eq '' ) {
        keytool -certreq -alias "$KeyAlias" -sigalg SHA256withRSA -file "$CSRFile" -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerarg "$PKCS11ConfigFile" -storepass "$StorePassword" -v 2>&1 >> $Logfile
    } else {
        keytool -certreq -alias "$KeyAlias" -sigalg SHA256withRSA -file "$CSRFile" -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerarg "$PKCS11ConfigFile" -storepass "$StorePassword" -dname "$D_name" -v 2>&1 >> $Logfile
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
        $CAPrivateKeyPassword,
        $SignedCertFile
    )
    if ( '' -eq $CAPrivateKeyPassword ) {
        openssl x509 -req -in "$CSRFile" -CA "$CA_Cert" -CAkey "$CA_Key" -CAcreateserial -out "$SignedCertFile" -days 500 -sha256 2>&1 >> $Logfile
    } else {
        openssl x509 -req -in "$CSRFile" -CA "$CA_Cert" -CAkey "$CA_Key" -CAcreateserial -out "$SignedCertFile" -days 500 -sha256 -passin "pass:$CAPrivateKeyPassword" 2>&1 >> $Logfile
    }
    if( $LASTEXITCODE -ne 0 ) {
        PrintErrorAndExit -FunctionFailed "SignCertificate" -ErrorCode $LASTEXITCODE 
    }
}

$StorePW = $($AuthKeyID.Replace("0x","") + $AuthPW )
$TemplateCertPem = Join-Path -Path $WorkDirectory -ChildPath 'TemplateCert.pem'
$TemplateCertDer = Join-Path -Path $WorkDirectory -ChildPath 'TemplateCert.der'
$SignedCertPem = Join-Path -Path $WorkDirectory -ChildPath 'SignedCert.pem'
$SignedCertDer = Join-Path -Path $WorkDirectory -ChildPath 'SignedCert.der'
$PKCS11ConfFile = Join-Path -Path $WorkDirectory -ChildPath $PKCS11Config
$CACert = Join-Path -Path $WorkDirectory -ChildPath $CAcertificate
$CAKey = Join-Path -Path $WorkDirectory -ChildPath $CAPrivateKey 

if ( '' -eq $CSRfile ) {
    $CSR = GenerateCSRName
} else {
    $CSR = $CSRFile
}

if ( ($ImportCert -eq $true) -and ($CreateCSR -eq $true) ) {
	Write-Output "Can't use -ImportCert together with -CreateCSR"
	exit 1
}

if ( ($ImportCert -eq $true) -and ( '' -eq $SignedCert ) ) {
    Write-Output "-SignedCert is mandatory when using -ImportCert"
	exit 1
}

if ( $ImportCert -eq $true ) {
	$SignedCertPem=$SignedCert
	$SignedCertDer=$($SignedCert + ".der")
}

##### Main program #####
if ( $ImportCert -ne $true ) {
    # Add start date and time to the log file
    Write-Output "Started $((Get-Date).ToString())" 2>&1 >> $Logfile

    # Generate the RSA key-pair
    PrintMessages -Messages "Generate the RSA key-pair" -Silent $Quiet
    GenerateKeyPair -Password "$AuthPW" -AuthKey_ID "$AuthKeyID" -Algo "$Algorithm" -Key_name "$KeyName" -Domains "$Domain" -Key_ID "$KeyID"

    # Create a template certificate
    PrintMessages -Messages  "Creating a template certificate" -Silent $Quiet
    SignAttestationCertificate -Password "$AuthPW" -AuthKey_ID "$AuthKeyID" -Key_ID "$KeyID" -Outfile "$TemplateCertPem"

    # Convert to DER format
    PrintMessages -Messages "Convert template certificate to DER format" -Silent $Quiet
    ConvertToDER -Infile "$TemplateCertPem" -Outfile "$TemplateCertDer"

    # Import template certificate
    PrintMessages -Messages "Import template certificate" $Quiet
    PutOpaque -Password "$AuthPW" -AuthKey_ID "$AuthKeyID" -Key_ID "$KeyID" -Key_Name "$KeyName" -Domains "$Domain" -Infile "$TemplateCertDer"

    # Create and export the CSR
    PrintMessages -Messages  "Create and export a CSR" -Silent $Quiet
    CreateAndExportCSR -KeyAlias "$KeyName" -CSRFile "$CSR" -PKCS11ConfigFile "$PKCS11ConfFile" -StorePassword "$StorePW" -D_name "$Dname"
    PrintMessages -Messages "CSR saved to $CSR" -Silent $Quiet
    if ( "$createcsr" -eq $true ) {
        # Cleanup and exit
        Cleanup
        exit 0
    }

    # Sign the Java code signing certificate
    # This step uses OpenSSL CA as an example
    PrintMessages -Messages  "Sign the Java code signing certificate" -Silent $Quiet
    SignCertificate -CSRFile "$CSR" -CA_Cert "$CACert" -CA_Key "$CAKey" -SignedCertFile "$SignedCertPem" -CAPrivateKeyPassword "$CAPrivateKeyPW"
}

# Convert signed certificate to DER format
PrintMessages -Messages  "Convert signed certificate to DER format" -Silent $Quiet
ConvertToDER -Infile "$SignedCertPem" -Outfile "$SignedCertDer"

# Delete the template certificate on YubiHSM"
PrintMessages -Messages  "Delete the template certificate on YubiHSM" -Silent $Quiet
DeleteOpaque -Password "$AuthPW" -AuthKey_ID "$AuthKeyID" -Key_ID "$KeyID"

# Import the Java code signing certificate
PrintMessages -Messages "Import the Java code signing certificate" -Silent $Quiet
PutOpaque -Password "$AuthPW" -AuthKey_ID "$AuthKeyID" -Key_ID "$KeyID" -Key_Name "$KeyName" -Domains "$Domain" -Infile "$SignedCertDer"

# Remove temporary files
PrintMessages -Messages "Remove temporary files" $Quiet

# Cleanup
Cleanup