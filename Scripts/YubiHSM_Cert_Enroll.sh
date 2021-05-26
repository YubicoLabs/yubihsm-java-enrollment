#!/bin/bash

##### Functions #####

usage () {
	echo "Syntax: `basename "$0"` [options]"
	echo "options:"
	echo "-k, --keyid                 Key ID for the new key [Default: 0x0002]" 
	echo "-n, --keyname               Name of the new key [Default: MyKey1]"
	echo "-d, --domain                Domain(s) for the new key [Default: 1]"
	echo "-a, --algorithm             Algorithm to use for the new key [Default: RSA2048]"
	echo "-i, --authkeyid             Key ID of the Authentication Key used [Default: 0x0001]"
	echo "-p, --authpassword          Password for the Authentication Key [Default: ]"
	echo "-c, --cacertificate         CA certificate to use [Default: ./TestCACert.pem]"
	echo "-s, --caprivatekey          Privet key for the CA certificate [Default: ./TestCAKey.pem]"
	echo "-r, --caprivatekeypw        Password for the CA certificate privet file [Default: ]"
	echo "-f, --pkcs11configfile      PKCS11 configuration file [Default: ./sun_yubihsm2_pkcs11.conf]"
	echo "-o, --dname                 X.500 Distinguished Name to be used as subject fields [Default: ]"
	echo "-t, --logfile               Log file path [Default: ./YubiHSM_PKCS11_Enroll.log"
	echo "-q, --quiet                 Suppress output"
	echo ""
	echo "  Example: `basename "$0"` -k 0x0002 -n MyKey -d 1 -a rsa2048 -i 0x0001 -p password -c ./rootCA-Cert.pem -s ./rootCA-Key.pem -f ./sun_yubihsm2_pkcs11.conf"
}


PrintMessages() {
	local msg="$1"
	local Silent="$2"
	if [ "$Silent" != true ] ; then
    	echo $msg
	fi
}

PrintErrorAndExit () {
	FunctionFailed="$1"
	ExitCode="$2"
	>&2 echo -e "\e[31m$FunctionFailed failed with exit code $ExitCode\e[39m"
	>&2 echo -e "\e[31mSee $LogFile for more information\e[39m"
	exit 1 
}

ConvertToDER () {
	local Infile="$1"
	local Outfile="$2"
	openssl x509 -in "$Infile" -out "$Outfile" -outform DER >> $LogFile 2>&1
	local ExitCode=$?
	if [ $ExitCode -ne 0 ]
	then
		PrintErrorAndExit "DeleteOpaque" $ExitCode
	fi
}

DeleteOpaque () {
	local Password="$1"
	local AuthKey_ID="$2"
	local Key_ID="$3"
	yubihsm-shell -p "$Password" --authkey="$AuthKey_ID" -a delete-object -i "$Key_ID" -t opaque >> $LogFile 2>&1
	local ExitCode=$?
	if [ $ExitCode -ne 0 ]
	then
		PrintErrorAndExit "DeleteOpaque" $ExitCode
	fi
}

PutOpaque () {
	local Password="$1"
	local AuthKey_ID="$2"
	local Key_ID="$3"
	local Key_Name="$4"
	local Domain="$5"
	local Infile="$6"
	yubihsm-shell -p "$Password" --authkey="$AuthKey_ID" -a put-opaque -i "$Key_ID" -d "$Domain" -l "$Key_Name" -A opaque-x509-certificate --in "$Infile" >> $LogFile 2>&1 
	local ExitCode=$?
	if [ $ExitCode -ne 0 ]
	then
		PrintErrorAndExit "PutOpaque" $ExitCode
	fi
}

SignAttestationCertificate () {
	local Password="$1"
	local AuthKey_ID="$2"
	local Key_ID="$3"
	local Outfile="$4"
	yubihsm-shell -p "$Password" --authkey="$AuthKey_ID" -a sign-attestation-certificate -i "$Key_ID" --attestation-id 0 --out "$Outfile" >> $LogFile 2>&1
	local ExitCode=$?
	if [ $ExitCode -ne 0 ]
	then
		PrintErrorAndExit "SignAttestationCertificate" $ExitCode   
	fi
}

GenerateKeyPair () {
	local Password="$1"
	local AuthKey_ID="$2"
	local Key_ID="$3"
	local Key_Name="$4"
	local Domain="$5"
	local Algorithm="$6"
	yubihsm-shell -p "$Password" --authkey="$AuthKey_ID" -a generate-asymmetric-key -c sign-pkcs,sign-pss,sign-attestation-certificate -A "$Algorithm" -l "$KeyName" -d "$Domain" -i "$KeyID" >> $LogFile 2>&1
	local ExitCode=$?
	if [ $ExitCode -ne 0 ]
	then
		PrintErrorAndExit "GenerateKeyPair" $ExitCode
	fi
}

CreateAndExportCSR () {
	local CSRFile="$1"
	local Key_Name="$2"
	local PKCS11Conf_File="$3"
	local Store_PW="$4"
	local D_name="$5"
	if [ -z "$D_name" ]
	then
		keytool -certreq -alias "$Key_Name" -sigalg SHA256withRSA -file "$CSRFile" -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerarg "$PKCS11Conf_File" -storepass "$Store_PW" -v >> $LogFile 2>&1
	else
		keytool -certreq -alias "$Key_Name" -sigalg SHA256withRSA -file "$CSRFile" -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerarg "$PKCS11Conf_File" -storepass "$Store_PW" -dname "$D_name" -v >> $LogFile 2>&1
	fi
	local ExitCode=$?
	if [ $ExitCode -ne 0 ]
	then
		PrintErrorAndExit "CreateAndExportCSR" $ExitCode
	fi
}

SignCertificate () {
	local CSRFile="$1"
	local CA_Cert="$2"
	local CA_Key="$3"
	local SignedCertFile="$4"
	if [ $# -lt 5 ]
	then
		local CAPrivateKey_PW=''
	else 
		local CAPrivateKey_PW="$5"
	fi
	if [ -z "$CAPrivateKeyPW" ]
	then
		  openssl x509 -req -in "$CSRFile" -CA "$CA_Cert" -CAkey "$CA_Key" -CAcreateserial -out "$SignedCertFile" -sha256 -days 365 >> $LogFile 2>&1
	else 
		  openssl x509 -req -in "$CSRFile" -CA "$CA_Cert" -CAkey "$CA_Key" -CAcreateserial -out "$SignedCertFile" -sha256 -passin pass:"$CAPrivateKey_PW" -days 365 >> $LogFile 2>&1
	fi
	local ExitCode=$?
	if [ $ExitCode -ne 0 ]
	then
		PrintErrorAndExit "SignCertificate" $ExitCode
	fi
}

Cleanup () {
	local Tempdir="$1"
	rm -R "$Tempdir" >> $LogFile 2>&1
	local ExitCode=$?
	if [ $ExitCode -ne 0 ]
	then
		PrintErrorAndExit "Cleanup" $ExitCode
	fi
}

# Load user defined parameters
while [[ $# > 0 ]]
do
	case "$1" in
    -k|--keyid)
		KeyID="$2"
		shift
		;;

	-n|--keyname)
		KeyName="$2"
		shift
		;;
			
    -d|--domain)
		Domain="$2"
		shift
		;;

	-a|--algorithm) 
		Algorithm="$2"
		shift
		;;            

	-i|--authkeyid) 
		AuthKeyID="$2"
		shift
		;;            

	-p|--authpassword)
		AuthPW="$2"
		shift
		;;            

	-c|--cacertificate)
		CACertificate="$2"
		shift
		;;
      
	-s|--caprivatekey)
		CAPrivateKey="$2"
		shift
		;;      

	-r|--caprivatekeypw)
		CAPrivateKeyPW="$2"
		shift
		;;
		
	-f|--pkcs11configfile)
		PKCS11ConfFile="$2"
		shift
		;; 

    -o|--dname)
		Dname="$2"
		shift
		;;    

    -q|--quiet)
		Quiet="true"
		;;
	
	-t|--logfile)
		LogFile="$2"
		shift
		;;
		
    *)
		usage
		exit 1
		;;
			
	esac
	shift
done

# Set default values if not defined by user parameters
KeyID="${KeyID:-0x0002}"
KeyName="${KeyName:-MyKey1}"
Domain="${Domain:-1}"
Algorithm="${Algorithm:-RSA2048}"
AuthKeyID="${AuthKeyID:-0x0001}"
AuthPW="${AuthPW:-}"
CACertificate="${CACertificate:-./TestCACert.pem}"
CAPrivateKey="${CAPrivateKey:-./TestCAKey.pem}"
PKCS11ConfFile="${PKCS11ConfFile:-./sun_yubihsm2_pkcs11.conf}"
CAPrivateKeyPW="${CAPrivateKeyPW:-}"
Dname="${Dname:-}"
LogFile="${LogFile:-./YubiHSM_PKCS11_Setup.log}"
Quiet="${Quiet:-false}"

# Work variables
temp_dir=$(mktemp -d)
TemplateCert=$(mktemp $temp_dir/TemplateCert.XXXXXXXXXXXX)
SignedCert=$(mktemp $temp_dir/SignedCert.XXXXXXXXXXXX)
PEMext='.pem'
DERext='.der'
StorePW=$(echo $AuthKeyID | sed 's/0x//')$AuthPW

CSR=$(pwd)/YHSM2-Sig.$(date "+%Y%m%d_%H%M%S").csr
i=0
while [ -f "$CSR" ]
do
	i+=1
	CSR=$(pwd)/YHSM2-Sig.$(date "+%Y%m%d_%H%M%S")_$i.csr
done

##### Main program #####

# Generate the RSA key-pair
PrintMessages "Generate key-pair" $Quiet
GenerateKeyPair "$AuthPW" "$AuthKeyID" "$KeyID" "$KeyName" "$Domain" "$Algorithm"

# Create a template certificate
PrintMessages "Creating a template certificate" $Quiet
SignAttestationCertificate "$AuthPW" "$AuthKeyID" "$KeyID" "$TemplateCert$PEMext"

# Convert to DER format
PrintMessages "Convert template certificate to DER format" $Quiet
ConvertToDER "$TemplateCert$PEMext" "$TemplateCert$DERext"

# Import template certificate
PrintMessages "Import template certificate" $Quiet
PutOpaque "$AuthPW" "$AuthKeyID" "$KeyID" "$KeyName" "$Domain" "$TemplateCert$DERext"

# Create and export the CSR
PrintMessages "Create and export a CSR" $Quiet
CreateAndExportCSR "$CSR" "$KeyName" "$PKCS11ConfFile" "$StorePW" "$Dname"
PrintMessages "CSR save to $CSR" $Quiet

# Sign the Java code signing certificate
# This step uses OpenSSL CA as an example
PrintMessages "Sign the Java code signing certificate" $Quiet
SignCertificate "$CSR" "$CACertificate" "$CAPrivateKey" "$SignedCert$PEMext" "$CAPrivateKeyPW"

# Convert signed certificate to DER format
PrintMessages "Convert signed certificate to DER format" $Quiet
ConvertToDER "$SignedCert$PEMext" "$SignedCert$DERext"

# Delete the template certificate  on YubiHSM"
PrintMessages "Delete the template certificate on YubiHSM" $Quiet
DeleteOpaque "$AuthPW" "$AuthKeyID" "$KeyID"

# Import the Java code signing certificate
PrintMessages "Import the Java code signing certificate" $Quiet
PutOpaque "$AuthPW" "$AuthKeyID" "$KeyID" "$KeyName" "$Domain" "$SignedCert$DERext"

# Remove temporary files
PrintMessages "Remove temporary files" $Quiet
Cleanup "$temp_dir"
