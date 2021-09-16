Configuring YubiHSM 2 for Java code signing
===========================================

The purpose of the scripts in this repository is to generate an RSA keypair and enroll for an X.509 certificate to a YubiHSM 2 using YubiHSM-Shell as the primary software tool. In addition to YubiHSM-Shell, Java KeyTool and OpenSSL are used.

Two scripts are published in the folder Scripts: the Windows PowerShell script ``YubiHSM_Cert_Enroll.ps1`` and the Linux Bash script ``YubiHSM_Cert_Enroll.sh``.

When the RSA keypair and certificate have been enrolled to the YubiHSM 2, the YubiHSM 2 PKCS #11 library can then be used with the Sun JCE PKCS #11 Provider.

More specifically, the key/certificate can be used for signing Java code, for example using JarSigner.

The following steps are performed by the scripts:

1. Generate an RSA keypair in the YubiHSM 2.
2. Export the CSR (Certificate Signing Request).
3. Sign the CSR into an X.509 certificate (using OpenSSL CA as an example).
4. Import the signed X.509 certificate into the YubiHSM 2.

The scripts are not officially supported and are provided as-is. The scripts are intended as references, and YubiHSM 2 administrators should ensure to read Yubico's [documentation on managing YubiHSMs](https://developers.yubico.com/YubiHSM2/) before making any deployments in production.

Prerequisites
=============

Operating system and SDKs
-------------------------

Use a computer with Windows 10 or a Linux distribution as the operating system.

Attach the YubiHSM 2 device to one of the available USB ports on the computer.

Install the following software SDKs and tools:

* [YubiHSM SDK](https://developers.yubico.com/YubiHSM2/Releases/) (including YubiHSM-Setup, YubiHSM-Shell and YubiHSM-Connector)
* [OpenSSL](https://wiki.openssl.org/index.php/Binaries)
* [Java JDK](https://www.oracle.com/java/technologies/javase-downloads.html) (including KeyTool and JarSigner)

Basic configuration of YubiHSM 2
--------------------------------

Start the YubiHSM-Connector, either as a service or from a command prompt.

Launch the YubiHSM-Shell in a different command prompt, and run the following to make sure that the YubiHSM 2 is accessible:

```
yubihsm-shell
Using default connector URL: http://127.0.0.1:12345
yubihsm> connect
Session keepalive set up to run every 15 seconds
yubihsm> session open 1 password
Created session 0
yubihsm> list objects 0
Found 1 object(s)
id: 0x0001, type: authentication-key, sequence: 0
```

Configuration file for YubiHSM 2 PKCS #11
----------------------------------------

Create the configuration file ``yubihsm_pkcs11.conf`` and store it in the same folder as the ``yubihsm_pkcs11`` module (which is typically ``C:\Program Files\Yubico\YubiHSM Shell\bin\pkcs11\`` on Windows and ``/usr/lib64/pkcs11/`` on Linux).

Configure the ``yubihsm_pkcs11.conf`` according to the instructions on the [YubiHSM 2 PKCS #11 webpage](https://developers.yubico.com/YubiHSM2/Component_Reference/PKCS_11/). If the YubiHSM-Connector is running on the same machine, it is sufficient to copy the [YubiHSM 2 PKCS #11 configuration sample](https://developers.yubico.com/YubiHSM2/Component_Reference/PKCS_11/) and paste it into the file ``yubihsm_pkcs11.conf``.

Configuration file of Sun JCE PKCS #11 Provider with YubiHSM 2
--------------------------------------------------------------

Next, the YubiHSM 2 PKCS #11 module must be configured for use with the [Sun JCE PKCS #11 Provider](https://docs.oracle.com/javase/9/security/pkcs11-reference-guide1.htm#JSSEC-GUID-30E98B63-4910-40A1-A6DD-663EAF466991).

Create the configuration file ``sun_yubihsm2_pkcs11.conf`` with the following content:

```
name = yubihsm-pkcs11
library = C:\Program Files\Yubico\YubiHSM Shell\bin\pkcs11\yubihsm_pkcs11.dll
attributes(*, CKO_PRIVATE_KEY, CKK_RSA) = {
  CKA_SIGN=true
}
 ```

Environment variables
---------------------

The path to the YubiHSM PKCS #11 configuration file must be set in the [environment variables](https://developers.yubico.com/YubiHSM2/Component_Reference/PKCS_11/) for Windows and Linux:

YUBIHSM_PKCS11_CONF = ``<YubiHSM PKCS11 folder>/yubihsm_pkcs11.conf``

On Windows it is also recommended to add the following folder paths to the environment variable PATH:

```
‘C:\Program Files\Yubico\YubiHSM Shell\bin'
'C:\Program Files\OpenSSL-Win64\bin'
'C:\Program Files\Java\jdk-<version>\bin'
```

Java keystore
-------------

The Java keystore contains a number of pre-configured trusted CA-certificates. The Java signing certificate in the YubiHSM 2 will be validated against the trusted CA-certificates in the Java keystore.

It is therefore recommended to check that the CA-certificate(s) that have been used to issue the Java signing certificates are present in the Java keystore. This can be checked by running the following command:

``keytool -list -cacerts -storepass <password to Java keystore>``

If it is not present, add the CA-certificate(s) as trusted certificate(s) to the Java keystore. The Java tool KeyTool can be used for this purpose.

In order to update the Java keystore, start a console in elevated mode (“Run as administrator” on Windows or use “sudo” on Linux), and then run the commands below to import and verify the CA-certificate(s):

```
keytool -import -noprompt -cacerts -storepass <password to Java keystore> -alias <alias of the CA-cert> -file <path to the CA-certificate file>

keytool -list -cacerts -storepass <password to Java keystore> -alias <alias of the CA-cert>
```

Below are examples of the commands to import and verify the CA-certificate(s) are:

```
keytool -import -noprompt -cacerts -storepass changeit -alias MyCACert -file ./rootCACert.pem

keytool -list -cacerts -storepass changeit -alias MyCACert
```

Windows PowerShell script for generating keys and certificates
==============================================================

The PowerShell script ``YubiHSM_Cert_Enroll.ps1`` in the Scripts folder can be executed on Windows to generate an RSA keypair and enroll for an X.509 certificate to a YubiHSM 2.

YubiHSM-Shell is used in command-line mode. 

OpenSSL is used as a basic CA for test and demo purposes only. For real deployments, however, the OpenSSL CA should be replaced with a proper CA that signs the CSR into an X.509 certificate.

Parameters
----------

The PowerShell script has the following parameters:

* ``Algorithm`` - Signature algorithm [Default: RSA2048]
* ``KeyID`` - KeyID where the RSA keypair will be stored [Default: 0x0002]
* ``KeyName`` - Label of the key/certificate, same as Java Alias [Default: MyKey1]
* ``WorkDirectory`` - Working directory where the script is executed [Default: $PSScriptRoot]
* ``Domain`` - Domain in the YubiHSM 2 [Default: 1]
* ``AuthKeyID`` - KeyId of the YubiHSM 2 authentication key [Default: 0x0001]
* ``AuthPW`` - Password to the YubiHSM 2 authentication key [Default: ]
* ``CAcertificate`` - CA certificate used by OpenSSL (for test purposes) [Default: TestCACert.pem]
* ``CAPrivateKey`` - CA private key used by OpenSSL (for test purposes) [Default: TestCAKey.pem]
* ``CAPrivateKeyPW`` - Password of the OpenSSL keystore (for test purposes) [Default: ]
* ``PKCS11Config`` - Java JCE PKCS #11 configuration file [Default: ./sun_yubihsm2_pkcs11.conf]
* ``LogFile`` - Log file path [Default: ``WorkDirectory``/YubiHSM_PKCS11_Enroll.log]
* ``Dname`` - X.500 Distinguished Name to be used as subject fields [Default: ]
* ``CreateCSR`` - Generate keys and export CSR and then exit
* ``ImportCert`` - Import signed certificate created with ``CreateCSR``
* ``CSRfile`` - File to save the CSR request to [Default: ./YHSM2-Sig.(date and time).csr]
* ``SignedCert`` - Signed certificate file. [Default: ]
* ``Quiet`` - Suppress output

All parameters have default settings in the PowerShell script. The parameters can either be modified in the PowerShell script, or be used as input variables when executing the script.

Example of how to execute the PowerShell script:
------------------------------------------------

``$ .\YubiHSM_PKCS11_Setup.ps1 -KeyID 0x0003``

Linux Bash script for generating keys and certificates
======================================================

The Bash script ``YubiHSM_Cert_Enroll.sh`` in the Scripts folder can be executed on Linux to generate an RSA keypair and enroll for an X.509 certificate to a YubiHSM 2.

YubiHSM-Shell is used in command-line mode. 

OpenSSL is used as a basic CA for test and demo purposes only. For real deployments, however, the OpenSSL CA should be replaced with a proper CA that signs the CSR into an X.509 certificate.

Parameters
----------

The Bash script has the following parameters:

* ``-a, --algorithm`` - Signature algorithm [Default: RSA2048]
* ``-k, --keyid`` - KeyID where the RSA keypair will be stored [Default: 0x0002]
* ``-n, --keyname`` - Label of the key/certificate, same as Java Alias [Default: MyKey1]
* ``-d, --domain`` - Domain in the YubiHSM 2 [Default: 1]
* ``-i, --authkeyid`` - KeyId of the YubiHSM 2 authentication key [Default: 0x0001]
* ``-p, --authpassword`` - Password to the YubiHSM 2 authentication key [Default: ]
* ``-c, --cacertificate`` - CA certificate used by OpenSSL (for test purposes) [Default: ./TestCACert.pem]
* ``-s, --caprivatekey`` - CA private key used by OpenSSL (for test purposes) [Default: ./TestCAKey.pem]
* ``-r, --caprivatekeypw`` - Password of the OpenSSL keystore (for test purposes) [Default: ]
* ``-f, --pkcs11configfile`` - Java JCE PKCS #11 configuration file [Default: ./sun_yubihsm2_pkcs11.conf]
* ``-o, --dname`` - X.500 Distinguished Name to be used as subject fields [Default: ]
* ``-t, --logfile`` - Log file path [Default: ./YubiHSM_PKCS11_Enroll.log
* ``-q, --quiet`` - Suppress output
* ``-C, --createcsr`` - Generate keys and export CSR and then exit
* ``-I, --importcert`` - Import signed certificate created with --createcsr"
* ``-F, --csrfile`` - File to save the CSR request to [Default: ./YHSM2-Sig.(date and time).csr]"
* ``-S, --signedcert`` - Signed certificate file. Mandatory when using --importcert [Default: ]"

All parameters have default settings in the Bash script. The parameters can either be modified in the Bash  script, or be used as input variables when executing the script.

Example of how to execute the Bash script:
------------------------------------------

``$ ./YubiHSM_PKCS11_Setup.sh -k 0x0002 -n MyKey -d 1 -a rsa2048 -i 0x0001 -p password -c ./TestCACert.pem -s ./TestCAKey.pem -f ./sun_yubihsm2_pkcs11.conf``

List the objects on YubiHSM 2
=============================

The created RSA keypair and X.509 certificate can now be accessed through YubiHSM 2 PKCS11 and be used with Sun JCE PKCS11 Provider.

It is recommended to check that the RSA keypair and the X.509 certificate have been created on the YubiHSM 2. It is possible to use either YubiHSM-Shell or Java KeyTool to list and check those objects on the YubiHSM 2.

Example of YubiHSM-Shell command:
---------------------------------

```
yubihsm> list objects 0
Found 3 object(s)
id: 0x0001, type: authentication-key, sequence: 0
id: 0x0002, type: opaque, sequence: 1
id: 0x0002, type: asymmetric-key, sequence: 0
yubihsm> get objectinfo 0 0x0002 asymmetric-key
id: 0x0002, type: asymmetric-key, algorithm: rsa2048, label: "........................................", length: 896, domains: 1, sequence: 0, origin: generated, capabilities: exportable-under-wrap:sign-attestation-certificate:sign-pkcs:sign-pss
```

Example of Java KeyTool command:
--------------------------------

```
keytool -list -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg sun_yubihsm2_pkcs11.conf -storepass 0001password -v

Keystore type: PKCS11
Keystore provider: SunPKCS11-yubihsm-pkcs11

Your keystore contains 1 entry

Alias name: MyKey1
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=YubiHSM Attestation id:0xd353
Issuer: EMAILADDRESS=admin@test.se, CN=TestCA, OU=Test, O=Yubico, L=Stockholm, ST=Stockholm, C=SE
Serial number: 23161118fc1d59fbab75138b562a4b00c8163c3d
Valid from: Wed Apr 14 10:43:28 CEST 2021 until: Sat Aug 27 10:43:28 CEST 2022
Certificate fingerprints:
         SHA1: 38:1E:81:1A:0A:6E:B0:87:E0:B6:5C:8A:B8:C6:EC:91:1D:51:28:1A
         SHA256: CC:F7:26:6C:70:12:7E:E3:62:22:71:9B:3C:32:16:C8:C6:34:10:6F:49:22:7A:18:70:09:E3:3E:73:42:38:47
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 1
```

Using YubiHSM 2 with Java signing applications
==============================================

When the YubiHSM 2 has been configured with an RSA keypair and a X.509 certificate, the YubiHSM 2 PKCS11 can now be used with any Java signing application that utilizes the default Sun JCE PKCS11 Provider.

For example, JarSigner can be used to sign a JAR-file with the YubiHSM 2 and validate the signed JAR-file.

Use JarSigner to sign a JAR-file
--------------------------------

**Example:**

```
jarsigner -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg sun_yubihsm2_pkcs11.conf lib.jar MyKey1 -storepass 0001password -sigalg SHA256withRSA -tsa http://timestamp.digicert.com -verbose

...

jar signed.
```
Use JarSigner to validate a signed JAR-file
-------------------------------------------

**Example:**

```
jarsigner -verify lib.jar -verbose -certs

...

jar verified.
```
