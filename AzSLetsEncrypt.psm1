#Requires -RunAsAdministrator
#Requires -Modules @{'ModuleName'='Posh-Acme';'ModuleVersion'='3.5.0'},@{'ModuleName'='AzureRM.Dns';'ModuleVersion'='5.0.3'} ,Microsoft.AzureStack.ReadinessChecker
function new-AzsPACert ($AzsCert, [switch]$LegacyCert, $Path, $azParams, $Force) {
    foreach ($Key in $AzsCert.Keys) {
        if (-not (Test-Path -Path "$Path\$Key")) {
            New-Item -ItemType Directory -Path "$Path\$Key"
        }
        $Cert = ($AzsCert[$Key]).Replace("""", "'")
        $maindomain = $cert.Split(',')
        $existCerts = Get-ChildItem  Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$($maindomain[0])"}
        If ($existCerts) {
            foreach ($Cert in $existCerts) {
                $Cert |Remove-Item 
            }
        }


        write-host "Main Domain: $maindomain"
        if (Get-PACertificate -MainDomain $maindomain[0]) {
            # Renew Cert
            write-host "obtaining Renewal Cert: $Cert"
            if ($Force) {
                Submit-Renewal -MainDomain $maindomain[0] -NewKey -Force
            }
            else { 
                Submit-Renewal -MainDomain $maindomain[0] -NewKey
            }
        }
        Else {

            write-host "obtaining new Cert: $Cert"
            #write-host "New-PACertificate $maindomain -DnsPlugin Azure -PluginArgs $azParams -AcceptTOS -PfxPass "$PfxPass""
            if ($Force) {
                $LECert = New-PACertificate $maindomain -DnsPlugin Azure -PluginArgs $azParams -AcceptTOS -PfxPass "$PfxPass" -Force
            }
            else {
                $LECert = New-PACertificate $maindomain -DnsPlugin Azure -PluginArgs $azParams -AcceptTOS -PfxPass "$PfxPass"
            }
            if ($LegacyCert) {
                # Create a CNG cert for PaaS RP.  Least hacky way to do it !
                & cmd /c certutil.exe -f -p $PfxPass -csp "Microsoft Enhanced RSA and AES Cryptographic Provider" -importpfx $($LECert.PfxFile) 
               
            }
            else {
               Import-PfxCertificate -FilePath $LECert.PfxFile cert:\localMachine\my -Password $secPfxPass -Exportable
            }
            $existCerts = Get-ChildItem  Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$($maindomain[0])"}
            If ($existCerts) {
                $expcertPath = "$Path\$Key\cert.pfx"
                Export-PfxCertificate -Cert $existCerts -Password $secPfxPass -FilePath $expcertPath
                $existCerts | remove-item
            }
            else {
                Write-Debug "Cert not installed"
            }
        }

    }
}

function New-AzsDnsCaaRecords {
    param (
        [Parameter(Mandatory)]
        [string]$ResourceGroup,
        [Parameter(Mandatory)]
        [string]$RegionName,
        [Parameter(Mandatory)]
        [string]$FQDN,
        [string]$mailTo,
        [switch]$ADFS,
        [switch]$PaaS
    )

    function Create-CaaRecord ($ep,$FQDN, $ResourceGroup ) {
        foreach ($Key in $ep.Keys) {

            $epName = $ep[$Key] 
            write-host "EPName:   $epName"

            $caarecords =@()
            $caarecords += New-AzureRMDnsRecordConfig -CaaFlags "0" -CaaTag "iodef" -CaaValue "mailto:$mailTo"
            $caarecords += New-AzureRMDnsRecordConfig -CaaFlags "0" -CaaTag "issue" -CaaValue "letsencrypt.org"
            New-AzureRMDnsRecordSet -Name $epName -RecordType "CAA" -ZoneName $FQDN  -ResourceGroupName $ResourceGroup -Ttl 3600 -DnsRecords $caarecords
            
        }
    }


    if (-not $mailTo) {
        $mailTo = "admin@$RegionName.$FQDN"
    }


    $AzsEndpoints = @{
    
        'Public Portal'="portal.$RegionName";
        'Admin Portal'="adminportal.$RegionName";
        'ARM Public'="management.$RegionName";
        'ARM Admin'="adminmanagement.$RegionName";
        'ACSBlob'="blob.$RegionName";
        'ACSTable'="table.$RegionName";
        'ACSQueue'="queue.$RegionName";
        'KeyVault'="vault.$RegionName";
        'KeyVaultInternal'="adminvault.$RegionName";
        'Admin Extension Host'="adminhosting.$RegionName";
        'Public Extension Host'="hosting.$RegionName"
        }


    $ADFSEndpoints = @{
        'ADFS'="adfs.$RegionName";
        'Graph'="graph.$RegionName";
    }

    $PaasEndpoints = @{
            'SQLAdapter'="dbadapter.$RegionName";
            'AppSvcWebDefault'="appservice.$RegionName";
            'AppSvcsso'="sso.appservice.$RegionName";
            'AppSvcscm'="scm.appservice.$RegionName";
            'AppSvcftp'="ftp.appservice.$RegionName";
            'AppSvcapi'="api.appservice.$RegionName";
            'cloudapp'="$regionName.cloudapp";
    }

    Get-AzureRMDnsRecordSet -ResourceGroupName $ResourceGroup -ZoneName $FQDN -RecordType CAA

    Create-CaaRecord -ep $AzsEndpoints -FQDN $FQDN -ResourceGroup $ResourceGroup

    if ($ADFS) {
        Create-CaaRecord -ep $ADFSEndpoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }

    If ($PaaS) {
        Create-CaaRecord -ep $PaasEndpoints -FQDN $FQDN -ResourceGroup $ResourceGroup
    }
}

function New-AzsPkiLECertificates {

param(
        [Parameter(Mandatory)]
        [string]$RegionName,
        [Parameter(Mandatory)]
        [string]$FQDN,
        [Parameter(Mandatory)]
        [string]$ServicePrincipal,
        [Parameter(Mandatory)]
        [string]$ServicePrincipalSecret,
        [Parameter(Mandatory)]
        [string]$pfxPass,
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [string]$CertPath = "",
        [switch]$Staging,
        [Switch]$ADFS,
        [Switch]$PaaS,
        [switch]$Force
    )

    # Requires the Posh-acme module
    # Requires Azure DNS Zone; Service Principal to create TXT records
    # https://github.com/rmbolger/Posh-ACME/blob/master/Posh-ACME/DnsPlugins/Azure-Readme.md


    # Set the LetsEncrpt environment according to your needs.  For testing, LE_STAGE
    If ($Staging) {
        Set-PAServer LE_STAGE
        write-debug "STAGING Server selected"
    }
    else {
        Set-PAServer LE_PROD
        write-debug "PRODUCTION Server selected"
    }

    If (!(Get-PAAccount)) {
        New-PAAccount -AcceptTOS
    }

    $DNSZone = "$RegionName.$FQDN"
    $secPfxPass = ConvertTo-SecureString -AsPlainText $PfxPass -Force
    $CoreCertPath = "$CertPath\Deployment"
    $AppServicesCertPath = "$CertPath\AppServices"
    $DBAdapterCertPath = "$CertPath\DBAdapter"
    $EventHubsCertPath = "$CertPath\EventHubs"
    $IoTHubCertPath = "$CertPath\IoTHub"


    $SpPassword = ConvertTo-SecureString $ServicePrincipalSecret -AsPlainText -Force
    $DnsZoneCreds = New-Object System.Management.Automation.PSCredential ($ServicePrincipal, $SpPassword)


    $azParams = @{
        AZSubscriptionId=$SubscriptionId;
        AZTenantId=$TenantId;
        AZAppCred=$DnsZoneCreds
      }

    $AzsCommmonEndpoints = @{
        'Public Portal'="portal.$DNSZone";
        'Admin Portal'="adminportal.$DNSZone";
        'ARM Public'="management.$DNSZone";
        'ARM Admin'="adminmanagement.$DNSZone";
        'ACSBlob'="*.blob.$DNSZone,blob.$DNSZone";
        'ACSTable'="*.table.$DNSZone,table.$DNSZone";
        'ACSQueue'="*.queue.$DNSZone,queue.$DNSZone";
        'KeyVault'="*.vault.$DNSZone,vault.$DNSZone";
        'KeyVaultInternal'="*.adminvault.$DNSZone,adminvault.$DNSZone";
        'Admin Extension Host'="*.adminhosting.$DNSZone,adminhosting.$DNSZone";
        'Public Extension Host'="*.hosting.$DNSZone,hosting.$DNSZone"
        }


    $AzsADFSEndpoints = @{
        'ADFS'="adfs.$DNSZone";
        'Graph'="graph.$DNSZone";
        }




    if (-not (Test-Path -Path $CertPath)) {
        New-Item -ItemType Directory -Path $CertPath
    }

    # Required certificates
    # new-AzsPACert $AzsCommmonEndpoints -Path $CoreCertPath -azParams $azParams $Force
    # if ($ADFS) {
    #     new-AzsPACert $AzsADFSEndpoints -Path $CoreCertPath -azParams $azParams $Force
    #     write-debug "Testing ADFS Certificates"
    #     Invoke-AzsCertificateValidation -CertificatePath $CoreCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN -IdentitySystem ADFS 
    # }
    # else {
    #     # Validate the Certs for Azs
    #     write-debug "Testing AAD Certificates"
    #     Invoke-AzsCertificateValidation -CertificatePath $CoreCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN -IdentitySystem AAD 
    # }


    If ($PaaS) {
    
        # AppService
        $AppServiceEndPoints = @{
            'API'="api.appservice.$DNSZone";
            'DefaultDomain'="*.appservice.$DNSZone,*.scm.appservice.$DNSZone,*.sso.appservice.$DNSZone";
            'Identity'="sso.appservice.$DNSZone";
            'Publishing'="ftp.appservice.$DNSZone";
        }

        new-AzsPACert $AppServiceEndPoints -Path $AppServicesCertPath -azParams $azParams $Force


        # #Create Certs for all possible PaaS endpoints as there is no cost :)
        # $AZSPaasEndPoints = @{
        #     'PaaSDBCert'="*.dbadapter.$DNSZone,dbadapter.$DNSZone";
        #     'PaaSDefaultCert'="*.appservice.$DNSZone,*.scm.appservice.$DNSZone,*.sso.appservice.$DNSZone";
        #     'PaaSAPICert'="api.appservice.$DNSZone";
        #     'PaaSFTPCert'="ftp.appservice.$DNSZone";
        #     'PaaSSSOCert'="sso.appservice.$DNSZone";
        # }
    
        # new-AzsPACert $AZSPaasEndPoints -Path $PaaSCertPath -LegacyCert -azParams $azParams $Force
        # $PaaSCertificates = @{}
        # foreach ($key in $AZSPaasEndPoints.Keys) {
        #     $passHash = @{
        #         'pfxPath'= "$PaaSCertPath\$key\cert.pfx";
        #         'pfxPassword' = $secPfxPass
        #     }
        #     $PaaSCertificates.Add($key,$passHash)
        #     write-host "$PaaSCertPath\$key\cert.pfx"
        # }
    
#        Invoke-AzsCertificateValidation -PaaSCertificates $PaaSCertificates -RegionName $RegionName -FQDN $FQDN

        # App Services
        Write-Host "Validating AppServices"
        Invoke-AzsCertificateValidation -CertificateType AppServices -CertificatePath $AppServicesCertPath -pfxPassword $secPfxPass -RegionName $RegionName -FQDN $FQDN

        # # DBAdapter
        # Write-Host "Validating DBAdapter"
        # Invoke-AzsCertificateValidation -CertificateType DBAdapter -CertificatePath C:\Certificates\DBAdapter -pfxPassword $pfxPassword -RegionName $RegionName -FQDN $FQDN

        # # EventHubs
        # Write-Host "Validating EventHubs"
        # Invoke-AzsCertificateValidation -CertificateType EventHubs -CertificatePath C:\Certificates\EventHubs -pfxPassword $pfxPassword -RegionName $RegionName -FQDN $FQDN

        # # IoTHub
        # Write-Host "Validating IoTHub"
        # Invoke-AzsCertificateValidation -CertificateType IoTHub -CertificatePath C:\Certificates\IoTHub -pfxPassword $pfxPassword -RegionName $RegionName -FQDN $FQDN
    }


     <#
        .SYNOPSIS
            Create PKI Certificates using Lets Encrypt for Azure Stack and validates them for usage

        .DESCRIPTION
            Uses the Posh-Acme module to create compatible Lets Encrypt PKI certificates for Azure Stack.  Used in conjunction with an Azure DNS zone 

        .PARAMETER RegionName
            The Azure Stack region name to generate the certificates for. e.g. local

        .PARAMETER ServicePrincpial
            The Service Princiapl GUID that has access to the DNS Zone.

        .PARAMETER ServicePrincpialSecret
            The Service Princiapl Secret.

        .PARAMETER pfxPass
            Password for PFX files.

        .PARAMETER SubscriptionId
            SubscriptionId for the Azure Subscription hosting the DNS Zone.

        .PARAMETER TenantId
            TenantId for the Azure AD Tenant.

        .PARAMETER CertPath
            Path to store the generated certificates.

        .PARAMETER FQDN
            The FQDN for the Azure Stack deployment.  e.g. azurestack.external

        .PARAMETER Staging
            If specified, uses the Lets Encrypt staging environment for testing purposes.  It is not rate limited, so is preferrable to use this switch prior to moving to Porduction.

        .PARAMETER ADFS
            If Specified, additional PKI certificates are created for ADFS deployments.

        .PARAMETER PaaS
            If specified, generate PKI Certificates required for SQL/MySQL and App Service PaaS.

        .PARAMETER Force
            Specifies the output file for which this function saves the response body. Enter a path and file name. If you omit the path, the default is the current location.

        .EXAMPLE

        #>
}
Export-ModuleMember New-AzsPkiLECertificates, new-AzsPACert, New-AzsDnsCaaRecords
