$DebugPreference = 'continue'

$Region = '<Region>'
$FQDN = '<FQDN>'
$DNSResourceGroup = '<DNS Zone Resource>'
$mailToAddress = '<email address>'

$Params = @{
 RegionName = $Region
 FQDN = $FQDN
 ServicePrincipal = '<Service Principal GUID>'
 ServicePrincipalSecret = '<Service Principal Secret>'
 pfxPass = 'P@ssword!'
 SubscriptionId = '<Sub Id>'
 TenantId = '<Tenant Id>'
 CertPath = 'c:\azsCerts'
}

$scriptpath = $PSScriptRoot
Set-Location $scriptpath
Import-Module .\AzSLetsEncrypt.psm1 -Force

# Creates CAA records at DNS Zone
$SpPassword = ConvertTo-SecureString $Params.ServicePrincipalSecret -AsPlainText -Force
$DnsZoneCreds = New-Object System.Management.Automation.PSCredential ($Params.ServicePrincipal, $SpPassword)
Connect-AzureRmAccount -TenantId $Params.TenantId -Subscription $Params.SubscriptionId -ServicePrincipal -Credential $DnsZoneCreds
New-AzsDnsCaaRecords -ResourceGroup $DNSResourceGroup -RegionName $Region -FQDN $FQDN -PaaS -mailTo $mailToAddress

# Creates or renew certificates
New-AzsPkiLECertificates @Params -Force -PaaS

# Validate created certificates with Azure Stack validation checker
Invoke-ValidateCertificates @Params -PaaS
