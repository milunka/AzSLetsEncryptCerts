# AzSLetsEncryptCerts
Automatically create Azure Stack certificates using Lets Encrypt

## Requirements

- An Azure subscription
- An Azure DNS Zone for your domain
- A Service Principal within your Azure AD tenant
- Azure PowerShell modules.  If using the AZ modules, the [Enable-AzureRmAlias](https://docs.microsoft.com/en-us/powershell/module/az.accounts/enable-azurermalias) should be set.
N.B. This does not work with the Azure Stack PowerShell modules, as the AzureRM.Dns modules currently included do not support the creation of CAA records - we need this capability!
```
Install-Module -Name AzureRM -AllowClobber
```

- Azure Stack Readiness checker [PowerShell Module](https://www.powershellgallery.com/packages/Microsoft.AzureStack.ReadinessChecker).
```
Install-Module -Name Microsoft.AzureStack.ReadinessChecker
```

- [Posh-ACME](https://github.com/rmbolger/Posh-ACME) PowerShell module
```
Install-Module -Name Posh-ACME
```

- Oh, and my Azure Stack Lets Encrypt PoSh module [original](https://github.com/dmc-tech/AzSLetsEncryptCerts), [my fork](https://github.com/milunka/AzSLetsEncryptCerts)

## Notes
Everything needed during certificate creation is stored here

%userprofile%\AppData\Local\Posh-ACME

If you need to recreate the certs before the allowed renewal period within the Posh-ACME module, or have some issues, you can delete the sub folders in this location and re-run the script.
