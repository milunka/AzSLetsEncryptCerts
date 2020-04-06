# AzSLetsEncryptCerts
Automatically create Azure Stack certificates using Lets Encrypt.
Original [module](https://github.com/dmc-tech/AzSLetsEncryptCerts), description of whole process and module is on this [blog post](https://www.cryingcloud.com/blog/2019/10/9/using-lets-encrypt-certificates-with-azure-stack)


## Requirements
- An Azure subscription
- An Azure DNS Zone for your domain
- A Service Principal within your Azure AD tenant
- Azure PowerShell modules.  If using the Azure stack modules, the [Enable-AzureRmAlias](https://docs.microsoft.com/en-us/powershell/module/az.accounts/enable-azurermalias) should be set.
This does not work with the Azure Stack PowerShell modules, as the AzureRM.Dns modules currently included do not support the creation of CAA records
```
Install-Module -Name AzureRM -AllowClobber
```

- Azure Stack Readiness checker [PowerShell Module](https://www.powershellgallery.com/packages/Microsoft.AzureStack.ReadinessChecker).
```
Install-Module -Name Microsoft.AzureStack.ReadinessChecker -RequiredVersion 1.2002.1111.69
```

- [Posh-ACME](https://github.com/rmbolger/Posh-ACME) PowerShell module
```
Install-Module -Name Posh-ACME -RequiredVersion 3.12.0
```

- Azure Stack Lets Encrypt PoSh module [original](https://github.com/dmc-tech/AzSLetsEncryptCerts), [my fork](https://github.com/milunka/AzSLetsEncryptCerts)

## Notes
1. Posh-ACME module is storing certificates request and result certificates at Local folder
```
%userprofile%\AppData\Local\Posh-ACME
```
If you need to recreate the certs before the allowed renewal period within the Posh-ACME module, or have some issues, you can delete the sub folders in this location and re-run the script.

2. Password for certificates must be
   -  at least 8 characters long
   -  have some complexity, it should contain at least 3 of the following
      -  uppercase
      -  lowercase
      -  numbers 0-9
      -  special characters
      -  alphabetical character that is neither uppercase nor lowercase


