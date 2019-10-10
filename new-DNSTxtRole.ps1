# Use this to create a role to assign to service principal used by Posh-Acme

$profile = Connect-AzureRMAccount

$roleDef = Get-AzureRmRoleDefinition -Name "DNS Zone Contributor"
$roleDef.Id = $null
$roleDef.Name = "DNS TXT Contributor"
$roleDef.Description = "Manage DNS TXT records only."
$roleDef.Actions.RemoveRange(0,$roleDef.Actions.Count)
$roleDef.Actions.Add("Microsoft.Network/dnsZones/TXT/*")
$roleDef.Actions.Add("Microsoft.Network/dnsZones/read")
$roleDef.Actions.Add("Microsoft.Authorization/*/read")
$roleDef.Actions.Add("Microsoft.Insights/alertRules/*")
$roleDef.Actions.Add("Microsoft.ResourceHealth/availabilityStatuses/read")
$roleDef.Actions.Add("Microsoft.Resources/deployments/read")
$roleDef.Actions.Add("Microsoft.Resources/subscriptions/resourceGroups/read")
$roleDef.AssignableScopes.Clear()
$roleDef.AssignableScopes.Add("/subscriptions/$($profile.Context.Subscription.Id)")

$role = New-AzureRmRoleDefinition $roleDef
$role