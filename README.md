# MapAz Powershell Module

MapAz is a PowerShell module that helps you query you Azure tenants and map resources, identities and access into meaningful objects. 

# Join Us!

Join our [|Zero| Labs](https://join.slack.com/t/minus273celsius/shared_invite/zt-1ulg46s8x-N0P9sEzmv3SbYTlDXVSf2g) Slack Community workspace for any questions, issues, or suggestions.

# Quick Start

## User Access

MapAz requires utilizes [Az](https://github.com/Azure/azure-powershell), [Az.Resources](https://learn.microsoft.com/en-us/powershell/module/az.resources/?view=azps-14.1.0) and [Az.Accounts](https://learn.microsoft.com/pt-pt/powershell/module/az.accounts/?view=azps-14.1.0&viewFallbackFrom=azps-13.0.0). To install, simply run the following from an elevated PowerShell shell:

```PowerShell
Install-Module -Name Az
Install-Module -Name Az.Resources
Install-Module -Name Az.Accounts
Install-Module MapAz
```
MapAz assumes you are already logged in to your Azure tenant, and that you have read permissions or have the [security reader](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security#security-reader) role on all subscriptions you need to analize. 

 First, connect to your tenant with the appropriate account
```PowerShell
Connect-AzAccount
```
Next, collect access operations for all users: 
```PowerShell
$ua = Get-MapAzAllUsersAccess -Verbose
```
Each object in $ua desctibes a potential operation an account can perform on a resource or provider. 
Each object has the the following fields:

* ResourceId    : full resource path  
* ResourceName  : name of the resource
* ResourceType  : shown as <Provider/resourcetype>
* Operation     : which operation is Microsoft.Compute/virtualMachines/upgradeVMAgent/action
* OperationType : read/write or action
* UserId        : Object ID of the user 3a0bbca5-40b7-4f0c-8aba-3e0db66268f7
* UserName      : Name of the user (if exists)
* Plane         : Control / Data Plane

## Resource Collection

Be default, MapAz will only collect resources available via the ARM API. However, it is possible to try an enumerate more resources:
```PowerShell
Clear-MapAzScriptCache
$resources = Get-MapAzResource -ScanSubResources
```