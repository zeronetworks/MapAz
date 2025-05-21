function Clear-AcAzGlobalCache
{
    [CmdletBinding()]
    param()
    begin 
    {
        $global:allRoleDefinitions = @()
        $global:allRoleAssignments = @()
        $global:allResources = @()
        $global:allUsers = @()
        $global:allOperations = @()
        $global:allResourceactionProviders = @()
    }
}

function Get-AcAzResourceProvider {
    [CmdletBinding()]
    param(
    [ValidateNotNullOrEmpty()]
    [string]
    $NameSpace)

    begin{
        if (-not (Get-Variable -Name allOperations -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allResourceactionProviders)
        {
            Write-Verbose 'Fetching all resource actionProviders...'
            $global:allResourceactionProviders += Get-AzResourceProvider -ErrorAction SilentlyContinue
            }
    }

    process {
        if ($NameSpace) {$global:allResourceactionProviders | Where-Object { $_.ProviderNamespace -like "$NameSpace*" }}
        else {$global:allResourceactionProviders}
    }
}

function Get-AcAzProviderOperations {
    [CmdletBinding()]
    param(
    [ValidateNotNullOrEmpty()]
    [string]
    $action,
    [bool] 
    $IsDataAction)

    begin{
        if (-not (Get-Variable -Name allOperations -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allOperations)
        {
            Write-Verbose 'Fetching all operations...'
            $global:allOperations += Get-AzProviderOperation -ErrorAction SilentlyContinue
            }
    }

    process {
        if ($action) {
            $global:allOperations | Where-Object { $_.Operation -like "$action*" } | 
                Where-Object {-not $PSBoundParameters.ContainsKey('IsDataAction') -or $_.IsDataAction -eq $IsDataAction}
        }
        else {$global:allOperations}
    }
}

function Get-AcAzUsers {
    [CmdletBinding()]
    param(
    [ValidateNotNullOrEmpty()]
    [string]
    $userId)

    begin{
        if (-not (Get-Variable -Name allUsers -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allUsers)
        {
            Write-Verbose 'Fetching all users...'
            $subs = Get-AzSubscription
            $global:allUsers = @()
            $global:allUsers += Get-AzAdUser
            $global:allUsers += Get-AzADServicePrincipal
            $global:allUsers += Get-AzADGroup
            
            $subs = Get-AzSubscription
            foreach ($sub in $subs) {
                Write-Verbose "Switching to subscription $($sub.Name) ($($sub.Id))"
                Set-AzContext -Subscription $sub.Id | Out-Null
                $global:allUsers += Get-AzUserAssignedIdentity -ErrorAction SilentlyContinue
            }
        }
    }

    process {
        if ($userId) {$global:allUsers | Where-Object { $_.Id -eq $userId }}
        else {$global:allUsers}
    }
}

function Get-AcAzRoleDefinitions {
    [CmdletBinding()]
    param(
    [ValidateNotNullOrEmpty()]
    [string]
    $roleId)

    begin{
        if (-not (Get-Variable -Name allRoleDefinitions -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allRoleDefinitions)
        {
            Write-Verbose 'Fetching all role definitions...'
            $subs = Get-AzSubscription
            $global:allRoleDefinitions = @()
            foreach ($sub in $subs) {
                Write-Verbose "Switching to subscription $($sub.Name) ($($sub.Id))"
                Set-AzContext -Subscription $sub.Id | Out-Null
                $global:allRoleDefinitions += Get-AzRoleDefinition -ErrorAction SilentlyContinue
            }
        }
    }

    process {
        $global:allRoleDefinitions | Where-Object { $_.Id -eq $roleId }
    }
}

function Get-AcAzRoleAssignments {
    [CmdletBinding()]
    param(
    [ValidateNotNullOrEmpty()]
    [string]
    $userId)

    begin{
        if (-not (Get-Variable -Name allRoleAssignments -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allRoleAssignments)
        {
            Write-Verbose 'Fetching all role assgingments...'
            $subs = Get-AzSubscription
            $global:allRoleAssignments = @()
            foreach ($sub in $subs) {
                Write-Verbose "Switching to subscription $($sub.Name) ($($sub.Id))"
                Set-AzContext -Subscription $sub.Id | Out-Null
                $global:allRoleAssignments += Get-AzRoleAssignment -ErrorAction SilentlyContinue
            }
        }
    }

    process {
        $global:allRoleAssignments | Where-Object { $_.ObjectId -eq $userId }
    }
}


function Get-AcAzResource {
    [CmdletBinding()]
    param(
        [Parameter(
            Position    = 0,
            HelpMessage = 'Scope to filter resources by ResourceId prefix'
        )]
        [string]$Scope,
        [Parameter(
            HelpMessage = 'Optional resource type to filter (e.g., Microsoft.Compute/virtualMachines)'
        )]
        [string]$ResType
    )

    begin {
        if (-not (Get-Variable -Name allResources -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allResources)
        {
            Write-Verbose 'Fetching all subscriptions and resources...'
            $subs = Get-AzSubscription
            $global:allResources = @()
            foreach ($sub in $subs) {
                Write-Verbose "Switching to subscription $($sub.Name) ($($sub.Id))"
                Set-AzContext -Subscription $sub.Id | Out-Null
                $global:allResources += Get-AzResource -ErrorAction SilentlyContinue
            }
        }
    }

    process {
        if ($Scope) {
            # Filter the fresh or cached list
            $global:allResources | Where-Object { $_.ResourceId -like "$Scope*" } | Where-Object {$_.ResourceType -like "$ResType*"}
        }
        else {
            # Return a shallow copy of the full list
            $global:allResources | ForEach-Object { $_ }
        }
    }
}

function Get-AcAzUserAssigments {
    [CmdletBinding(DefaultParameterSetName = 'ByUPN')]
    param(
        [Parameter(
            Mandatory        = $true,
            ParameterSetName = 'ByUPN',
            Position         = 0,
            HelpMessage      = 'User Principal Name (e.g. alice@contoso.com)'
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $UserPrincipalName,

        [Parameter(
            Mandatory        = $true,
            ParameterSetName = 'ById',
            Position         = 0,
            HelpMessage      = 'Azure AD ObjectId GUID'
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $UserId
    )

    begin {
        # Resolve the AD user object based on input
        if ($PSCmdlet.ParameterSetName -eq 'ByUPN') {
            Write-Verbose "Resolving user by UPN: $UserPrincipalName"
            $user = Get-AzADUser -UserPrincipalName $UserPrincipalName -ErrorAction SilentlyContinue
        }
        else {
            Write-Verbose "Resolving user by ObjectId: $UserId"
            $user = Get-AzADUser -ObjectId $UserId -ErrorAction SilentlyContinue
        }

        if (-not $user) {
            Throw "User not found in Azure AD."
        }
    }

    process {
        $assignments = Get-AcAzRoleAssignments -userId $user.Id

        if (-not $assignments) {
            Write-Warning "No role assignments found for user $($user.DisplayName)"
            return
        }

        $uroles = @{}
        $uroles["Id"]             = $user.Id
        $uroles["Name"]           = $user.UserPrincipalName
        $uroles["scopes"] = @{}

        

        $assignments | ForEach-Object { 
            $role_defs = Get-AcAzRoleDefinitions -roleId $_.RoleDefinitionId
            $scope = $_.Scope
            $resources = Get-AcAzResource -Scope $scope
            
            if (-not $uroles["scopes"].ContainsKey($scope)) {
                $uroles["scopes"][$scope] = @{
                Actions     = @()
                DataActions = @()
                NotActions  = @()
                NotDataActions = @()
                Resources = @()
                }
            }
            
            $uroles["scopes"][$scope].Actions += $role_defs.Actions | Select-Object -Unique
            $uroles["scopes"][$scope].NotActions += $role_defs.NotActions | Select-Object -Unique
            $uroles["scopes"][$scope].DataActions += $role_defs.DataActions | Select-Object -Unique
            $uroles["scopes"][$scope].NotDataActions += $role_defs.NotDataActions | Select-Object -Unique

            if ($resources)
            {
                $resourceIds = $resources | Select-Object -ExpandProperty ResourceId
                $resourceIdStrings = [string[]]$resourceIds 
                $uroles["scopes"]["$scope"].Resources += $resourceIdStrings | Select-Object -Unique
            }
        }

        $uroles
    }
}

function Resolve-AccessPlane {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $Actions,

        [Parameter()]
        [string] $ResourceScope,

        [Parameter(Mandatory)]
        $Assignment,

        [Parameter(Mandatory)]
        [string]$Plane,

        [string[]] $NotActions
    )

    begin {
        $OpsByNamespace = @{}
    }

    process {

        $resAccessList = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($action in $Actions) {
            Write-Verbose "Processing action '$action'"

            # Parse action into namespace, provider path, and operation
            $parts = $action.Split('/')
            $ns    = $parts[0]
            $prov  = $parts[0..($parts.Length - 2)] -join '/'
            $op    = $parts[-1]

            # Cache provider operations once per namespace
            if (-not $OpsByNamespace.ContainsKey($ns)) {
                Write-Verbose "Fetching provider operations for namespace '$ns'"
                $OpsByNamespace[$ns] = Get-AcAzProviderOperations -action $ns -IsDataAction $false
            }

            Write-Verbose "Getting resources of type '$prov' under '$ResourceScope'"
            $resources = Get-AcAzResource -Scope $ResourceScope -ResType $prov
            Write-Verbose "Found $($resources.Count) matching resources"

            $resources | Group-Object -Property ResourceType | ForEach-Object {
                $type  = $_.Name
                $group = $_.Group

                Write-Verbose "Filtering operations for resource type '$type'"
                $matches = $OpsByNamespace[$ns] | Where-Object { $_.Operation -like "$type/$op" }
                Write-Verbose "Found $($matches.Count) matching operations for type '$type'"

                foreach ($r in $group) {
                    foreach ($mo in $matches) {
                        if ($NotActions -and ($NotActions | Where-Object { $mo.Operation -like $_ })) {
                            Write-Verbose "Removing operation as it cancelled out by not operation: '$($mo.Operation)'"
                        }
                        else {
                            $resAccessList.Add([PSCustomObject]@{
                                Name           = $Assignment.Name
                                Id             = $Assignment.Id
                                ResourceId     = $r.ResourceId
                                ResourceType   = $type
                                ResourceName   = $r.Name
                                Operation      = $mo.Operation
                                OperationType  = $mo.Operation.Split('/')[-1]
                                Plane          = $Plane
                            })
                        }
                    }
                }
            }
        }

        return $resAccessList
    }
}



function Get-AcAzUserAccess {
    [CmdletBinding(DefaultParameterSetName = 'ByUPN')]
    param(
        [Parameter(
            Mandatory        = $true,
            ParameterSetName = 'ByUPN',
            Position         = 0,
            HelpMessage      = 'User Principal Name (e.g. alice@contoso.com)'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter(
            Mandatory        = $true,
            ParameterSetName = 'ById',
            Position         = 0,
            HelpMessage      = 'Azure AD ObjectId GUID'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [Parameter(
            Mandatory   = $false,
            HelpMessage = 'Optional scope to filter results (e.g. /subscriptions/<id>)'
        )]
        [string]$ResourceScope
    )

    begin {
        Write-Verbose "Resolving assignments for user via parameter set '$($PSCmdlet.ParameterSetName)'"
        if ($PSCmdlet.ParameterSetName -eq 'ByUPN') {
            $userassignments = Get-AcAzUserAssigments -UserPrincipalName $UserPrincipalName -ErrorAction SilentlyContinue
        }
        else {
            $userassignments = Get-AcAzUserAssigments -UserId $UserId -ErrorAction SilentlyContinue
        }
        if (-not $userassignments) {
            Throw "Could not find User Assignments for user."
        }
        Write-Verbose "Found $($userassignments.Count) assignment(s)."

        $resScope = if ($ResourceScope) { $ResourceScope.ToLower() } else { $null }

        $resAccessList = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        foreach ($assignment in $userassignments) {
            foreach ($scope in $assignment.scopes.Keys) {
                Write-Verbose "Processing scope '$scope'"
                if (-not $resScope -or $resScope.StartsWith($scope.ToLower())) {
                    
                    $actions = $assignment.scopes[$scope].Actions
                    $notactions = $assignment.scopes[$scope].NotActions

                    Resolve-AccessPlane -Actions $actions -NotActions $notactions -ResourceScope $resScope -Assignment $assignment -Plane "Control" | 
                    ForEach-Object { $resAccessList.Add($_) }

                    $dataActions = $assignment.scopes[$scope].DataActions
                    $notDataActions = $assignment.scopes[$scope].NotDataActions

                    Resolve-AccessPlane -Actions $dataActions -NotActions $notDataActions -ResourceScope $resScope -Assignment $assignment -Plane "Data" |
                    ForEach-Object { $resAccessList.Add($_) }
                }
            }
        }
    }

    end {
        Write-Verbose "Sorting and de-duplicating results"
        $result = $resAccessList |
            Sort-Object Name, Id, ResourceId, ResourceName, Operation, OperationType -Unique
        Write-Verbose "Total unique access entries: $($result.Count)"
        return $result
    }
}



# Export the function when the module is imported
Export-ModuleMember -Function Get-AcAzUserAssigments,Get-AcAzResource,
                                Get-AcAzRoleAssignments,Clear-AcAzGlobalCache,Get-AcAzUserAccess,
                                Get-AcAzUsers,Get-AcAzProviderOperations,Get-AcAzResourceProvider
