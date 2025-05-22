Add-Type -TypeDefinition @"
public class EnrichedOp {
    public string ResourceId;
    public string ResourceName;
    public string Operation;
    public string OperationType;
    public string UserId;
    public string UserName;
    public EnrichedOp(string rid, string rname, string op, string optype, string uid, string uname) {
        ResourceId   = rid;
        ResourceName = rname;
        Operation    = op;
        OperationType= optype;
        UserId       = uid;
        UserName     = uname;
    }
}
"@ -Language CSharp


function Clear-AcAzScriptCache
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
        $global:OpsByRoleAssignment = @{}
        $global:allGroupMembers = @()
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

function Test-AcAzUserGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $GroupId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $UserId
    )

    begin {
        if (-not (Get-Variable -Name allGroupMembers -Scope Global -ErrorAction SilentlyContinue) `
            -or -not $global:allGroupMembers)
        {
            Write-Verbose 'Caching all group members...'
            $global:allGroupMembers = @()

            # Fetch every AAD group once
            $allGroups = Get-AzADGroup

            foreach ($grp in $allGroups) {
                Write-Verbose "  • Loading members of '$($grp.DisplayName)' ($($grp.Id))"
                $members = Get-AzADGroupMember -GroupObjectId $grp.Id -ErrorAction SilentlyContinue
                $global:allGroupMembers += [PSCustomObject]@{
                    GroupId = $grp.Id
                    Members = $members
                }
            }
        }
    }

    process {
        function Test-Member {
            param(
                [string]   $CurrentGroupId,
                [string]   $SearchUserId,
                [string[]] $Visited
            )

            if ($Visited -contains $CurrentGroupId) { return $false }
            $Visited += $CurrentGroupId

            # Get cached entry
            $entry = $global:allGroupMembers |
                     Where-Object { $_.GroupId -eq $CurrentGroupId }
            if (-not $entry) { return $false }

            $members = $entry.Members

            # Direct user?
            if ($members.Id -contains $SearchUserId) {
                return $true
            }

            # Recurse into nested groups
            $subGroups = $members | Where-Object { $_.ObjectType -eq 'Group' }
            foreach ($sg in $subGroups) {
                if (Test-Member -CurrentGroupId $sg.Id `
                                -SearchUserId $SearchUserId `
                                -Visited $Visited) {
                    return $true
                }
            }

            return $false
        }

        # Kickoff with empty visited list
        $isMember = Test-Member -CurrentGroupId $GroupId `
                                -SearchUserId $UserId `
                                -Visited @()

        # Output boolean
        $isMember
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
    $userId,
    [ValidateNotNullOrEmpty()]
    [string]
    $userPrincipalName)

    begin{
        if (-not (Get-Variable -Name allUsers -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allUsers)
        {
            Write-Host  'Fetching all users...'
            $global:allUsers = @()
            $global:allUsers += Get-AzAdUser
            Write-Host  'Fetching all service principals...'
            $global:allUsers += Get-AzADServicePrincipal
            Write-Host  'Fetching all groups...'
            $global:allUsers += Get-AzADGroup
            
            Write-Host  'Fetching all managed identities...'
            $subs = Get-AzSubscription
            foreach ($sub in $subs) {
                Write-Verbose "Switching to subscription $($sub.Name) ($($sub.Id))"
                Set-AzContext -Subscription $sub.Id | Out-Null
                $global:allUsers += Get-AzUserAssignedIdentity -ErrorAction SilentlyContinue
            }
        }
    }

    end {
        if ($UserId -or  $userPrincipalName) {
            $global:allUsers | Where-Object { ($_.Id -eq $UserId) -or ($_.UserPrincipalName -eq $userPrincipalName) }
        }
        else {
            $global:allUsers
        }
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
        [string] $UserId,

        [ValidateNotNullOrEmpty()]
        [string] $UserName
    )

    begin {
        # If they passed -UserName, resolve it to an ObjectId
        if ($UserName) {
            Write-Verbose "Resolving user principal name '$UserName' to object ID..."
            $u = Get-AcAzUsers -userPrincipalName $UserName 
            $UserId = $u.Id
        }
        else
        {
            $u = Get-AcAzUsers -userId $UserId
            $UserName = $u.UserPrincipalName
        }

        if (-not (Get-Variable -Name allRoleAssignments -Scope Global -ErrorAction SilentlyContinue) `
            -or -not $global:allRoleAssignments)
        {
            Write-Verbose 'Fetching all role assignments for $UserName:$UserId'
            $global:allRoleAssignments = @()
            $subs = Get-AzSubscription
            foreach ($sub in $subs) {
                Write-Verbose "Switching to subscription $($sub.Name) ($($sub.Id))"
                Set-AzContext -Subscription $sub.Id | Out-Null
                $global:allRoleAssignments += Get-AzRoleAssignment -ErrorAction SilentlyContinue
            }
        }
    }

    process {
        if (-not $UserId) {
            $global:allRoleAssignments
        }
        else {
            $global:allRoleAssignments |
              Where-Object {
                  ($_.ObjectId -eq $UserId) -or
                  ($_.ObjectType -eq 'Group' -and
                   (Test-AcAzUserGroupMembership -GroupId $_.ObjectId -UserId $UserId))
              }
        }
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

function Resolve-AccessPlane {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $Actions,

        [Parameter()]
        [string] $ResourceScope,

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

function Get-AcARoleAssignmentAccess {
    [CmdletBinding(DefaultParameterSetName = 'ByUPN')]
    param(
        [Parameter(
            Mandatory        = $true,
            Position         = 0,
            HelpMessage      = 'Role Id'
        )]
        [ValidateNotNullOrEmpty()]
        $Assignment,
        [Parameter(
            Mandatory   = $false,
            HelpMessage = 'Optional scope to filter results (e.g. /subscriptions/<id>)'
        )]
        [string]$ResourceScope)

    begin {
        Write-Host  "Resolving assignments for role $RoleId"
       
        $resScope = if ($ResourceScope) { $ResourceScope.ToLower() } else { $null }

        $roleAccessList = [System.Collections.Generic.List[PSCustomObject]]::new()

        if (-not $global:OpsByRoleAssignment) {
            Write-Verbose "Initializing role assugment cache..."
            $global:OpsByRoleAssignment = @{}
        }
    }

    process {
        $roles = Get-AcAzRoleDefinitions -roleId $Assignment.RoleDefinitionId
        foreach ($role in $roles) {
            $scope = $Assignment.Scope
            if ( -not $global:OpsByRoleAssignment.ContainsKey($Assignment.RoleAssignmentId)){

                Write-Host  "Processing Role '$($role.Name)' for scope '$scope'"
                if (-not $resScope -or $resScope.StartsWith($scope.ToLower())) {
                    
                    $actions = $role.Actions
                    $notactions = $role.NotActions

                    Write-Verbose "Fetching control plane operations for role '$($Assignment.RoleAssignmentId)'"
                    Resolve-AccessPlane -Actions $actions -NotActions $notactions -ResourceScope $resScope -Plane "Control" | 
                    ForEach-Object { $roleAccessList.Add($_) }

                    $dataActions = $role.DataActions
                    $notDataActions = $role.NotDataActions

                    Write-Verbose "Fetching data plane operations for role '$($Assignment.RoleAssignmentId)'"
                    Resolve-AccessPlane -Actions $dataActions -NotActions $notDataActions -ResourceScope $resScope -Plane "Data" |
                    ForEach-Object { $roleAccessList.Add($_) }

                    $global:OpsByRoleAssignment[$Assignment.RoleAssignmentId] = $roleAccessList
                }
            }
            else {Write-Verbose "Role assigment already cached : '$($Assignment.RoleDefinitionName) : $($Assignment.RoleDefinitionId)'"}
        }
    }

    end {
        Write-Host  "Sorting and de-duplicating results for Role '$($Assignment.RoleDefinitionName)'"
        $result = $result |    Sort-Object ResourceId, ResourceName, Operation, OperationType -Unique
        Write-Host  "Total unique access entries: $($result.Count)"
        return $result
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
        Write-Host  "Resolving assignments for user via parameter set '$($PSCmdlet.ParameterSetName)'"
        if ($PSCmdlet.ParameterSetName -eq 'ByUPN') {
        
            $userassignments = Get-AcAzRoleAssignments -UserName $UserPrincipalName -ErrorAction SilentlyContinue
            $currUserId = (Get-AcAzUsers -userPrincipalName $UserPrincipalName).Id 
            $currUserPrincipalName = $UserPrincipalName
        }
        else {
            $userassignments = Get-AcAzRoleAssignments -UserId $UserId -ErrorAction SilentlyContinue
            $currUserPrincipalName = (Get-AcAzUsers -userId $UserId).UserPrincipalName
            $currUserId = $UserId 

        }
        if (-not $userassignments) {
            Write-Warning "Could not find User Assignments for user $((@($UserPrincipalName, $UserId, ("Unknown")) | Where-Object { $_ -ne $null} | Select-Object -First 1))"
            return
        }
        Write-Verbose "Found $($userassignments.Count) assignment(s)."

        $resScope = if ($ResourceScope) { $ResourceScope.ToLower() } else { $null }
    }

    process {
        foreach ($assignment in $userassignments) {

            Get-AcARoleAssignmentAccess -Assignment $assignment -ResourceScope $resScope
        }
    }

    end {
        Write-Host  "Collecting assignments and their access for '$currUserPrincipalName':'$currUserId'"
        
        $assignmentCount = 0
        [int]$totalCount = 0
        foreach ($a in $userAssignments) {
            $ops = $global:OpsByRoleAssignment[$a.RoleAssignmentId]
            if ($ops) { 
                $totalCount += $ops.Count 
                $assignmentCount++
            }
        }

        [EnrichedOp[]]$results = New-Object EnrichedOp[] $totalCount
        [int]$idx = 0

        

        foreach ($a in $userAssignments) {
            $ops = $global:OpsByRoleAssignment[$a.RoleAssignmentId]
            if ($ops) {
                foreach ($op in $ops) {
                    $results[$idx++] = [EnrichedOp]::new(
                        $op.ResourceId,
                        $op.ResourceName,
                        $op.Operation,
                        $op.OperationType,
                        $currUserId,
                        $currUserPrincipalName
                    )
                }
            }
        }

        #foreach ($assignment in $userAssignments) {
        #    $ops = $global:OpsByRoleAssignment[$assignment.RoleAssignmentId]
        #    if ($ops) {
        #        [PSCustomObject[]]$batch = foreach ($op in $ops) {
        #            [PSCustomObject]@{
        #                ResourceId     = $op.ResourceId
        #                ResourceName   = $op.ResourceName
        #                Operation      = $op.Operation
        #                OperationType  = $op.OperationType
        #                UserId         = $currUserId
        #                UserName       = $currUserPrincipalName
        #            }
        #        }
#
                # now this will work without the conversion error
#                $result.AddRange($batch)
#                $assignmentCount++
#            }
#        }

        Write-Host  "Filtering duplicate operations..."

        $results = $results | Sort-Object UserId,UserName, ResourceId, ResourceName, Operation, OperationType -Unique

        Write-Host "Total assigned roles for $$currUserPrincipalName: $assignmentCount"
        Write-Host "Total unique access entries: $($result.Count)"
        return $results
    }
}

function Get-AcAzAllUsersAccess {
    [CmdletBinding()]
    param()
    
    begin {
            Write-Host  "Collecting assignments for all users and converting to access objects..."
    }
    process {
        $allAccess = Get-AcAzUsers | ForEach-Object {Get-AcAzUserAccess -UserId $_.Id}
    }

    end 
    {
        return $allAccess
    }
}


# Export the function when the module is imported
Export-ModuleMember -Function Get-AcAzUserAssigments,Get-AcAzResource,Test-AcAzUserGroupMembership,
                                Get-AcAzRoleAssignments,Clear-AcAzScriptCache,Get-AcAzUserAccess,
                                Get-AcAzUsers,Get-AcAzProviderOperations,Get-AcAzResourceProvider,
                                Get-AcAzAllUsersAccess
