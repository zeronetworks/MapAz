Add-Type -TypeDefinition @"
public class EnrichedOp {
    public string ResourceId;
    public string ResourceName;
    public string ResourceType;
    public string Operation;
    public string OperationType;
    public string UserId;
    public string UserName;
    public string Plane;
    public EnrichedOp(string rid, string rname, string rtype,string op, string optype, string uid, string uname, string pl) {
        ResourceId   = rid;
        ResourceName = rname;
        ResourceType = rtype;
        Operation    = op;
        OperationType= optype;
        UserId       = uid;
        UserName     = uname;
        Plane        = pl;
    }
}
"@ -Language CSharp

function Clear-MapAzScriptCache
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

function Get-MapAzResourceProvider {
    [CmdletBinding()]
    param(
    [string]
    $NameSpace)

    begin{
        if (-not (Get-Variable -Name allResourceactionProviders -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allResourceactionProviders){
            Write-Verbose 'Fetching all resource actionProviders...'
            $global:allResourceactionProviders += Get-AzResourceProvider -ErrorAction SilentlyContinue
        }
    }

    process {
        if ($NameSpace) {$global:allResourceactionProviders | Where-Object { $_.ProviderNamespace -like "$NameSpace*" }}
        else {$global:allResourceactionProviders}
    }
}

function Test-MapAzUserGroupMembership {
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

function Get-MapAzProviderOperations {
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
            $global:allOperations.Where({
                $_.Operation -like $action -and $_.IsDataAction -eq $IsDataAction
            })
        }
        else {$global:allOperations}
    }
}

function Get-MapAzUsers {
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
            $matches = $global:allUsers | Where-Object { ($_.Id -eq $UserId) -or ($_.UserPrincipalName -eq $userPrincipalName) }
            if (-not $matches) { Write-Warning "No user found with Id $UserId or UPN $userPrincipalName."}
            return $matches
        }           
        else {
            $global:allUsers
        }
    }
}

function Get-MapAzRoleDefinitions {
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

function Get-MapAzRoleAssignments {
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
            $u = Get-MapAzUsers -userPrincipalName $UserName 
            $UserId = $u.Id
        }
        else
        {
            $u = Get-MapAzUsers -userId $UserId
            $UserName = $u.UserPrincipalName
        }

        if (-not (Get-Variable -Name allRoleAssignments -Scope Global -ErrorAction SilentlyContinue) `
            -or -not $global:allRoleAssignments)
        {
            Write-Verbose "Fetching all role assignments for $UserName ($UserId)"
            $global:allRoleAssignments = @()
            $subs = Get-AzSubscription
            foreach ($sub in $subs) {
                Write-Verbose "Switching to subscription $($sub.Name) ($($sub.Id))"
                Set-AzContext -Subscription $sub.Id | Out-Null

                $ra = Get-AzRoleAssignment -ErrorAction SilentlyContinue
                if (-not ($global:allRoleAssignments).Where({$_.RoleAssignmentId -eq $ra.RoleAssignmentId})){
                    $global:allRoleAssignments += $ra
                }
            }
        }
    }

    process {
        if (-not $UserId -and -not $UserName) {
            $global:allRoleAssignments
        }
        else {
            $global:allRoleAssignments |
              Where-Object {
                  ($_.ObjectId -eq $UserId) -or
                  ($_.ObjectType -eq 'Group' -and
                   (Test-MapAzUserGroupMembership -GroupId $_.ObjectId -UserId $UserId))
              }
        }
    }
}

function Get-MapAzProviderErrorInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$Message
    )
    process {
        foreach ($msg in $Message) {
            # extract the comma-separated api-versions inside single quotes
            $apiMatch = [regex]::Match($msg, "supported api-versions are '([^']+)'")
            $apiVersions = if ($apiMatch.Success) {
                $apiMatch.Groups[1].Value `
                  -split ',' `
                  | ForEach-Object { $_.Trim() } `
                  | Where-Object { $_ -ne '' }
            } else { @() }

            # extract the comma-separated locations inside single quotes
            $locMatch = [regex]::Match($msg, "supported locations are '([^']+)'")
            $locations = if ($locMatch.Success) {
                $locMatch.Groups[1].Value `
                  -split ',' `
                  | ForEach-Object { $_.Trim() } `
                  | Where-Object { $_ -ne '' }
            } else { @() }

            # output a structured object
            [PSCustomObject]@{
                Message     = $msg
                ApiVersions = $apiVersions
                Locations   = $locations
            }
        }
    }
}

function Get-MapAzResourceViaRESTAPINative {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)]
        [string]$Uri,

        [Parameter(Mandatory, Position=1)]
        [string]$Token
    )

    begin {
        # Default API version
        $script:apiver = "2021-04-01"
    }

    process {
        $uriAndApi = $Uri + "?api-version=" + $script:apiver

        Write-Verbose "Trying to GET resource at URI: $uriAndApi"
        $httpResp = Invoke-WebRequest -Method GET -Uri $uriAndApi -Headers @{ Authorization = "Bearer $Token" } -SkipHttpErrorCheck
        if ($httpResp.StatusCode -ne 200) {

            $statuscode = $httpResp.StatusCode
            $httpJson = $httpResp.Content | ConvertFrom-Json
            $errorCode = $httpJson.error.code

            Write-Debug "Got error $statuscode : $errorCode for URI: $uri"

            if ($errorCode -like "NoRegisteredProviderFound") {
                $errMsg = $httpJson.error.Message | Get-MapAzProviderErrorInfo
                if ($errMsg.ApiVersions) {
                    $script:apiver = $errMsg.ApiVersions[-1]
                    $uriAndApi = $Uri + "?api-version=" + $script:apiver

                    Write-Debug "Changing API versoin, trying URI: $uriAndApi"
                    $httpResp = Invoke-WebRequest -Method GET -Uri $uriAndApi -Headers @{ Authorization = "Bearer $Token" } -SkipHttpErrorCheck
                }
            }
        }
        
        if ($httpResp.StatusCode -ne 200) {
            try{
                $httpJson = $httpResp.Content | ConvertFrom-Json
                $errorCode = $httpJson.error.code
                Write-Debug "Got error $statuscode : $errorCode for URI: $uri"
            }
            catch {
                Write-Debug "Http content is not JSON!"
            }
        }  

        $httpResp
    }
}



function Get-MapAzResourceViaRESTAPI {
    [CmdletBinding()]
    param([string]$Uri)

    begin {
        #Import-Module Az
        $script:apiver = "2021-04-01"
    }
    
    process {
        $uriAndApi = $Uri + "?api-version=" + $script:apiver

        Write-Verbose "Trying to GET resource at URI: $uriAndApi"
        $httpResp = Invoke-AzRestMethod -Method GET -Path $uriAndApi
        if ($httpResp.StatusCode -ne 200) {

            $statuscode = $httpResp.StatusCode
            $httpJson = $httpResp.Content | ConvertFrom-Json
            $errorCode = $httpJson.error.code

            Write-Debug "Got error $statuscode : $errorCode for URI: $uri"

            if ($errorCode -like "NoRegisteredProviderFound") {
                $errMsg = $httpJson.error.Message | Get-MapAzProviderErrorInfo
                if ($errMsg.ApiVersions) {
                    $script:apiver = $errMsg.ApiVersions[-1]
                    $uriAndApi = $Uri + "?api-version=" + $script:apiver

                    #Write-Debug "Changing API versoin, trying URI: $uriAndApi"
                    $httpResp = Invoke-AzRestMethod -Method GET -Path $uriAndApi
                }
            }
        }
        
        if ($httpResp.StatusCode -ne 200) {
            try{
                $httpJson = $httpResp.Content | ConvertFrom-Json
                $errorCode = $httpJson.error.code
                Write-Verbose "Got error $statuscode : $errorCode for URI: $uri"
            }
            catch {
                Write-Debug "Http content is not JSON!"
            }
        }  

        $httpResp
    }
}

function Get-MapAzResourceAndSubResources {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$ResGroup,
        [string]$ProviderName,
        [string]$ResourceName,
        [string]$ResourceType)

    begin {

        if (-not $global:allResources) { $global:allResources= @()}

    }

    process {
        Write-Host "Scanning sub resources for resource: $ResourceName at group: $ResGroup"

        foreach ($subResType in ((Get-MapAzResourceProvider -NameSpace $ProviderName).ResourceTypes.ResourceTypeName).Where({$_ -like "$ResourceType/*"})){
            $subType = $subResType.Replace("$ResourceType/","")
            $subResId = "/subscriptions/$SubscriptionId/resourceGroups/$ResGroup/providers/$ProviderName/$ResourceType/$ResourceName/$subType"
            if (-not (($global:allResources).ResourceId -contains $subResId)){
                Write-Verbose "Trying to get sub resource $subResId"
   
                $httpResp = Get-MapAzResourceViaRESTAPI -Uri $subResId
                if ($httpResp.StatusCode -eq 200) {
                    try {
                        $subResources = ($httpResp.Content | ConvertFrom-Json).value
                    }
                    catch {
                        Write-Debug "Failed to parse JSON for URI $($item.Uri): $($_.Exception.Message)"
                    }
                    foreach ($subResource in $subResources){
                        if (($subResource.PSObject.Properties.Name -contains "Id") -and ($subResource.PSObject.Properties.Name -contains "type")){ 
                             if($subResource.type -like "$ProviderName*"){
                                Write-Host "Found sub resource: $($subResource.Id)" -ForegroundColor Green
                                $results = Get-AzResource -ResourceId $subResource.Id -ErrorAction SilentlyContinue
                                foreach ($res in $results){
                                    if (($res.PSObject.Properties.Name -contains "ResourceType") -and $res.ResourceType){
                                        $global:allResources += $res
                                        $subrestype = $res.ResourceType.Replace("$ProviderName/","")
                                        Get-MapAzResourceAndSubResources -SubscriptionId $SubscriptionId -ResGroup $ResGroup -ProviderName $ProviderName -ResourceName $res.Name -ResourceType $subrestype
                                    }
                                    else {Write-Debug "No type for resource $($res.Id)"}
                                }
                            }
                            else {
                                Write-Debug "This is not a resource: $($subResource.Id)"
                                Write-Debug "breaking loop, assuming other elements are the same..."
                                break
                            }
                        }
                    }
                }
            }
        }
    }
}

function Get-MapAzResource {
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
        [string]$ResType,
        [switch]$ScanSubResources
    )

    begin {
        if (-not (Get-Variable -Name allResources -Scope Global -ErrorAction SilentlyContinue) -or -not $global:allResources){

            Write-Verbose 'Fetching all subscriptions and resources...'
            $subs = Get-AzSubscription
            $global:allResources = @()
            foreach ($sub in $subs) {
                Write-Host "Switching to subscription $($sub.Name) ($($sub.Id))"
                Set-AzContext -Subscription $sub.Id | Out-Null

                $resources = Get-AzResource -ErrorAction SilentlyContinue
                foreach ($res in $resources){
                    if (-not (($global:allResources).ResourceId -contains $res.Id)){
                            $global:allResources += $res
                        }

                    if ($ScanSubResources.IsPresent){
                        $providerName = $res.ResourceType.Split("/")[0]
                        $resType = $res.ResourceType.Replace("$providerName/","")
                        Get-MapAzResourceAndSubResources -SubscriptionId $sub -ResGroup $res.ResourceGroupName -ProviderName $providerName -ResourceName $res.Name -ResourceType $resType
                    } 
                }                     
            }
                     
        }
                     
    }

    process {
        if ($Scope -or $ResType) {
            # Filter the fresh or cached list
            ($global:allResources).Where({
                ($_.ResourceId -like "$Scope*") -and ($_.ResourceType -like "$ResType*")
            }) 
        }
        else {
            # Return a shallow copy of the full list
            $global:allResources | ForEach-Object { $_ }
        }
    }
}

function Resolve-MapAzAccessPlane {
    [CmdletBinding()]
    param(
        [Parameter()]

        [string[]] $Actions,

        [Parameter()]
        [string] $ResourceScope,

        [Parameter(Mandatory)]
        [string]$Plane,

        [string[]] $NotActions,
        [bool]$IsDataAction
    )

    begin {
        $OpsByAction = @{}
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
            if (-not $OpsByAction.ContainsKey($ns)) {
                Write-Verbose "Fetching provider operations for namespace '$ns'"
                $OpsByAction[$action] = Get-MapAzProviderOperations -action $action -IsDataAction $IsDataAction
            }

            #Remove actions negated by not actions
            $allowedOps = ($OpsByAction[$action]).Where({
                            foreach ($notAction in $NotActions){
                                if ($_.Operation -like $notAction) {return $false}
                            }
                            return $true
                        })

            $nonResourceOperations = $allowedOps.Where({-not $_.ResourceName -and $_.IsDataAction -eq $false})
            foreach ($nonResOp in $nonResourceOperations){
                $resAccessList.Add([PSCustomObject]@{
                                    ResourceId     = $null
                                    ResourceType   = $null
                                    ResourceName   = $null
                                    Operation      = $nonResOp.Operation
                                    OperationType  = $nonResOp.Operation.Split('/')[-1]
                                    Plane          = "Control"
                                })
            }

            Write-Verbose "Getting resources of type '$prov' under '$ResourceScope'"
            $resources = Get-MapAzResource -Scope $ResourceScope -ResType $prov
            Write-Verbose "Found $($resources.Count) matching resources"

            $resources | Group-Object -Property ResourceType | ForEach-Object {
                $type  = $_.Name
                $group = $_.Group

                Write-Verbose "Filtering operations for resource type '$type'"
                $matches = $allowedOps.Where({$_.Operation -like "$type/$op"})
                Write-Verbose "Found $($matches.Count) matching operations for a resource of type '$type'"

                foreach ($r in $group) {
                    foreach ($mo in $matches) {
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
        return $resAccessList | Sort-Object ResourceId, ResourceType ,ResourceName, Operation, OperationType, Plane -Unique
    }
}

function Get-MapAzRoleAssignmentAccess {
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
        Write-Host  "Resolving assignments for role $($Assignment.RoleDefinitionName)"
       
        $resScope = if ($ResourceScope) { $ResourceScope.ToLower() } else { $null }

        $roleAccessList = [System.Collections.Generic.List[PSCustomObject]]::new()

        if (-not $global:OpsByRoleAssignment) {
            Write-Verbose "Initializing role assugment cache..."
            $global:OpsByRoleAssignment = @{}
        }
    }

    process {
        $roles = Get-MapAzRoleDefinitions -roleId $Assignment.RoleDefinitionId
        foreach ($role in $roles) {
            $scope = $Assignment.Scope
            if ( -not $global:OpsByRoleAssignment.ContainsKey($Assignment.RoleAssignmentId)){

                Write-Host  "Processing Role '$($role.Name)' for scope '$scope'"
                if (-not $resScope -or $resScope.StartsWith($scope.ToLower())) {
                    
                    $actions = $role.Actions
                    $notactions = $role.NotActions

                    Write-Verbose "Fetching control plane operations for role '$($Assignment.RoleAssignmentId)'"
                    Resolve-MapAzAccessPlane -Actions $actions -NotActions $notactions -ResourceScope $resScope -Plane "Control" -IsDataAction $false | 
                    ForEach-Object { $roleAccessList.Add($_) }

                    $dataActions = $role.DataActions
                    $notDataActions = $role.NotDataActions

                    Write-Verbose "Fetching data plane operations for role '$($Assignment.RoleAssignmentId)'"
                    Resolve-MapAzAccessPlane -Actions $dataActions -NotActions $notDataActions -ResourceScope $resScope -Plane "Data" -IsDataAction $true |
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

function Get-MapAzUserAccess {
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
        if ($PSCmdlet.ParameterSetName -eq 'ByUPN') {
        
            $userassignments = Get-MapAzRoleAssignments -UserName $UserPrincipalName -ErrorAction SilentlyContinue
            $currUserId = (Get-MapAzUsers -userPrincipalName $UserPrincipalName).Id 
            $currUserPrincipalName = $UserPrincipalName
        }
        else {
            $userassignments = Get-MapAzRoleAssignments -UserId $UserId -ErrorAction SilentlyContinue
            $currUserPrincipalName = (Get-MapAzUsers -userId $UserId).UserPrincipalName
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

            Get-MapAzRoleAssignmentAccess -Assignment $assignment -ResourceScope $resScope
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
                        $op.ResourceType,
                        $op.Operation,
                        $op.OperationType,
                        $currUserId,
                        $currUserPrincipalName,
                        $op.Plane
                    )
                }
            }
        }

        Write-Host  "Filtering duplicate operations..."

        $results = $results | Sort-Object UserId,UserName, ResourceId, ResourceName, ResourceType, Operation, OperationType -Unique

        Write-Host "Total assigned roles for $$currUserPrincipalName: $assignmentCount"
        Write-Host "Total unique access entries: $($results.Count)"
        return $results
    }
}

function Get-MapAzAllUsersAccess {
    [CmdletBinding()]
    param()
    
    begin {
            Write-Host  "Collecting assignments for all users and converting to access objects..."
    }
    process {
        $allAccess = Get-MapAzUsers | ForEach-Object {Get-MapAzUserAccess -UserId $_.Id}
    }

    end 
    {
        return $allAccess
    }
}


# Export the function when the module is imported
Export-ModuleMember -Function Get-MapAzUserAssigments,Get-MapAzResource,Test-MapAzUserGroupMembership,
                                Get-MapAzRoleAssignments,Clear-MapAzScriptCache,Get-MapAzUserAccess,
                                Get-MapAzUsers,Get-MapAzProviderOperations,Get-MapAzResourceProvider,
                                Get-MapAzAllUsersAccess,Get-MapAzResourceViaRESTAPI,Get-MapAzResourceAndSubResources,
                                Get-MapAzResourceViaNativeRESTAPI,Get-MapAzThrottleLimit,Set-MapAzThrottleLimit