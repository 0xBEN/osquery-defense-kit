[CmdletBinding()]
param()

# Check for required module
if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
    throw "This script requires the module 'powershell-yaml'. Please install to proceed."
}

# Check if we're running in the root of the repo
$checkPwd = git remote get-url --all origin 2>/dev/null
if (($checkPwd -notlike 'https://github.com/*/osquery-defense-kit') -or (-not (Get-ChildItem $PWD -Hidden -Directory -Name '.git'))) {
    throw "Please run this script in the root of the repository."
}

# Check if the target directories containing the .SQL files are present
$targetDirectories = @('detection', 'incident_response', 'policy')
$allDirectories = Get-ChildItem -Directory | Select-Object -ExpandProperty Name
$missingDirectories = $targetDirectories | Where-Object {$_ -notin $allDirectories}
if ($missingDirectories) {
    throw "Could not detect the following directories in $PWD`:`n$($missingDirectories -join ', ')"
}

# Create output files
$detectionQueriesTemplate = "$PWD/chainguard-detection-queries.yml"
$irQueriesTemplate = "$PWD/chainguard-IR-queries.yml"
$policiesTemplate = "$PWD/chainguard-policies.yml"
if (-not (Test-Path $detectionQueriesTemplate)) {
    $firstRunDetection = $true
    New-Item -ItemType File -Path $detectionQueriesTemplate | Out-Null
}
if (-not (Test-Path $irQueriesTemplate)) {
    $firstRunIR = $true
    New-Item -ItemType File -Path $irQueriesTemplate | Out-Null
}
if (-not (Test-Path $policiesTemplate)) {
    $firstRunPolicies = $true
    New-Item -ItemType File -Path $policiesTemplate | Out-Null
}
 
# SQL file discovery
$detectionQueryFiles = Get-ChildItem -Path ./detection -File -Recurse -Filter '*.sql'
$IRQueryFiles = Get-ChildItem -Path ./incident_response -File -Recurse -Filter '*.sql'
$policyFiles = Get-ChildItem -Path ./policy -File -Recurse -Filter '*.sql'

if (-not $firstRunDetection) { 
    $detectionYamlDocs = Get-Content $detectionQueriesTemplate | ConvertFrom-Yaml -AllDocuments
}
if (-not $firstRunIR) {
    $irYamlDocs = Get-Content $irQueriesTemplate | ConvertFrom-Yaml -AllDocuments
}
if (-not $firstRunPolicies) {
    $policiesYamlDocs = Get-Content $policiesTemplate | ConvertFrom-Yaml -AllDocuments
}

# Create the YAML output for the detection queries
$detetionQueriesYaml = @()
foreach ($file in $detectionQueryFiles) {
    $query = Get-Content $file
    if (($query | Out-String) -in $detectionYamlDocs.spec.query) {
        Write-Verbose "Existing query found in file: $file"
        $existingQuery = $detectionYamlDocs | Where-Object {$_.spec.query -eq ($query | Out-String)}
        $queryYaml = $existingQuery | ConvertTo-Yaml
    }
    else {
        $splitPath = $file.FullName.Split([System.IO.Path]::DirectorySeparatorChar)
        $queryType = [CultureInfo]::CurrentCulture.TextInfo.ToTitleCase($splitPath[-2])
        $fileName = $splitPath[-1]
        $queryName = $fileName -replace '\.sql', ''
        if ($queryName -like '*-*') {
            $queryName = $queryName -replace '-', ' '
        }
        if ($queryName -like '*_*') {
            $queryName = $queryName -replace '_', ' '
        }
        $queryName = [CultureInfo]::CurrentCulture.TextInfo.ToTitleCase($queryName)
        $queryName = "Detection - $queryType`: $queryName"
        $queryDescription = $query[0] -replace '\-\- ', ''
        $queryObject = [PSCustomObject]@{
            apiVersion = 'v1'
            kind = 'query'
            spec = @{
                name = $queryName
                description = $queryDescription
                query = $query | Out-String
            }
        }
        $queryYaml = $queryObject | ConvertTo-Yaml
    }

$detectionQueriesYaml += @"
---
$queryYaml
"@


}
$detectionQueriesYaml > $detectionQueriesTemplate

# Create the YAML output for IR queries
$IRQueriesYaml = @()
foreach ($file in $IRQueryFiles) {
    $query = Get-Content $file
    if (($query | Out-String) -in $irYamlDocs.spec.query) {
        Write-Verbose "Existing query found in file: $file"
        $existingQuery = $irYamlDocs | Where-Object {$_.spec.query -eq ($query | Out-String)}
        $queryYaml = $existingQuery | ConvertTo-Yaml
    }
    else {
        $splitPath = $file.FullName.Split([System.IO.Path]::DirectorySeparatorChar)
        $fileName = $splitPath[-1]
        $queryName = $fileName -replace '\.sql', ''
        if ($queryName -like '*-*') {
            $queryName = $queryName -replace '-', ' '
        }
        if ($queryName -like '*_*') {
            $queryName = $queryName -replace '_', ' '
        }
        $queryName = [CultureInfo]::CurrentCulture.TextInfo.ToTitleCase($queryName)
        $queryName = "Incident Response: $queryName"
        $queryDescription = $query[0] -replace '\-\- ', ''
        $queryObject = [PSCustomObject]@{
            apiVersion = 'v1'
            kind = 'query'
            spec = @{
                name = $queryName
                description = $queryDescription
                query = $query | Out-String
            }
        }
        $queryYaml = $queryObject | ConvertTo-Yaml
    }

$IRQueriesYaml += @"
---
$queryYaml
"@

}
$IRQueriesYaml > $IRQueriesTemplate

# Create the YAML output for policies
$policiesYaml = @()
foreach ($file in $policyFiles) {
    $query = Get-Content $file
    if (($query | Out-String) -in $policiesYamlDocs.spec.query) {
        Write-Verbose "Existing query found in file: $file"
        $existingPolicy = $policiesYamlDocs | Where-Object {$_.spec.query -eq ($query | Out-String)}
        $policyYaml = $existingPolicy | ConvertTo-Yaml
    }
    else {
        $splitPath = $file.FullName.Split([System.IO.Path]::DirectorySeparatorChar)
        $fileName = $splitPath[-1]
        $policyName = $fileName -replace '\.sql', ''
        if ($policyName -like '*-*') {
            $policyName = $policyName -replace '-', ' '
        }
        if ($policyName -like '*_*') {
            $policyName = $policyName -replace '_', ' '
        }
        $policyName = [CultureInfo]::CurrentCulture.TextInfo.ToTitleCase($policyName)
        $policyDescription = $query[0] -replace '\-\- ', ''
        $policyObject = [PSCustomObject]@{
            apiVersion = 'v1'
            kind = 'policy'
            spec = @{
                name = $policyName
                description = $policyDescription
                query = $query | Out-String
            }
        }
        $policyYaml = $policyObject | ConvertTo-Yaml
    }

$policiesYaml += @"
---
$policyYaml
"@

}
$policiesYaml > $policiesTemplate
