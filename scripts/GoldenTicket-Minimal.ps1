<#
.SPDX-License-Identifier: MIT
.Copyright (c) 2026 ktod4ts
.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#>

# ============================================================
# Phase 1: Golden Ticket Analysis (Minimal)
# ============================================================

# ============================================================
# Configuration
# ============================================================

$esHost = "https://localhost:19200"
$username = "elastic"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "Enter Elasticsearch password: " -ForegroundColor Yellow -NoNewline
$securePassword = Read-Host -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

$outputDir = ".\Phase1_GoldenTicket_Minimal_$timestamp"
$startTime = "2025-12-07T04:38:03Z"
$endTime = "2025-12-07T05:08:03Z"

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Green
}

$auth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$username`:$password"))

function Invoke-ElasticsearchQuery {
    param([string]$IndexPattern, [string]$QueryJson)
    
    $uri = "$esHost/$IndexPattern/_search"
    $tempFile = "$env:TEMP\es_query_$(Get-Random).json"
    [System.IO.File]::WriteAllText($tempFile, $QueryJson, [System.Text.UTF8Encoding]::new())
    
    try {
        $result = curl.exe -s -k -H "Authorization: Basic $auth" -H "Content-Type: application/json" -X POST -d "@$tempFile" $uri 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [ERROR] curl exit code: $LASTEXITCODE" -ForegroundColor Red
            return $null
        }
        return $result | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Host "  [ERROR] $_" -ForegroundColor Red
        return $null
    }
    finally {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Phase 1: Golden Ticket Analysis (Minimal)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# Point 1: TGT Request (4768)
# ============================================================

Write-Host "[Point 1] 4768 - TGT Request (Legitimate Login)" -ForegroundColor Yellow

$query1 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "4768" } },
        { "range": { "@timestamp": { "gte": "START_TIME", "lte": "END_TIME" } } }
      ]
    }
  },
  "size": 100,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@
$query1 = $query1 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime
$response1 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query1
if ($null -eq $response1) { exit 1 }
Write-Host "  Found: $($response1.hits.total.value) records" -ForegroundColor Green

# ============================================================
# Point 2: Service Ticket Requests (4769) - Multiple Services/Users
# ============================================================

Write-Host ""
Write-Host "[Point 2] 4769 - Service Ticket Requests (Multiple Services/Users)" -ForegroundColor Yellow

$query2 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "4769" } },
        { "range": { "@timestamp": { "gte": "START_TIME", "lte": "END_TIME" } } }
      ]
    }
  },
  "size": 100,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@
$query2 = $query2 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime
$response2 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query2
if ($null -eq $response2) { exit 1 }
Write-Host "  Found: $($response2.hits.total.value) records" -ForegroundColor Green

# Analyze by service and user
$serviceGroups = $response2.hits.hits | Group-Object { $_._source.winlog.event_data.ServiceName }
$userGroups = $response2.hits.hits | Group-Object { $_._source.winlog.event_data.TargetUserName }
Write-Host "  Services: $($serviceGroups.Count) types" -ForegroundColor Cyan
$serviceGroups | ForEach-Object { Write-Host "    - $($_.Name): $($_.Count)" }
Write-Host "  Users: $($userGroups.Count) types" -ForegroundColor Cyan
$userGroups | ForEach-Object { Write-Host "    - $($_.Name): $($_.Count)" }

# ============================================================
# Point 3.5: Rubeus Execution (Sysmon Event 1)
# ============================================================

Write-Host ""
Write-Host "[Point 3.5] Sysmon Event 1 - Rubeus.exe Execution" -ForegroundColor Yellow

$query3_5 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "1" } },
        { "term": { "host.name": "op01" } },
        { "wildcard": { "process.executable": "*Rubeus*" } },
        { "range": { "@timestamp": { "gte": "START_TIME", "lte": "END_TIME" } } }
      ]
    }
  },
  "size": 100,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@
$query3_5 = $query3_5 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime
$response3_5 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query3_5
if ($null -eq $response3_5) { exit 1 }
Write-Host "  Found: $($response3_5.hits.total.value) processes" -ForegroundColor Green

# Analyze Rubeus commands
$rubeusCmds = $response3_5.hits.hits | Group-Object { 
    if ($_._source.process.command_line -match 'golden') { 'golden' }
    elseif ($_._source.process.command_line -match 'purge') { 'purge' }
    elseif ($_._source.process.command_line -match 'klist') { 'klist' }
    else { 'other' }
}
Write-Host "  Commands:" -ForegroundColor Cyan
$rubeusCmds | ForEach-Object { Write-Host "    - $($_.Name): $($_.Count)" }

# Show golden ticket commands
$response3_5.hits.hits | Where-Object { $_._source.process.command_line -match 'golden' } | ForEach-Object {
    Write-Host "    Golden Ticket at: $($_._source.'@timestamp')" -ForegroundColor Yellow
    if ($_._source.process.command_line -match '/aes256') {
        Write-Host "      [+] AES256 key detected" -ForegroundColor Green
    }
    if ($_._source.process.command_line -match '/user:Administrator') {
        Write-Host "      [+] /user:Administrator detected" -ForegroundColor Green
    }
    if ($_._source.process.command_line -match '/ptt') {
        Write-Host "      [+] /ptt (Pass-the-Ticket) detected" -ForegroundColor Green
    }
}

# ============================================================
# Point 4.5: Privilege Assignment (Event 4672)
# ============================================================

Write-Host ""
Write-Host "[Point 4.5] Event 4672 - Privilege Assignment (PtT Indicator)" -ForegroundColor Yellow

$query4_5 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "4672" } },
        { "term": { "host.name": "dc" } },
        { "range": { "@timestamp": { "gte": "START_TIME", "lte": "END_TIME" } } }
      ],
      "filter": [
        { "bool": { "must_not": [
          { "term": { "user.name": "SYSTEM" } },
          { "wildcard": { "user.name": "*$" } }
        ] } }
      ]
    }
  },
  "size": 100,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@
$query4_5 = $query4_5 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime
$response4_5 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query4_5
if ($null -eq $response4_5) { exit 1 }
Write-Host "  Found: $($response4_5.hits.total.value) records" -ForegroundColor Green

$response4_5.hits.hits | ForEach-Object {
    Write-Host "  User: $($_._source.user.domain)\$($_._source.user.name)" -ForegroundColor Cyan
    Write-Host "  Time: $($_._source.'@timestamp')" -ForegroundColor Cyan
    Write-Host "  Privileges: $(($_._source.winlog.event_data.PrivilegeList | Measure-Object).Count) granted" -ForegroundColor Cyan
    Write-Host "  Details:" -ForegroundColor Cyan
    $_._source.winlog.event_data.PrivilegeList | ForEach-Object {
        Write-Host "    - $_"
    }
}

# ============================================================
# Export Results
# ============================================================

Write-Host ""
Write-Host "[Export]" -ForegroundColor Cyan

# Point 1: 4768 TGT
$response1 | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\01_4768_TGT_$timestamp.json" -Encoding UTF8
$response1.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='TargetUser'; e={$_._source.winlog.event_data.TargetUserName}}, @{n='SourceIP'; e={$_._source.source.ip}} | Export-Csv -Path "$outputDir\01_4768_TGT_$timestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  Point 1 (4768): JSON and CSV exported"

# Point 2: 4769 ST
$response2 | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\02_4769_ST_$timestamp.json" -Encoding UTF8
$response2.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='TargetUser'; e={$_._source.winlog.event_data.TargetUserName}}, @{n='ServiceName'; e={$_._source.winlog.event_data.ServiceName}}, @{n='SourceIP'; e={$_._source.source.ip}} | Export-Csv -Path "$outputDir\02_4769_ST_$timestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  Point 2 (4769): JSON and CSV exported"

# Point 3.5: Rubeus
$response3_5 | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\03_5_Rubeus_$timestamp.json" -Encoding UTF8
$response3_5.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='ProcessName'; e={$_._source.process.name}}, @{n='CommandLine'; e={$_._source.process.command_line}} | Export-Csv -Path "$outputDir\03_5_Rubeus_$timestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  Point 3.5 (Rubeus): JSON and CSV exported"

# Point 4.5: Event 4672
$response4_5 | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\04_5_4672_Priv_$timestamp.json" -Encoding UTF8
$response4_5.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='User'; e={$_._source.user.name}}, @{n='Domain'; e={$_._source.user.domain}}, @{n='PrivilegeCount'; e={$_._source.winlog.event_data.PrivilegeList.Count}} | Export-Csv -Path "$outputDir\04_5_4672_Priv_$timestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  Point 4.5 (4672): JSON and CSV exported"

Write-Host "  Output directory: $outputDir" -ForegroundColor Green

# ============================================================
# Verdict
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Verdict" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

$criticalIndicators = 0

if ($response2.hits.total.value -gt 3) { $criticalIndicators += 1 }
if ($response3_5.hits.total.value -gt 0) { $criticalIndicators += 1 }
if ($response4_5.hits.total.value -gt 0) { $criticalIndicators += 1 }

Write-Host "Critical Indicators: $criticalIndicators / 3"
Write-Host ""

if ($criticalIndicators -eq 3) {
    Write-Host "[CRITICAL] Golden Ticket attack almost certainly confirmed" -ForegroundColor Red
    Write-Host "Evidence:" -ForegroundColor Red
    Write-Host "  1. Multiple services (4769)" -ForegroundColor Green
    Write-Host "  2. Rubeus golden ticket generation" -ForegroundColor Green
    Write-Host "  3. Non-SYSTEM privilege assignment (4672)" -ForegroundColor Green
} elseif ($criticalIndicators -eq 2) {
    Write-Host "[HIGH] Golden Ticket likely confirmed" -ForegroundColor Yellow
} else {
    Write-Host "[MEDIUM] Further investigation needed" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Analysis complete!" -ForegroundColor Green
