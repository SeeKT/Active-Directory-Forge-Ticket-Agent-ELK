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
# Phase 2: Silver Ticket Minimal Check
# Identify Silver Ticket with minimum required evidence
# ============================================================
#
# Essential 3-point check (time-series aware):
#   1. Rubeus.exe silver execution (ST direct forgery)
#   2. 4672 privilege assignment shortly after Rubeus (ST usage proof)
#   3. No 4768/4769 on client side OP01 (no DC communication)
#

# ============================================================
# Configuration
# ============================================================

$esHost = "https://localhost:19200"
$username = "elastic"

# Generate timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Read password from stdin
Write-Host "Enter Elasticsearch password: " -ForegroundColor Yellow -NoNewline
$securePassword = Read-Host -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

$outputDir = ".\SilverTicketMinimal_$timestamp"

# Target time window: 05:21:30 UTC +/- 15 minutes
$startTime = "2025-12-07T05:06:30Z"
$endTime = "2025-12-07T05:36:30Z"

# ============================================================
# Initialize
# ============================================================

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
    Write-Host "Output directory: $outputDir" -ForegroundColor Green
}

$auth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$username`:$password"))

function Invoke-ElasticsearchQuery {
    param(
        [string]$IndexPattern,
        [string]$QueryJson
    )
    
    $uri = "$esHost/$IndexPattern/_search"
    $tempFile = "$env:TEMP\es_query_$(Get-Random).json"
    [System.IO.File]::WriteAllText($tempFile, $QueryJson, [System.Text.UTF8Encoding]::new())
    
    try {
        $result = curl.exe -s -k -H "Authorization: Basic $auth" -H "Content-Type: application/json" -X POST -d "@$tempFile" $uri 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [ERROR] Elasticsearch connection failed" -ForegroundColor Red
            return $null
        }
        
        $parsedResult = $result | ConvertFrom-Json -ErrorAction Stop
        return $parsedResult
    }
    catch {
        Write-Host "  [ERROR] Query execution failed: $_" -ForegroundColor Red
        return $null
    }
    finally {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================
# Display Header
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Silver Ticket Minimal Check" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Elasticsearch: $esHost"
Write-Host "Time Window: $startTime to $endTime (UTC)"
Write-Host ""

# ============================================================
# Essential Check 1: Rubeus.exe silver execution
# ============================================================

Write-Host "1. Rubeus.exe silver execution (ST direct forgery)" -ForegroundColor Yellow

$query1 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "1" } },
        { "term": { "host.name": "op01" } },
        { "wildcard": { "process.executable": "*Rubeus*" } },
        { "wildcard": { "process.command_line": "*silver*" } },
        {
          "range": {
            "@timestamp": {
              "gte": "START_TIME",
              "lte": "END_TIME"
            }
          }
        }
      ]
    }
  },
  "size": 100,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@

$query1 = $query1 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response1 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query1

if ($null -eq $response1) {
    exit 1
}

$rubeusFound = $response1.hits.total.value -gt 0

Write-Host "   Result: $($response1.hits.total.value) records"
if ($rubeusFound) {
    Write-Host "   [+] Rubeus.exe silver detected" -ForegroundColor Green
    $response1.hits.hits | ForEach-Object {
        Write-Host "       Time: $($_._source.'@timestamp')"
        Write-Host "       Host: $($_._source.host.name)"
        Write-Host "       Process: $($_._source.process.executable)"
        Write-Host "       Command: $($_._source.process.command_line)"
    }
} else {
    Write-Host "   [-] Rubeus.exe silver NOT detected (likely NOT Silver Ticket)" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================
# Essential Check 2: Event 4672 privilege assignment (ST usage)
# ============================================================

Write-Host "2. Event 4672 privilege assignment (ST usage proof)" -ForegroundColor Yellow

$query2 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "4672" } },
        {
          "range": {
            "@timestamp": {
              "gte": "START_TIME",
              "lte": "END_TIME"
            }
          }
        }
      ],
      "filter": [
        {
          "bool": {
            "must_not": [
              { "term": { "user.name": "SYSTEM" } },
              { "wildcard": { "user.name": "*$" } }
            ]
          }
        }
      ]
    }
  },
  "size": 100,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@

$query2 = $query2 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response2 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query2

$privilegeFound = $response2.hits.total.value -gt 0

Write-Host "   Result: $($response2.hits.total.value) records"
if ($privilegeFound) {
    Write-Host "   [+] Privilege assignments detected" -ForegroundColor Green
    $response2.hits.hits | ForEach-Object {
        Write-Host "       Time: $($_._source.'@timestamp')"
        Write-Host "       Host: $($_._source.host.name)"
        Write-Host "       User: $($_._source.user.domain)\$($_._source.user.name)"
    }
} else {
    Write-Host "   [-] No privilege assignments" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================
# Time-series analysis: Check pattern
# ============================================================

Write-Host "Time-series Pattern Analysis" -ForegroundColor Yellow

# Extract Rubeus time
$rubeusTime = $null
if ($rubeusFound) {
    $rubeusTime = [datetime]$response1.hits.hits[0]._source.'@timestamp'
    Write-Host "   Rubeus silver time: $rubeusTime (UTC)"
}

# Extract 4672 time
$privilegeTime = $null
if ($privilegeFound) {
    $privilegeTime = [datetime]$response2.hits.hits[0]._source.'@timestamp'
    Write-Host "   First 4672 time: $privilegeTime (UTC)"
}

# Check time delta
$timeDelta = $null
if ($rubeusTime -and $privilegeTime) {
    $timeDelta = ($privilegeTime - $rubeusTime).TotalSeconds
    Write-Host "   Time delta: $([math]::Round($timeDelta, 1)) seconds"
    
    if ($timeDelta -ge 0 -and $timeDelta -le 60) {
        Write-Host "   [+] Pattern match: 4672 within 60 seconds after Rubeus" -ForegroundColor Green
    } else {
        Write-Host "   [-] Pattern mismatch: time gap too large" -ForegroundColor Yellow
    }
}

Write-Host ""

# ============================================================
# Time-series Check: Client-side 4768/4769 during attack window
# ============================================================

Write-Host "4. Client-side 4768/4769 timeline (attack detection)" -ForegroundColor Yellow

# Get 4768/4769 on DC and client separately
$query3a = @'
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "event.code": ["4768", "4769"] } },
        { "term": { "host.name": "dc" } },
        {
          "range": {
            "@timestamp": {
              "gte": "START_TIME",
              "lte": "END_TIME"
            }
          }
        }
      ]
    }
  },
  "size": 100,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@

$query3a = $query3a -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response3a = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query3a

Write-Host "   DC side 4768/4769: $($response3a.hits.total.value) records (normal activity expected)"

# Client side (OP01)
$query3b = @'
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "event.code": ["4768", "4769"] } },
        { "term": { "host.name": "op01" } },
        {
          "range": {
            "@timestamp": {
              "gte": "START_TIME",
              "lte": "END_TIME"
            }
          }
        }
      ]
    }
  },
  "size": 10,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@

$query3b = $query3b -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response3b = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query3b

$clientKerberosAbsent = $response3b.hits.total.value -eq 0

Write-Host "   OP01 side 4768/4769: $($response3b.hits.total.value) records"
if ($clientKerberosAbsent) {
    Write-Host "   [+] No client-side Kerberos logs on OP01 during attack window" -ForegroundColor Green
    Write-Host "       -> ST used directly, bypassing DC" -ForegroundColor Green
} else {
    Write-Host "   [-] Client-side logs present (likely Golden Ticket, not Silver)" -ForegroundColor Yellow
    $response3b.hits.hits | Select-Object -First 3 | ForEach-Object {
        Write-Host "       EventID: $($_._source.event.code), Time: $($_._source.'@timestamp')"
    }
}

Write-Host ""

# ============================================================
# Export Results
# ============================================================

Write-Host "[Export]" -ForegroundColor Cyan

# Point 1: Rubeus
$jsonFile1 = "$outputDir\01_Rubeus_$timestamp.json"
$response1 | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile1 -Encoding UTF8
Write-Host "  Rubeus: $jsonFile1"

$csvFile1 = "$outputDir\01_Rubeus_$timestamp.csv"
$response1.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='Host'; e={$_._source.host.name}}, @{n='Process'; e={$_._source.process.executable}}, @{n='CommandLine'; e={$_._source.process.command_line}} | Export-Csv -Path $csvFile1 -Encoding UTF8 -NoTypeInformation
Write-Host "  Rubeus CSV: $csvFile1"

# Point 2: Privilege
$jsonFile2 = "$outputDir\02_Privilege_$timestamp.json"
$response2 | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile2 -Encoding UTF8
Write-Host "  Privilege: $jsonFile2"

$csvFile2 = "$outputDir\02_Privilege_$timestamp.csv"
$response2.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='Host'; e={$_._source.host.name}}, @{n='User'; e={$_._source.user.domain + "\" + $_._source.user.name}} | Export-Csv -Path $csvFile2 -Encoding UTF8 -NoTypeInformation
Write-Host "  Privilege CSV: $csvFile2"

# Point 3: Client Kerberos
$jsonFile3a = "$outputDir\03a_ClientKerberos_DC_$timestamp.json"
$response3a | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile3a -Encoding UTF8
Write-Host "  Client Kerberos (DC) JSON: $jsonFile3a"

$csvFile3a = "$outputDir\03a_ClientKerberos_DC_$timestamp.csv"
$response3a.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='TargetUser'; e={$_._source.winlog.event_data.TargetUserName}}, @{n='ServiceName'; e={$_._source.winlog.event_data.ServiceName}}, @{n='SourceIP'; e={$_._source.source.ip}} | Export-Csv -Path $csvFile3a -Encoding UTF8 -NoTypeInformation
Write-Host "  Client Kerberos (DC) CSV: $csvFile3a"

$jsonFile3b = "$outputDir\03b_ClientKerberos_OP01_$timestamp.json"
$response3b | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile3b -Encoding UTF8
Write-Host "  Client Kerberos (OP01) JSON: $jsonFile3b"

$csvFile3b = "$outputDir\03b_ClientKerberos_OP01_$timestamp.csv"
$response3b.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='TargetUser'; e={$_._source.winlog.event_data.TargetUserName}}, @{n='ServiceName'; e={$_._source.winlog.event_data.ServiceName}}, @{n='SourceIP'; e={$_._source.source.ip}} | Export-Csv -Path $csvFile3b -Encoding UTF8 -NoTypeInformation
Write-Host "  Client Kerberos (OP01) CSV: $csvFile3b"

Write-Host ""

# ============================================================
# Verdict
# ============================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Verdict" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$essentialPoints = 0
$patternMatch = $false

if ($rubeusFound) { 
    $essentialPoints += 1
    Write-Host "[+] 1. Rubeus.exe silver: DETECTED"
} else {
    Write-Host "[-] 1. Rubeus.exe silver: NOT detected"
}

# Check time pattern
if ($rubeusTime -and $privilegeTime -and $timeDelta -ge 0 -and $timeDelta -le 60) {
    $patternMatch = $true
    Write-Host "[+] 2. 4672 within 60 sec after Rubeus: DETECTED (pattern match)"
    $essentialPoints += 1
} elseif ($privilegeFound) {
    Write-Host "[+] 2. 4672 privilege assignment: DETECTED (but timing mismatch)"
    $essentialPoints += 0.5
} else {
    Write-Host "[-] 2. 4672 privilege assignment: NOT detected"
}

if ($clientKerberosAbsent) { 
    $essentialPoints += 1
    Write-Host "[+] 3. Client-side 4768/4769 on OP01: ABSENT"
    Write-Host "       (ST bypassed DC, used directly on target)"
} else {
    Write-Host "[-] 3. Client-side 4768/4769 on OP01: PRESENT"
}

Write-Host ""

$verdict = ""
if ($essentialPoints -eq 3 -and $patternMatch) {
    $verdict = "[CRITICAL] Silver Ticket attack CONFIRMED"
    Write-Host $verdict -ForegroundColor Red
    Write-Host "  All 3 essential indicators with time-series pattern match:"
    Write-Host "  1. Rubeus silver (ST direct forgery)"
    Write-Host "  2. 4672 within 60 seconds (ST usage proof)"
    Write-Host "  3. No client-side Kerberos on OP01 (DC bypassed)"
} elseif ($essentialPoints -ge 2.5) {
    $verdict = "[HIGH] Silver Ticket likely confirmed"
    Write-Host $verdict -ForegroundColor Yellow
} elseif ($essentialPoints -ge 2) {
    $verdict = "[MEDIUM] Silver Ticket possible"
    Write-Host $verdict -ForegroundColor Yellow
} else {
    $verdict = "[LOW] Silver Ticket not detected"
    Write-Host $verdict -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Output: $outputDir" -ForegroundColor Green
Write-Host "Done" -ForegroundColor Green
