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
# Phase 3: Diamond Ticket Detection - Minimal Analysis
# ============================================================
#
# Focus: 4 key detection points only
#   1. 4768 - TGT request (confirm DC communication)
#   2. 4769 - Service ticket requests (multiple services)
#   3. 4672 - Privilege assignment (KEY INDICATOR)
#   4. Sysmon - Rubeus/PsExec execution
#

# ============================================================
# Configuration
# ============================================================

$esHost = "https://localhost:19200"
$username = "elastic"

# Generate timestamp for output filename
$outputTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Read password
Write-Host "Enter Elasticsearch password: " -ForegroundColor Yellow -NoNewline
$securePassword = Read-Host -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

$outputDir = ".\Phase3_DiamondTicket_Minimal_$outputTimestamp"

# Target time window
$startTime = "2025-12-07T05:38:16Z"
$endTime = "2025-12-07T06:08:16Z"

# ============================================================
# Initialize
# ============================================================

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Green
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
            Write-Host "  [CURL ERROR] Exit Code: $LASTEXITCODE" -ForegroundColor Red
            return $null
        }
        
        $parsedResult = $result | ConvertFrom-Json -ErrorAction Stop
        return $parsedResult
    }
    catch {
        Write-Host "  [JSON PARSE ERROR] $_" -ForegroundColor Red
        return $null
    }
    finally {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Phase 3: Diamond Ticket Detection (Minimal)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Period: $startTime to $endTime (UTC)"
Write-Host ""

# ============================================================
# Point 1: 4768 (TGT Request)
# ============================================================

Write-Host "[Point 1] 4768 - TGT Request (DC Communication)" -ForegroundColor Yellow

$query1 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "4768" } },
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
Write-Host "  Result: $($response1.hits.total.value) records" -ForegroundColor Green

# ============================================================
# Point 2: 4769 (Service Ticket Requests)
# ============================================================

Write-Host ""
Write-Host "[Point 2] 4769 - Service Ticket Requests (Multiple Services)" -ForegroundColor Yellow

$query2 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "4769" } },
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

$query2 = $query2 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response2 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query2
Write-Host "  Result: $($response2.hits.total.value) records" -ForegroundColor Green

# Service distribution
$serviceList = @()
$response2.hits.hits | ForEach-Object {
    $serviceName = $_._source.winlog.event_data.ServiceName
    if ($serviceName) {
        $serviceList += $serviceName
    }
}
$uniqueServices = $serviceList | Sort-Object -Unique
Write-Host "  Services: $($uniqueServices.Count) unique types" -ForegroundColor Cyan
$serviceList | Group-Object | ForEach-Object {
    Write-Host "    - $($_.Name): $($_.Count) records"
}

# ============================================================
# Point 3: 4672 (Privilege Assignment - KEY INDICATOR)
# ============================================================

Write-Host ""
Write-Host "[Point 3] 4672 - Privilege Assignment (KEY INDICATOR)" -ForegroundColor Yellow

$query3 = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "4672" } },
        { "term": { "host.name": "dc" } },
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

$query3 = $query3 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response3 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query3
Write-Host "  Result: $($response3.hits.total.value) records" -ForegroundColor Green

if ($response3.hits.total.value -gt 0) {
    Write-Host "  [!] Suspicious privilege assignments detected:" -ForegroundColor Red
    $response3.hits.hits | ForEach-Object {
        $eventTime = $_._source.'@timestamp'
        $user = $_._source.user.name
        $domain = $_._source.user.domain
        $privCount = ($_._source.winlog.event_data.PrivilegeList | Measure-Object).Count
        Write-Host "      $eventTime | $domain\$user | $privCount privileges" -ForegroundColor Red
    }
}

# ============================================================
# Point 4: Sysmon Event ID 1 (Rubeus/PsExec Execution)
# ============================================================

Write-Host ""
Write-Host "[Point 4] Sysmon - Rubeus/PsExec Execution" -ForegroundColor Yellow

# Search for Rubeus
$query4a = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "1" } },
        { "wildcard": { "process.executable": "*Rubeus*" } },
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

$query4a = $query4a -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime
$response4a = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query4a

# Search for PsExec
$query4b = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "1" } },
        {
          "bool": {
            "should": [
              { "term": { "process.name": "PsExec64.exe" } },
              { "term": { "process.name": "PsExec.exe" } }
            ]
          }
        },
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

$query4b = $query4b -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime
$response4b = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query4b

Write-Host "  Rubeus: $($response4a.hits.total.value) records" -ForegroundColor Green
Write-Host "  PsExec: $($response4b.hits.total.value) records" -ForegroundColor Green

if ($response4a.hits.total.value -gt 0) {
    Write-Host "  [!] Rubeus execution detected:" -ForegroundColor Red
    $response4a.hits.hits | ForEach-Object {
        $eventTime = $_._source.'@timestamp'
        $command = $_._source.process.command_line
        Write-Host "      $eventTime | $command" -ForegroundColor Red
    }
}

if ($response4b.hits.total.value -gt 0) {
    Write-Host "  [!] PsExec execution detected:" -ForegroundColor Red
    $response4b.hits.hits | ForEach-Object {
        $eventTime = $_._source.'@timestamp'
        $command = $_._source.process.command_line
        Write-Host "      $eventTime | $command" -ForegroundColor Red
    }
}

# ============================================================
# Export Results
# ============================================================

Write-Host ""
Write-Host "[Data Export]" -ForegroundColor Cyan

# Point 1: 4768
$response1 | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\01_Point1_4768_$outputTimestamp.json" -Encoding UTF8
Write-Host "  01_Point1_4768_$outputTimestamp.json"

$response1.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='User'; e={$_._source.winlog.event_data.TargetUserName}}, @{n='SourceIP'; e={$_._source.source.ip}} | Export-Csv -Path "$outputDir\01_Point1_4768_$outputTimestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  01_Point1_4768_$outputTimestamp.csv"

# Point 2: 4769
$response2 | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\02_Point2_4769Services_$outputTimestamp.json" -Encoding UTF8
Write-Host "  02_Point2_4769Services_$outputTimestamp.json"

$response2.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='User'; e={$_._source.winlog.event_data.TargetUserName}}, @{n='ServiceName'; e={$_._source.winlog.event_data.ServiceName}} | Export-Csv -Path "$outputDir\02_Point2_4769Services_$outputTimestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  02_Point2_4769Services_$outputTimestamp.csv"

# Point 3: 4672
$response3 | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\04_5_Point4_5_PrivilegeAssignment_$outputTimestamp.json" -Encoding UTF8
Write-Host "  04_5_Point4_5_PrivilegeAssignment_$outputTimestamp.json"

$response3.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='User'; e={$_._source.user.name}}, @{n='Domain'; e={$_._source.user.domain}}, @{n='PrivilegeCount'; e={($_._source.winlog.event_data.PrivilegeList | Measure-Object).Count}}, @{n='Privileges'; e={($_._source.winlog.event_data.PrivilegeList | ConvertTo-Json -Compress)}} | Export-Csv -Path "$outputDir\04_5_Point4_5_PrivilegeAssignment_$outputTimestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  04_5_Point4_5_PrivilegeAssignment_$outputTimestamp.csv"

# Point 4a: Rubeus
$response4a | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\02_5_Point2_5_SysmonRubeusMimikatz_$outputTimestamp.json" -Encoding UTF8
Write-Host "  02_5_Point2_5_SysmonRubeusMimikatz_$outputTimestamp.json"

$response4a.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='ProcessName'; e={$_._source.process.name}}, @{n='CommandLine'; e={$_._source.process.command_line}} | Export-Csv -Path "$outputDir\02_5_Point2_5_SysmonRubeusMimikatz_$outputTimestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  02_5_Point2_5_SysmonRubeusMimikatz_$outputTimestamp.csv"

# Point 4b: PsExec
$response4b | ConvertTo-Json -Depth 10 | Out-File -FilePath "$outputDir\05_Point5_PsExec_$outputTimestamp.json" -Encoding UTF8
Write-Host "  05_Point5_PsExec_$outputTimestamp.json"

$response4b.hits.hits | Select-Object @{n='Timestamp'; e={$_._source.'@timestamp'}}, @{n='EventID'; e={$_._source.event.code}}, @{n='Computer'; e={$_._source.host.name}}, @{n='ProcessName'; e={$_._source.process.name}}, @{n='CommandLine'; e={$_._source.process.command_line}} | Export-Csv -Path "$outputDir\05_Point5_PsExec_$outputTimestamp.csv" -Encoding UTF8 -NoTypeInformation
Write-Host "  05_Point5_PsExec_$outputTimestamp.csv"

# ============================================================
# Analysis Result
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Detection Result" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

$indicators = 0

Write-Host ""
Write-Host "Point 1 (4768 - DC Communication):"
if ($response1.hits.total.value -gt 0) {
    Write-Host "  [OK] Detected ($($response1.hits.total.value) events)" -ForegroundColor Green
    $indicators += 1
} else {
    Write-Host "  [!] Not detected (possible Silver Ticket)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Point 2 (4769 - Multiple Services):"
if ($response2.hits.total.value -gt 3) {
    Write-Host "  [OK] Detected ($($response2.hits.total.value) events, $($uniqueServices.Count) service types)" -ForegroundColor Green
    $indicators += 1
} else {
    Write-Host "  [!] Low count ($($response2.hits.total.value) events)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Point 3 (4672 - Privilege Assignment - KEY INDICATOR):"
if ($response3.hits.total.value -gt 0) {
    Write-Host "  [CRITICAL] Detected ($($response3.hits.total.value) events)" -ForegroundColor Red
    $indicators += 1
} else {
    Write-Host "  [OK] Not detected (no suspicious privilege assignment)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Point 4 (Sysmon - Tool Execution):"
$toolCount = $response4a.hits.total.value + $response4b.hits.total.value
if ($toolCount -gt 0) {
    Write-Host "  [OK] Detected ($toolCount events: Rubeus=$($response4a.hits.total.value), PsExec=$($response4b.hits.total.value))" -ForegroundColor Green
    $indicators += 1
} else {
    Write-Host "  [!] Not detected" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Verdict:" -ForegroundColor Green

if ($indicators -eq 4) {
    Write-Host "[CRITICAL] Diamond Ticket attack CONFIRMED" -ForegroundColor Red
    Write-Host "All 4 indicators present -> Attack confirmed" -ForegroundColor Red
} elseif ($indicators -eq 3) {
    Write-Host "[HIGH] Diamond Ticket attack LIKELY" -ForegroundColor Green
    Write-Host "3 out of 4 indicators present" -ForegroundColor Green
} elseif ($indicators -ge 2) {
    Write-Host "[MEDIUM] Diamond Ticket attack POSSIBLE" -ForegroundColor Yellow
    Write-Host "Further investigation needed" -ForegroundColor Yellow
} else {
    Write-Host "[LOW] Diamond Ticket unlikely" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Output: $outputDir" -ForegroundColor Green
Write-Host "Complete!" -ForegroundColor Green
