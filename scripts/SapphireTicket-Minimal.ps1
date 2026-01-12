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
# Phase 4: Sapphire Ticket Analysis
# Elasticsearch Data Export
# ============================================================
#
# Analysis Time: 15:30:30 - 15:31:10 JST (06:30:30 - 06:31:10 UTC)
#
# Executed Queries:
#   Point 1: Check 4768 absence
#   Point 2: Check 4769 single service (krbtgt)
#   Point 2.5: Sysmon Event ID 1 (PowerShell/Mimikatz detection)
#   Point 3: Check same IP address for client and DC
#   Point 4: Check access success with same IP
#   Point 4.5: Privilege assignment detection (Event 4672 - PtT Indicator)
#   Point 5: PsExec execution detection (lateral movement)

# ============================================================
# Configuration
# ============================================================

$esHost = "https://localhost:19200"
$username = "elastic"

# Generate timestamp for output directory
$outputTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Read password from stdin
Write-Host "Enter Elasticsearch password: " -ForegroundColor Yellow -NoNewline
$securePassword = Read-Host -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

$outputDir = ".\SapphireTicket_LogExport_$outputTimestamp"

# Target time window
$startTime = "2025-12-07T06:15:30Z"
$endTime = "2025-12-07T06:45:30Z"

# ============================================================
# Initialize
# ============================================================

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Green
}

function Invoke-ElasticsearchQuery {
    param(
        [string]$IndexPattern,
        [string]$QueryJson
    )
    
    $uri = "$esHost/$IndexPattern/_search"
    $tempFile = "$env:TEMP\es_query_$(Get-Random).json"
    [System.IO.File]::WriteAllText($tempFile, $QueryJson, [System.Text.UTF8Encoding]::new())
    
    try {
        $auth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$username`:$password"))
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
Write-Host "Sapphire Ticket Analysis - Log Export" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Elasticsearch: $esHost"
Write-Host "Period: $startTime to $endTime (UTC)"
Write-Host "Output Directory: $outputDir"
Write-Host ""

# ============================================================
# Query 1: Event ID 4768 - TGT Request (Kerberos AS-REQ)
# ============================================================

Write-Host "[Query 1] Event ID 4768 - Kerberos TGT Request" -ForegroundColor Yellow

$query4768 = @'
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
  "size": 1000,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@

$query4768 = $query4768 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response4768 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query4768
if ($null -eq $response4768) {
    Write-Host "  [ERROR] Failed to query Event ID 4768" -ForegroundColor Red
    exit 1
}

Write-Host "  Found: $($response4768.hits.total.value) records" -ForegroundColor Green

# Export 4768 to JSON
$jsonFile4768 = "$outputDir\01_Event4768_TGT_Request_$outputTimestamp.json"
$response4768 | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile4768 -Encoding UTF8
Write-Host "  JSON: $jsonFile4768" -ForegroundColor Cyan

# Export 4768 to CSV
$csvFile4768 = "$outputDir\01_Event4768_TGT_Request_$outputTimestamp.csv"
$response4768.hits.hits | ForEach-Object {
    $hit = $_._source
    [PSCustomObject]@{
        'Timestamp' = $hit.'@timestamp'
        'EventID' = $hit.event.code
        'Computer' = $hit.host.name
        'TargetUser' = $hit.winlog.event_data.TargetUserName
        'TargetDomain' = $hit.winlog.event_data.TargetDomainName
        'UserID' = $hit.winlog.event_data.TargetSid
        'SourceIP' = $hit.source.ip
        'SourcePort' = $hit.source.port
        'ServiceName' = $hit.winlog.event_data.ServiceName
        'TicketOptions' = $hit.winlog.event_data.TicketOptions
        'TicketEncryptionType' = $hit.winlog.event_data.TicketEncryptionType
        'PreAuthType' = $hit.winlog.event_data.PreAuthType
        'Status' = $hit.winlog.event_data.Status
        'RecordID' = $hit.winlog.record_id
    }
} | Export-Csv -Path $csvFile4768 -Encoding UTF8 -NoTypeInformation
Write-Host "  CSV: $csvFile4768" -ForegroundColor Cyan

Write-Host ""

# ============================================================
# Query 2: Event ID 4769 - Service Ticket Request (Kerberos TGS-REQ)
# ============================================================

Write-Host "[Query 2] Event ID 4769 - Kerberos Service Ticket Request" -ForegroundColor Yellow

$query4769 = @'
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
  "size": 1000,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@

$query4769 = $query4769 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response4769 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query4769
if ($null -eq $response4769) {
    Write-Host "  [ERROR] Failed to query Event ID 4769" -ForegroundColor Red
    exit 1
}

Write-Host "  Found: $($response4769.hits.total.value) records" -ForegroundColor Green

# Export 4769 to JSON
$jsonFile4769 = "$outputDir\02_Event4769_Service_Ticket_$outputTimestamp.json"
$response4769 | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile4769 -Encoding UTF8
Write-Host "  JSON: $jsonFile4769" -ForegroundColor Cyan

# Export 4769 to CSV
$csvFile4769 = "$outputDir\02_Event4769_Service_Ticket_$outputTimestamp.csv"
$response4769.hits.hits | ForEach-Object {
    $hit = $_._source
    [PSCustomObject]@{
        'Timestamp' = $hit.'@timestamp'
        'EventID' = $hit.event.code
        'Computer' = $hit.host.name
        'ClientUser' = $hit.winlog.event_data.ClientName
        'ClientDomain' = $hit.winlog.event_data.ClientDomainName
        'ServiceName' = $hit.winlog.event_data.ServiceName
        'ServiceID' = $hit.winlog.event_data.ServiceSid
        'SourceIP' = $hit.source.ip
        'SourcePort' = $hit.source.port
        'LogonGuid' = if ($hit.message -match 'ログオン GUID.*\{([^}]+)\}') { $matches[1] } else { 'N/A' }
        'TicketOptions' = $hit.winlog.event_data.TicketOptions
        'TicketEncryptionType' = $hit.winlog.event_data.TicketEncryptionType
        'Status' = $hit.winlog.event_data.Status
        'RecordID' = $hit.winlog.record_id
    }
} | Export-Csv -Path $csvFile4769 -Encoding UTF8 -NoTypeInformation
Write-Host "  CSV: $csvFile4769" -ForegroundColor Cyan

Write-Host ""

# ============================================================
# Query 3: Event ID 4672 - Special Logon (Privilege Assignment)
# ============================================================

Write-Host "[Query 3] Event ID 4672 - Special Logon (Privilege Assignment)" -ForegroundColor Yellow

$query4672 = @'
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
      ]
    }
  },
  "size": 1000,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@

$query4672 = $query4672 -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$response4672 = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $query4672
if ($null -eq $response4672) {
    Write-Host "  [ERROR] Failed to query Event ID 4672" -ForegroundColor Red
    exit 1
}

Write-Host "  Found: $($response4672.hits.total.value) records" -ForegroundColor Green

# Export 4672 to JSON
$jsonFile4672 = "$outputDir\03_Event4672_Special_Logon_$outputTimestamp.json"
$response4672 | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile4672 -Encoding UTF8
Write-Host "  JSON: $jsonFile4672" -ForegroundColor Cyan

# Export 4672 to CSV
$csvFile4672 = "$outputDir\03_Event4672_Special_Logon_$outputTimestamp.csv"
$response4672.hits.hits | ForEach-Object {
    $hit = $_._source
    $privileges = if ($hit.winlog.event_data.PrivilegeList -is [array]) {
        $hit.winlog.event_data.PrivilegeList -join '; '
    } elseif ($hit.winlog.event_data.PrivilegeList) {
        $hit.winlog.event_data.PrivilegeList
    } else {
        'N/A'
    }
    
    [PSCustomObject]@{
        'Timestamp' = $hit.'@timestamp'
        'EventID' = $hit.event.code
        'Computer' = $hit.host.name
        'User' = $hit.user.name
        'Domain' = $hit.user.domain
        'UserID' = if ($hit.winlog.event_data.SubjectUserSid) { $hit.winlog.event_data.SubjectUserSid } else { 'N/A' }
        'LogonID' = $hit.winlog.logon.id
        'PrivilegeCount' = if ($hit.winlog.event_data.PrivilegeList -is [array]) { $hit.winlog.event_data.PrivilegeList.Count } else { 1 }
        'Privileges' = $privileges
        'RecordID' = $hit.winlog.record_id
    }
} | Export-Csv -Path $csvFile4672 -Encoding UTF8 -NoTypeInformation
Write-Host "  CSV: $csvFile4672" -ForegroundColor Cyan

Write-Host ""

# ============================================================
# Query 4: Sysmon Event ID 1 - Process Creation
# ============================================================

Write-Host "[Query 4] Sysmon Event ID 1 - Process Creation" -ForegroundColor Yellow

$querySysmon = @'
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "1" } },
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
  "size": 1000,
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
'@

$querySysmon = $querySysmon -replace 'START_TIME', $startTime -replace 'END_TIME', $endTime

$responseSysmon = Invoke-ElasticsearchQuery -IndexPattern ".ds-winlogbeat-*" -QueryJson $querySysmon
if ($null -eq $responseSysmon) {
    Write-Host "  [ERROR] Failed to query Sysmon Event ID 1" -ForegroundColor Red
    exit 1
}

Write-Host "  Found: $($responseSysmon.hits.total.value) records" -ForegroundColor Green

# Export Sysmon to JSON
$jsonFileSysmon = "$outputDir\04_Event1_Sysmon_Process_$outputTimestamp.json"
$responseSysmon | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFileSysmon -Encoding UTF8
Write-Host "  JSON: $jsonFileSysmon" -ForegroundColor Cyan

# Export Sysmon to CSV
$csvFileSysmon = "$outputDir\04_Event1_Sysmon_Process_$outputTimestamp.csv"
$responseSysmon.hits.hits | ForEach-Object {
    $hit = $_._source
    [PSCustomObject]@{
        'Timestamp' = $hit.'@timestamp'
        'EventID' = $hit.event.code
        'Computer' = $hit.host.name
        'ProcessName' = $hit.process.name
        'ProcessID' = $hit.process.pid
        'ProcessGuid' = $hit.process.guid
        'CommandLine' = $hit.process.command_line
        'WorkingDirectory' = $hit.process.working_directory
        'ParentProcessName' = $hit.process.parent.name
        'ParentProcessID' = $hit.process.parent.pid
        'User' = $hit.user.name
        'Domain' = $hit.user.domain
        'IntegrityLevel' = if ($hit.message -match 'IntegrityLevel:\s+(\S+)') { $matches[1] } else { 'N/A' }
        'RecordID' = $hit.winlog.record_id
    }
} | Export-Csv -Path $csvFileSysmon -Encoding UTF8 -NoTypeInformation
Write-Host "  CSV: $csvFileSysmon" -ForegroundColor Cyan

Write-Host ""

# ============================================================
# Summary Report
# ============================================================

Write-Host "============================================================" -ForegroundColor Green
Write-Host "Export Summary" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

$totalRecords = $response4768.hits.total.value + $response4769.hits.total.value + $response4672.hits.total.value + $responseSysmon.hits.total.value

Write-Host "Event ID 4768 (TGT Request):"
Write-Host "  Records: $($response4768.hits.total.value)" -ForegroundColor Green
Write-Host "  JSON: $(Split-Path -Leaf $jsonFile4768)"
Write-Host "  CSV: $(Split-Path -Leaf $csvFile4768)"
Write-Host ""

Write-Host "Event ID 4769 (Service Ticket Request):"
Write-Host "  Records: $($response4769.hits.total.value)" -ForegroundColor Green
Write-Host "  JSON: $(Split-Path -Leaf $jsonFile4769)"
Write-Host "  CSV: $(Split-Path -Leaf $csvFile4769)"
Write-Host ""

Write-Host "Event ID 4672 (Special Logon):"
Write-Host "  Records: $($response4672.hits.total.value)" -ForegroundColor Green
Write-Host "  JSON: $(Split-Path -Leaf $jsonFile4672)"
Write-Host "  CSV: $(Split-Path -Leaf $csvFile4672)"
Write-Host ""

Write-Host "Sysmon Event ID 1 (Process Creation):"
Write-Host "  Records: $($responseSysmon.hits.total.value)" -ForegroundColor Green
Write-Host "  JSON: $(Split-Path -Leaf $jsonFileSysmon)"
Write-Host "  CSV: $(Split-Path -Leaf $csvFileSysmon)"
Write-Host ""

Write-Host "Total Records Exported: $totalRecords" -ForegroundColor Cyan
Write-Host "Output Directory: $outputDir" -ForegroundColor Cyan
Write-Host ""

Write-Host "============================================================" -ForegroundColor Green
Write-Host "Export Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
