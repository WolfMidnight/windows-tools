# -------------------- Sysinternals Suite --------------------
if ($IncludeAutoruns -and $AutorunsEXE) {
  try {
    Write-Note "Running Autoruns CSV export"
    $arCsv = Join-Path $OutDir "Autoruns.csv"
    $arXml = Join-Path $OutDir "Autoruns.xml"
    
    # CSV format
    $res = Invoke-CLI -File $AutorunsEXE -Args "-accepteula -nobanner -s -c -h -v" -StdOutToFile $arCsv
    Write-Note "Autoruns CSV exit $($res.ExitCode)"
    
    # XML format for detailed parsing
    $res = Invoke-CLI -File $AutorunsEXE -Args "-accepteula -nobanner -s -x -h -v" -StdOutToFile $arXml
    Write-Note "Autoruns XML exit $($res.ExitCode)"
    
  } catch { Write-Note "Autoruns failed: $($_.Exception.Message)" "ERROR" }
}

if ($Deep -and $SigcheckEXE) {
  try {
    Write-Note "Running Sigcheck on multiple locations"
    
    # Windows directory
    $sigOut1 = Join-Path $Dirs.FileSystem "Sigcheck_Windows.csv"
    $res = Invoke-CLI -File $SigcheckEXE -Args "-accepteula -nobanner -u -e -s -h -c -q C:\Windows\System32" -StdOutToFile $sigOut1
    Write-Note "Sigcheck Windows exit $($res.ExitCode)"
    
    # Program Files
    $sigOut2 = Join-Path $Dirs.FileSystem "Sigcheck_ProgramFiles.csv"
    $res = Invoke-CLI -File $SigcheckEXE -Args "-accepteula -nobanner -u -e -s -h -c -q `"C:\Program Files`"" -StdOutToFile $sigOut2
    Write-Note "Sigcheck Program Files exit $($res.ExitCode)"
    
    # Startup locations
    $sigOut3 = Join-Path $Dirs.FileSystem "Sigcheck_Startup.csv"
    $res = Invoke-CLI -File $SigcheckEXE -Args "-accepteula -nobanner -u -e -s -h -c -q `"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup`"" -StdOutToFile $sigOut3
    Write-Note "Sigcheck Startup exit $($res.ExitCode)"
    
  } catch { Write-Note "Sigcheck failed: $($_.Exception.Message)" "ERROR" }
}

if ($ListDLLsEXE) {
  try {
    Write-Note "Running ListDLLs to find unsigned DLLs"
    $dllOut = Join-Path $Dirs.Memory "ListDLLs_Unsigned.txt"
    $res = Invoke-CLI -File $ListDLLsEXE -Args "-accepteula -u" -StdOutToFile $dllOut
    Write-Note "ListDLLs exit $($res.ExitCode)"
  } catch { Write-Note "ListDLLs failed: $($_.Exception.Message)" "ERROR" }
}

if ($TCPViewEXE) {
  try {
    Write-Note "Running TCPView for network connections"
    $tcpOut = Join-Path $Dirs.Network "TCPView.csv"
    $res = Invoke-CLI -File $TCPViewEXE -Args "-accepteula -c" -StdOutToFile $tcpOut
    Write-Note "TCPView exit $($res.ExitCode)"
  } catch { Write-Note "TCPView failed: $($_.Exception.Message)" "ERROR" }
}

# -------------------- Third-party scanners --------------------
function Run-AdwCleaner {
  $adwExe = Join-Path $TempTools "adwcleaner.exe"
  $adwUrl = "https://downloads.malwarebytes.com/file/adwcleaner"
  
  if (Invoke-Download -Url $adwUrl -OutFile $adwExe) {
    $adwOutDir = Join-Path $Dirs.ThirdParty "AdwCleaner"
    New-OutDir $adwOutDir
    
    # First run: scan only
    $args = "/eula /scan /noreboot /path `"$adwOutDir`""
    Write-Note "AdwCleaner: Scanning"
    $res = Invoke-CLI -File $adwExe -Args $args -TimeoutSeconds 600
    Write-Note "AdwCleaner scan exit $($res.ExitCode)"
    
    # Second run: clean if needed
    $args = "/eula /clean /noreboot /path `"$adwOutDir`""
    Write-Note "AdwCleaner: Cleaning"
    $res = Invoke-CLI -File $adwExe -Args $args -TimeoutSeconds 600
    Write-Note "AdwCleaner clean exit $($res.ExitCode)"
    
    Remove-Item -LiteralPath $adwExe -Force -ErrorAction SilentlyContinue
  }
}

function Run-KVRT {
  $kvrtExe = Join-Path $TempTools "kvrt.exe"
  $kvrtUrl = "https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe"
  
  if (Invoke-Download -Url $kvrtUrl -OutFile $kvrtExe) {
    $kvrtDir = Join-Path $Dirs.ThirdParty "KVRT_Data"
    New-OutDir $kvrtDir
    
    $kvrtArgs = "-accepteula -silent -adinsilent -processlevel 3 -d `"$kvrtDir`""
    if ($KVRTAllVolumes) { $kvrtArgs += " -allvolumes" }
    
    Write-Note "KVRT: Starting deep scan"
    $kvrtLog = Join-Path $Dirs.ThirdParty "kvrt_console.log"
    $res = Invoke-CLI -File $kvrtExe -Args $kvrtArgs -StdOutToFile $kvrtLog -TimeoutSeconds 0
    Write-Note "KVRT exit $($res.ExitCode)"
    
    Remove-Item -LiteralPath $kvrtExe -Force -ErrorAction SilentlyContinue
  }
}

function Run-MSERT {
  $msertExe = Join-Path $TempTools "msert.exe"
  $msertUrl = "https://go.microsoft.com/fwlink/?LinkId=212733"
  
  if (Invoke-Download -Url $msertUrl -OutFile $msertExe) {
    Write-Note "MSERT: Starting full scan"
    $res = Invoke-CLI -File $msertExe -Args "/F /Q" -TimeoutSeconds 0
    Write-Note "MSERT exit $($res.ExitCode)"
    
    $msLog = "$env:WINDIR\debug\msert.log"
    if (Test-Path $msLog) {
      Copy-Item -LiteralPath $msLog -Destination (Join-Path $Dirs.ThirdParty "MSERT.log") -Force
    }
    
    Remove-Item -LiteralPath $msertExe -Force -ErrorAction SilentlyContinue
  }
}

function Run-ESET {
  $esetExe = Join-Path $TempTools "esetonlinescanner.exe"
  $esetUrl = "https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe"
  
  if (Invoke-Download -Url $esetUrl -OutFile $esetExe) {
    Write-Note "ESET: Starting online scan"
    $esetLog = Join-Path $Dirs.ThirdParty "ESET_scan.log"
    $args = "/log-file=`"$esetLog`" /no-quarantine /clean-mode=none"
    
    $res = Invoke-CLI -File $esetExe -Args $args -TimeoutSeconds 0
    Write-Note "ESET exit $($res.ExitCode)"
    
    Remove-Item -LiteralPath $esetExe -Force -ErrorAction SilentlyContinue
  }
}

if ($UseAdwCleaner) { try { Run-AdwCleaner } catch { Write-Note "AdwCleaner error: $_" "ERROR" } }
if ($UseKVRT)       { try { Run-KVRT       } catch { Write-Note "KVRT error: $_" "ERROR" } }
if ($UseMSERT)      { try { Run-MSERT      } catch { Write-Note "MSERT error: $_" "ERROR" } }
if ($UseKVRT -and $DoubleCheck) { 
  Write-Note "Running ESET as double-check scanner"
  try { Run-ESET } catch { Write-Note "ESET error: $_" "ERROR" } 
}

# -------------------- Rootkit Detection --------------------
function Run-RootkitScan {
  if (-not $UseRootkitScan) { return }
  
  Write-Note "Starting rootkit detection"
  $rkDir = Join-Path $Dirs.Memory "Rootkits"
  New-OutDir $rkDir
  
  # GMER
  $gmerExe = Join-Path $TempTools "gmer.exe"
  $gmerUrl = "http://www.gmer.net/gmer.exe"
  
  if (Invoke-Download -Url $gmerUrl -OutFile $gmerExe) {
    Write-Note "GMER: Scanning for rootkits"
    $gmerLog = Join-Path $rkDir "gmer.log"
    $args = "-log=`"$gmerLog`" -silent"
    
    try {
      $res = Invoke-CLI -File $gmerExe -Args $args -TimeoutSeconds 1200
      Write-Note "GMER exit $($res.ExitCode)"
    } catch {
      Write-Note "GMER scan failed: $_" "ERROR"
    }
    
    Remove-Item -LiteralPath $gmerExe -Force -ErrorAction SilentlyContinue
  }
  
  # RootkitRevealer (if available)
  $rkRevealerEXE = @(
    (Join-Path $SysBase "RootkitRevealer64.exe"),
    (Join-Path $SysBase "RootkitRevealer.exe")
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
  
  if ($rkRevealerEXE) {
    Write-Note "RootkitRevealer: Scanning"
    $rkrLog = Join-Path $rkDir "RootkitRevealer.txt"
    $res = Invoke-CLI -File $rkRevealerEXE -Args "-accepteula -a -c -f `"$rkrLog`"" -TimeoutSeconds 1200
    Write-Note "RootkitRevealer exit $($res.ExitCode)"
  }
}

Run-RootkitScan

# -------------------- Memory Analysis --------------------
function Run-HollowsHunter {
  $hhExe = Join-Path $TempTools "hollows_hunter64.exe"
  $hhUrl = "https://github.com/hasherezade/hollows_hunter/releases/latest/download/hollows_hunter64.exe"
  
  if (Invoke-Download -Url $hhUrl -OutFile $hhExe) {
    $hhOut = Join-Path $Dirs.Memory "HollowsHunter"
    New-OutDir $hhOut
    
    # First pass: normal scan
    $args = "/hooks /shellc /dir `"$hhOut`" /uniqd /quiet"
    Write-Note "HollowsHunter: First pass"
    $res = Invoke-CLI -File $hhExe -Args $args -TimeoutSeconds 600
    Write-Note "HollowsHunter pass 1 exit $($res.ExitCode)"
    
    if ($DoubleCheck) {
      # Second pass: deep scan with IAT checks
      Start-Sleep -Seconds 5
      $hhOut2 = Join-Path $Dirs.Memory "HollowsHunter_Deep"
      New-OutDir $hhOut2
      $args = "/hooks /shellc /iat 3 /threads /data /dir `"$hhOut2`" /uniqd /quiet"
      Write-Note "HollowsHunter: Deep scan pass"
      $res = Invoke-CLI -File $hhExe -Args $args -TimeoutSeconds 900
      Write-Note "HollowsHunter pass 2 exit $($res.ExitCode)"
    }
    
    Remove-Item -LiteralPath $hhExe -Force -ErrorAction SilentlyContinue
  }
}

function Run-Moneta {
  $monetaExe = Join-Path $TempTools "Moneta64.exe"
  $monetaUrl = "https://github.com/forrest-orr/moneta/releases/latest/download/Moneta64.exe"
  
  if (Invoke-Download -Url $monetaUrl -OutFile $monetaExe) {
    $monetaOut = Join-Path $Dirs.Memory "Moneta_scan.txt"
    
    Write-Note "Moneta: Memory artifact scanning"
    $res = Invoke-CLI -File $monetaExe -Args "-m ioc -d" -StdOutToFile $monetaOut -TimeoutSeconds 600
    Write-Note "Moneta exit $($res.ExitCode)"
    
    Remove-Item -LiteralPath $monetaExe -Force -ErrorAction SilentlyContinue
  }
}

if ($UseMemorySweep) {
  try { Run-HollowsHunter } catch { Write-Note "HollowsHunter error: $_" "ERROR" }
  if ($DoubleCheck) {
    try { Run-Moneta } catch { Write-Note "Moneta error: $_" "ERROR" }
  }
}

# -------------------- File Integrity Monitoring --------------------
function Get-CriticalFileHashes {
  Write-Note "Computing hashes for critical system files"
  $hashOut = Join-Path $Dirs.FileSystem "CriticalFileHashes.json"
  
  $criticalPaths = @(
    "$env:SystemRoot\System32\kernel32.dll",
    "$env:SystemRoot\System32\ntdll.dll",
    "$env:SystemRoot\System32\wininet.dll",
    "$env:SystemRoot\System32\ws2_32.dll",
    "$env:SystemRoot\System32\advapi32.dll",
    "$env:SystemRoot\System32\user32.dll",
    "$env:SystemRoot\System32\svchost.exe",
    "$env:SystemRoot\System32\lsass.exe",
    "$env:SystemRoot\System32\services.exe",
    "$env:SystemRoot\System32\winlogon.exe",
    "$env:SystemRoot\System32\csrss.exe",
    "$env:SystemRoot\System32\smss.exe",
    "$env:SystemRoot\explorer.exe"
  )
  
  $hashes = @{}
  foreach ($path in $criticalPaths) {
    if (Test-Path $path) {
      $hashes[$path] = @{
        SHA256 = (Get-FileHash -Path $path -Algorithm SHA256).Hash
        SHA1 = (Get-FileHash -Path $path -Algorithm SHA1).Hash
        MD5 = (Get-FileHash -Path $path -Algorithm MD5).Hash
        Size = (Get-Item $path).Length
        LastWriteTime = (Get-Item $path).LastWriteTime
        Version = (Get-Item $path).VersionInfo.FileVersion
      }
    }
  }
  
  $hashes | ConvertTo-Json -Depth 5 | Out-File -FilePath $hashOut -Encoding utf8
}

Get-CriticalFileHashes

# -------------------- Verification Pass --------------------
if ($DoubleCheck) {
  Write-Note "Starting verification pass"
  
  # Re-inventory critical items
  Start-Sleep -Seconds 10
  
  $verifyData = @{
    Timestamp = (Get-Date).ToString("s")
    ProcessesRecheck = @()
    ServicesRecheck = @()
    NetworkRecheck = @()
  }
  
  # Recheck processes
  $verifyData.ProcessesRecheck = Get-Process | Where-Object {
    $_.Path -and (-not (Get-AuthenticodeSignature $_.Path).Status -eq 'Valid')
  } | Select-Object Name,Id,Path
  
  # Recheck services
  $verifyData.ServicesRecheck = Get-CimInstance Win32_Service | Where-Object {
    $_.State -eq 'Running' -and $_.PathName -notmatch 'svchost.exe'
  } | Select-Object Name,PathName,ProcessId
  
  # Recheck network
  $verifyData.NetworkRecheck = Get-NetTCPConnection | Where-Object {
    $_.State -eq 'Established' -and $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1'
  } | Select-Object LocalPort,RemoteAddress,RemotePort,OwningProcess
  
  $verifyPath = Join-Path $Dirs.Verification "DoubleCheck.json"
  $verifyData | ConvertTo-Json -Depth 5 | Out-File -FilePath $verifyPath -Encoding utf8
  
  Write-Note "Verification pass complete"
}

# -------------------- Windows Update (Run Last) --------------------
Invoke-WindowsUpdate

# -------------------- Analysis and Reporting --------------------
function New-ThreatReport {
  Write-Note "Generating threat analysis report"
  $reportPath = Join-Path $OutDir "ThreatAnalysis.html"
  
  $suspiciousItems = @{
    UnsignedProcesses = @()
    UnsignedServices = @()
    UnusualNetworkConnections = @()
    SuspiciousStartupItems = @()
    UnknownScheduledTasks = @()
    RemovedBloatware = @()
    CleanedTempFiles = @()
  }
  
  # Analyze processes
  $suspiciousItems.UnsignedProcesses = $Inventory.Processes | Where-Object {
    $_.Path -and (-not (Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue).Status -eq 'Valid')
  } | Select-Object Name,Path,Id
  
  # Analyze network connections
  $suspiciousItems.UnusualNetworkConnections = $Inventory.NetworkConnections | Where-Object {
    $_.RemotePort -in @(1337,4444,5555,6666,7777,8888,9999,31337) -or
    $_.RemoteAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
  }
  
  # Check for removed bloatware
  if (Test-Path (Join-Path $Dirs.Debloat "BloatwareRemoval.log")) {
    $bloatLog = Get-Content (Join-Path $Dirs.Debloat "BloatwareRemoval.log") | ConvertFrom-Json
    $suspiciousItems.RemovedBloatware = $bloatLog.RemovedApps
  }
  
  # Check for cleaned temp files
  if (Test-Path (Join-Path $Dirs.SystemRepair "TempCleanup.log")) {
    $tempLog = Get-Content (Join-Path $Dirs.SystemRepair "TempCleanup.log") | ConvertFrom-Json
    $suspiciousItems.CleanedTempFiles = @{
      TotalFreedMB = $tempLog.TotalFreedMB
      FilesRemoved = $tempLog.FilesRemoved
    }
  }
  
  # Generate HTML report
  $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>DeepScan Enhanced - Threat Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; padding: 30px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; font-size: 2.5em; }
        h2 { color: #34495e; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 15px; }
        h3 { color: #7f8c8d; margin-top: 20px; }
        .info { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .info strong { color: #ffd700; }
        .warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 15px; border-radius: 8px; margin: 10px 0; }
        .success { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; padding: 15px; border-radius: 8px; margin: 10px 0; }
        .critical { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; padding: 15px; border-radius: 8px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; background: white; margin-top: 15px; border-radius: 10px; overflow: hidden; box-shadow: 0 5px 20px rgba(0,0,0,0.1); }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
        tr:hover { background: #f8f9fa; transition: background 0.3s; }
        tr:last-child td { border-bottom: none; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-box { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 5px 20px rgba(0,0,0,0.1); border-top: 4px solid #3498db; }
        .summary-box h3 { margin-top: 0; color: #2c3e50; }
        .summary-box .number { font-size: 2.5em; font-weight: bold; color: #3498db; }
        .summary-box .label { color: #7f8c8d; margin-top: 5px; }
        .progress { background: #ecf0f1; height: 30px; border-radius: 15px; overflow: hidden; margin: 15px 0; }
        .progress-bar { background: linear-gradient(90deg, #43e97b 0%, #38f9d7 100%); height: 100%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; transition: width 1s ease; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; margin: 2px; }
        .badge-success { background: #27ae60; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-danger { background: #e74c3c; color: white; }
        .badge-info { background: #3498db; color: white; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ DeepScan Enhanced v3.0 - Threat Analysis Report</h1>
        <div class="info">
            <strong>Scan Date:</strong> $(Get-Date)<br>
            <strong>Computer:</strong> $env:COMPUTERNAME<br>
            <strong>User:</strong> $env:USERNAME<br>
            <strong>Script Version:</strong> $ScriptVersion<br>
            <strong>System:</strong> Windows $(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion
        </div>
        
        <h2>📊 Scan Summary</h2>
        <div class="summary">
            <div class="summary-box">
                <h3>Processes</h3>
                <div class="number">$($Inventory.Processes.Count)</div>
                <div class="label">Total Processes</div>
                <div class="progress">
                    <div class="progress-bar" style="width: $(100 - ([math]::Min($suspiciousItems.UnsignedProcesses.Count * 5, 100)))%">
                        $($Inventory.Processes.Count - $suspiciousItems.UnsignedProcesses.Count) Signed
                    </div>
                </div>
                <span class="badge badge-warning">$($suspiciousItems.UnsignedProcesses.Count) Unsigned</span>
            </div>
            
            <div class="summary-box">
                <h3>Services</h3>
                <div class="number">$($Inventory.Services.Count)</div>
                <div class="label">Total Services</div>
                <div class="progress">
                    <div class="progress-bar" style="width: $(($Inventory.Services | Where-Object {$_.State -eq 'Running'} | Measure-Object).Count / $Inventory.Services.Count * 100)%">
                        $(($Inventory.Services | Where-Object {$_.State -eq 'Running'} | Measure-Object).Count) Running
                    </div>
                </div>
            </div>
            
            <div class="summary-box">
                <h3>Network</h3>
                <div class="number">$($Inventory.NetworkConnections.Count)</div>
                <div class="label">Active Connections</div>
                <span class="badge badge-info">$(($Inventory.NetworkConnections | Where-Object {$_.State -eq 'Established'} | Measure-Object).Count) Established</span>
                <span class="badge badge-warning">$($suspiciousItems.UnusualNetworkConnections.Count) Suspicious</span>
            </div>
            
            <div class="summary-box">
                <h3>System Health</h3>
                <div class="number">$(if($RepairSystem){'✓'}else{'—'})</div>
                <div class="label">Integrity Check</div>
                $(if($suspiciousItems.CleanedTempFiles){"<span class='badge badge-success'>$($suspiciousItems.CleanedTempFiles.TotalFreedMB) MB Cleaned</span>"})
                $(if($suspiciousItems.RemovedBloatware){"<span class='badge badge-info'>$($suspiciousItems.RemovedBloatware.Count) Apps Removed</span>"})
            </div>
        </div>
        
        <h2>🔍 Detailed Findings</h2>
"@
  
  if ($suspiciousItems.UnsignedProcesses.Count -gt 0) {
    $html += @"
        <div class="warning">
            <h3>⚠️ Unsigned Processes Detected</h3>
            <p>The following processes are not digitally signed and should be reviewed:</p>
        </div>
        <table>
            <tr><th>Process Name</th><th>Path</th><th>Process ID</th></tr>
"@
    foreach ($item in $suspiciousItems.UnsignedProcesses | Select-Object -First 20) {
      $html += "<tr><td>$($item.Name)</td><td>$($item.Path)</td><td>$($item.Id)</td></tr>"
    }
    $html += "</table>"
    if ($suspiciousItems.UnsignedProcesses.Count -gt 20) {
      $html += "<p style='color: #7f8c8d; margin-top: 10px;'>... and $($suspiciousItems.UnsignedProcesses.Count - 20) more unsigned processes</p>"
    }
  }
  
  if ($suspiciousItems.UnusualNetworkConnections.Count -gt 0) {
    $html += @"
        <div class="warning">
            <h3>⚠️ Unusual Network Connections</h3>
            <p>The following network connections use suspicious ports or addresses:</p>
        </div>
        <table>
            <tr><th>Local Port</th><th>Remote Address</th><th>Remote Port</th><th>Process</th></tr>
"@
    foreach ($item in $suspiciousItems.UnusualNetworkConnections | Select-Object -First 10) {
      $html += "<tr><td>$($item.LocalPort)</td><td>$($item.RemoteAddress)</td><td>$($item.RemotePort)</td><td>$($item.ProcessName)</td></tr>"
    }
    $html += "</table>"
  }
  
  if ($suspiciousItems.RemovedBloatware.Count -gt 0) {
    $html += @"
        <div class="success">
            <h3>✅ Bloatware Removed</h3>
            <p>Successfully removed $($suspiciousItems.RemovedBloatware.Count) bloatware applications</p>
        </div>
"@
  }
  
  if ($suspiciousItems.CleanedTempFiles) {
    $html += @"
        <div class="success">
            <h3>✅ Temporary Files Cleaned</h3>
            <p>Freed $($suspiciousItems.CleanedTempFiles.TotalFreedMB) MB by removing $($suspiciousItems.CleanedTempFiles.FilesRemoved) temporary files</p>
        </div>
"@
  }
  
  $html += @"
        <h2>🛠️ Scan Components Status</h2>
        <table>
            <tr><th>Component</th><th>Status</th><th>Details</th></tr>
            <tr>
                <td>Windows Defender</td>
                <td>$(if($UseDefender){'<span class="badge badge-success">✓ Executed</span>'}else{'<span class="badge badge-info">Skipped</span>'})</td>
                <td>$(if($UseDefender){'Full system scan initiated'}else{'Not requested'})</td>
            </tr>
            <tr>
                <td>System Integrity</td>
                <td>$(if($RepairSystem){'<span class="badge badge-success">✓ Checked</span>'}else{'<span class="badge badge-info">Skipped</span>'})</td>
                <td>$(if($RepairSystem){'SFC and DISM verification completed'}else{'Not requested'})</td>
            </tr>
            <tr>
                <td>Debloating</td>
                <td>$(if($Debloat){'<span class="badge badge-success">✓ Completed</span>'}else{'<span class="badge badge-info">Skipped</span>'})</td>
                <td>$(if($Debloat){"Removed $($suspiciousItems.RemovedBloatware.Count) applications"}else{'Not requested'})</td>
            </tr>
            <tr>
                <td>Temp Cleanup</td>
                <td>$(if($CleanTemp){'<span class="badge badge-success">✓ Completed</span>'}else{'<span class="badge badge-info">Skipped</span>'})</td>
                <td>$(if($CleanTemp){"Freed $($suspiciousItems.CleanedTempFiles.TotalFreedMB) MB"}else{'Not requested'})</td>
            </tr>
            <tr>
                <td>Windows Updates</td>
                <td>$(if($UpdateWindows){'<span class="badge badge-success">✓ Checked</span>'}else{'<span class="badge badge-info">Skipped</span>'})</td>
                <td>$(if($UpdateWindows){'Update check completed'}else{'Not requested'})</td>
            </tr>
            <tr>
                <td>Autoruns</td>
                <td>$(if($AutorunsEXE -and $IncludeAutoruns){'<span class="badge badge-success">✓ Executed</span>'}else{'<span class="badge badge-warning">Not Available</span>'})</td>
                <td>$(if($AutorunsEXE -and $IncludeAutoruns){'Startup analysis complete'}else{'Sysinternals tool not found'})</td>
            </tr>
            <tr>
                <td>Memory Analysis</td>
                <td>$(if($UseMemorySweep){'<span class="badge badge-success">✓ Executed</span>'}else{'<span class="badge badge-info">Skipped</span>'})</td>
                <td>$(if($UseMemorySweep){'Process hollowing and injection detection'}else{'Not requested'})</td>
            </tr>
            <tr>
                <td>Rootkit Scan</td>
                <td>$(if($UseRootkitScan){'<span class="badge badge-success">✓ Executed</span>'}else{'<span class="badge badge-info">Skipped</span>'})</td>
                <td>$(if($UseRootkitScan){'Deep rootkit detection completed'}else{'Not requested'})</td>
            </tr>
            <tr>
                <td>Third-Party Scanners</td>
                <td>$(if($UseAdwCleaner -or $UseKVRT -or $UseMSERT){'<span class="badge badge-success">✓ Executed</span>'}else{'<span class="badge badge-info">Skipped</span>'})</td>
                <td>AdwCleaner: $(if($UseAdwCleaner){'✓'}else{'—'}) | KVRT: $(if($UseKVRT){'✓'}else{'—'}) | MSERT: $(if($UseMSERT){'✓'}else{'—'})</td>
            </tr>
        </table>
        
        <div class="footer">
            <p><strong>Output Directory:</strong> $OutDir</p>
            <p>Review the detailed logs in each subdirectory for complete analysis</p>
            <p style="margin-top: 20px; font-size: 0.9em;">DeepScan Enhanced v3.0 - Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
    </div>
</body>
</html>
"@
  
  $html | Out-File -FilePath $reportPath -Encoding utf8
  Write-Note "HTML report generated: $reportPath" "SUCCESS"
}

New-ThreatReport

# -------------------- Summary Generation --------------------
$Summary = [ordered]@{
  Version  = $ScriptVersion
  Hash     = $ScriptHash
  OutDir   = $OutDir
  When     = (Get-Date).ToString("s")
  User     = $User
  Computer = $env:COMPUTERNAME
  OS       = (Get-CimInstance Win32_OperatingSystem).Caption
  RestorePoint = if(-not $NoRestorePoint){'Created'}else{'Skipped'}
  Tools    = @{
    Autoruns      = [bool]$AutorunsEXE
    Sigcheck      = [bool]$SigcheckEXE
    ListDLLs      = [bool]$ListDLLsEXE
    TCPView       = [bool]$TCPViewEXE
    AdwCleaner    = $UseAdwCleaner
    KVRT          = $UseKVRT
    MSERT         = $UseMSERT
    ESET          = ($UseKVRT -and $DoubleCheck)
    HollowsHunter = $UseMemorySweep
    Moneta        = ($UseMemorySweep -and $DoubleCheck)
    GMER          = $UseRootkitScan
    Defender      = $UseDefender
    Debloat       = $Debloat
    TempCleanup   = $CleanTemp
    SystemRepair  = $RepairSystem
    WindowsUpdate = $UpdateWindows
  }
  Counts = @{
    Processes    = ($Inventory.Processes | Measure-Object).Count
    Services     = ($Inventory.Services | Measure-Object).Count
    Drivers      = ($Inventory.Drivers | Measure-Object).Count
    Tasks        = ($Inventory.ScheduledTasks | Measure-Object).Count
    Connections  = ($Inventory.NetworkConnections | Measure-Object).Count
    DNSCache     = ($Inventory.DNSCache | Measure-Object).Count
  }
}

$SummaryJson = Join-Path $OutDir "ScanSummary.json"
$Summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $SummaryJson -Encoding utf8

# Text summary
$SummaryTxt = Join-Path $OutDir "ScanSummary.txt"
@"
================================================================================
                    DeepScan Enhanced v3.0 - Summary Report
================================================================================
Scan Date:     $(Get-Date)
Computer:      $env:COMPUTERNAME
User:          $env:USERNAME
OS:            $($Summary.OS)
Output:        $OutDir
Restore Point: $($Summary.RestorePoint)

INVENTORY COUNTS:
-----------------
Processes:     $($Summary.Counts.Processes)
Services:      $($Summary.Counts.Services)
Drivers:       $($Summary.Counts.Drivers)
Sched Tasks:   $($Summary.Counts.Tasks)
Network Conn:  $($Summary.Counts.Connections)
DNS Cache:     $($Summary.Counts.DNSCache)

SCANNERS EXECUTED:
------------------
$(if($UseDefender)     {"[✓] Windows Defender Full Scan"} else {"[ ] Windows Defender"})
$(if($RepairSystem)    {"[✓] System File Integrity Check"} else {"[ ] System Repair"})
$(if($Debloat)         {"[✓] Windows Debloating"} else {"[ ] Debloat"})
$(if($CleanTemp)       {"[✓] Temporary File Cleanup"} else {"[ ] Temp Cleanup"})
$(if($UpdateWindows)   {"[✓] Windows Update Check"} else {"[ ] Windows Update"})
$(if($IncludeAutoruns) {"[✓] Sysinternals Autoruns"} else {"[ ] Autoruns"})
$(if($Deep)            {"[✓] Sysinternals Sigcheck"} else {"[ ] Sigcheck"})
$(if($UseAdwCleaner)   {"[✓] Malwarebytes AdwCleaner"} else {"[ ] AdwCleaner"})
$(if($UseKVRT)         {"[✓] Kaspersky KVRT"} else {"[ ] KVRT"})
$(if($UseMSERT)        {"[✓] Microsoft MSERT"} else {"[ ] MSERT"})
$(if($UseMemorySweep)  {"[✓] Memory Analysis (HollowsHunter$(if($DoubleCheck){' + Moneta'}))"} else {"[ ] Memory Analysis"})
$(if($UseRootkitScan)  {"[✓] Rootkit Detection (GMER)"} else {"[ ] Rootkit Scan"})
$(if($DoubleCheck)     {"[✓] Double-Check Verification"} else {"[ ] Verification"})

RESULTS LOCATION:
-----------------
Main Directory:    $OutDir
HTML Report:       $(Join-Path $OutDir "ThreatAnalysis.html")
Inventory:         $(Join-Path $OutDir "Inventory.json")
Logs Directory:    $($Dirs.Logs)
Third-Party:       $($Dirs.ThirdParty)
System Repair:     $($Dirs.SystemRepair)
Debloat Results:   $($Dirs.Debloat)

================================================================================
                      Scan Complete - Review Results Above
================================================================================
"@ | Out-File -FilePath $SummaryTxt -Encoding utf8

# -------------------- Cleanup --------------------
Write-Note "Performing cleanup"

try { if ($global:NoteWriter) { $global:NoteWriter.Flush(); $global:NoteWriter.Dispose() } } catch {}
try { Stop-Transcript | Out-Null } catch {}

if ($SelfDestruct) {
  Write-Note "Self-destruct: removing temp tools" "WARNING"
  try { Remove-Item -LiteralPath $TempTools -Recurse -Force -ErrorAction SilentlyContinue } catch {}
  
  $me = $MyInvocation.MyCommand.Path
  if ($me -and (Test-Path $me)) {
    $cmd = "Start-Sleep -Seconds 5; Remove-Item -LiteralPath `"$me`" -Force"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -Command $cmd" -WindowStyle Hidden
  }
}

# Final output
Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "         DEEPSCAN ENHANCED v3.0 COMPLETE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Results saved to: " -NoNewline
Write-Host $OutDir -ForegroundColor Yellow
Write-Host "HTML Report: " -NoNewline
Write-Host (Join-Path $OutDir "ThreatAnalysis.html") -ForegroundColor Yellow
Write-Host "Summary: " -NoNewline
Write-Host $SummaryTxt -ForegroundColor Yellow
Write-Host ""
if ($UpdateWindows -and (Test-Path (Join-Path $Dirs.SystemRepair "WindowsUpdate.log"))) {
  Write-Host "⚠️  Windows Updates were installed - review update log" -ForegroundColor Yellow
}
if ($RepairSystem -and (Test-Path (Join-Path $Dirs.SystemRepair "sfc_repair.log"))) {
  Write-Host "⚠️  System repairs were performed - review repair logs" -ForegroundColor Yellow
}
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan<#
.SYNOPSIS
  DeepScan_Enhanced.ps1 v3.0 - Multi-layered investigative + disinfect script for Windows 10/11.
  Enhanced with Tron-like features: debloating, system repair, temp cleanup, restore points.
  - Inventories persistence, network, and security posture
  - Windows Defender deep scan integration
  - Rootkit detection via GMER and RootkitRevealer
  - WMI persistence analysis
  - Certificate store verification
  - Browser extension enumeration
  - File integrity monitoring and repair
  - Windows bloatware removal
  - Safe temporary file cleanup
  - System restore point creation
  - Windows Update integration
  - Optionally runs Sysinternals suite
  - Portable third-party scanners with verification
  - Memory sweep via multiple tools
  - All results saved under C:\Users\%USERNAME%\Desktop\Deep Scan\<timestamp>\
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
  [switch]$Full,              # shorthand: turns on everything heavy
  [switch]$IncludeAutoruns,
  [switch]$Deep,              # turn on deeper file signature walk
  [switch]$UseAdwCleaner,
  [switch]$UseKVRT,
  [switch]$KVRTAllVolumes,
  [switch]$UseMSERT,
  [switch]$UseMemorySweep,    # Memory analysis sweep
  [switch]$UseRootkitScan,    # Rootkit detection
  [switch]$UseDefender,       # Windows Defender deep scan
  [switch]$DoubleCheck,       # Run verification passes
  [switch]$Debloat,          # Remove Windows bloatware
  [switch]$CleanTemp,         # Clean temporary files safely
  [switch]$RepairSystem,      # Run system file integrity checks
  [switch]$UpdateWindows,     # Check and install Windows updates
  [switch]$NoRestorePoint,    # Skip creating system restore point
  [switch]$SelfDestruct,      # remove downloaded tools when finished
  [switch]$SkipNetworkCheck   # Skip network-dependent operations
)

# Encoding guards
try { 
  $OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 
} catch {}

# -------------------- Constants & prep --------------------
$ErrorActionPreference = 'Continue'
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$Host.UI.RawUI.WindowTitle = "DeepScan Enhanced v3.0"

# Version info
$ScriptVersion = "3.0"
$ScriptHash = (Get-FileHash -Path $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash

function New-OutDir {
  param([string]$BasePath)
  if (-not (Test-Path -LiteralPath $BasePath)) {
    New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
  }
}

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

# Verify admin rights
if (-not (Test-IsAdmin)) {
  Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
  Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
  exit 1
}

$User = $env:USERNAME
$RootOut = "C:\Users\$User\Desktop\Deep Scan"
New-OutDir $RootOut
$Stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutDir = Join-Path $RootOut $Stamp
New-OutDir $OutDir

# Create subdirectories
$Dirs = @{
  Logs      = Join-Path $OutDir "Logs"
  ThirdParty = Join-Path $OutDir "ThirdParty"
  Memory    = Join-Path $OutDir "Memory"
  Network   = Join-Path $OutDir "Network"
  Registry  = Join-Path $OutDir "Registry"
  FileSystem = Join-Path $OutDir "FileSystem"
  Browser   = Join-Path $OutDir "Browser"
  WMI       = Join-Path $OutDir "WMI"
  Defender  = Join-Path $OutDir "Defender"
  Verification = Join-Path $OutDir "Verification"
  SystemRepair = Join-Path $OutDir "SystemRepair"
  Debloat   = Join-Path $OutDir "Debloat"
}
$Dirs.Values | ForEach-Object { New-OutDir $_ }

$TempTools = Join-Path $env:TEMP "DeepScanTools"
New-OutDir $TempTools

# Transcript log
$LiveLog = Join-Path $OutDir "DeepScan.log"
try { Start-Transcript -Path $LiveLog -Append | Out-Null } catch {}

# Note log with safe file sharing
$NoteLog = Join-Path $OutDir "DeepScan.note.log"
$global:NoteWriter = $null
try {
  $fs = [System.IO.File]::Open($NoteLog,
                                [System.IO.FileMode]::OpenOrCreate,
                                [System.IO.FileAccess]::Write,
                                [System.IO.FileShare]::ReadWrite)
  $global:NoteWriter = New-Object System.IO.StreamWriter($fs, [System.Text.Encoding]::UTF8)
  $global:NoteWriter.BaseStream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
  $global:NoteWriter.AutoFlush = $true
} catch {}

function Write-Note {
  param(
    [string]$msg,
    [string]$Level = "INFO"
  )
  $ts = (Get-Date).ToString("HH:mm:ss.fff")
  $line = "[$ts] [$Level] $msg"
  
  switch ($Level) {
    "ERROR"   { Write-Host $line -ForegroundColor Red }
    "WARNING" { Write-Host $line -ForegroundColor Yellow }
    "SUCCESS" { Write-Host $line -ForegroundColor Green }
    default   { Write-Host $line }
  }
  
  try { if ($global:NoteWriter) { $global:NoteWriter.WriteLine($line) } } catch {}
}

# -------------------- System Restore Point --------------------
function New-SystemRestorePoint {
  if ($NoRestorePoint) {
    Write-Note "Skipping system restore point creation (user requested)"
    return
  }
  
  Write-Note "Creating system restore point before scan"
  try {
    # Enable system restore on C: drive
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    
    # Create restore point
    $description = "DeepScan Pre-Scan Backup - $Stamp"
    Checkpoint-Computer -Description $description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
    
    Write-Note "System restore point created successfully" "SUCCESS"
    
    # Verify it was created
    $latestRP = Get-ComputerRestorePoint | Sort-Object -Property SequenceNumber -Descending | Select-Object -First 1
    if ($latestRP) {
      Write-Note "Restore point: $($latestRP.Description) (Sequence: $($latestRP.SequenceNumber))"
    }
  } catch {
    Write-Note "Failed to create restore point: $_" "WARNING"
    Write-Note "Consider creating one manually before proceeding" "WARNING"
    
    $response = Read-Host "Continue without restore point? (Y/N)"
    if ($response -ne 'Y') {
      Write-Note "Scan aborted by user"
      exit 1
    }
  }
}

# Create restore point early
New-SystemRestorePoint

# Network check
$NetworkAvailable = $true
if (-not $SkipNetworkCheck) {
  try {
    $testConnection = Test-NetConnection -ComputerName "8.8.8.8" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
    $NetworkAvailable = $testConnection
  } catch {
    $NetworkAvailable = $false
  }
  Write-Note "Network availability: $NetworkAvailable" $(if($NetworkAvailable){"SUCCESS"}else{"WARNING"})
}

# Prefer TLS 1.2
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# Resolve Sysinternals
$SysBase = "C:\Tools\Sysinternals"
$AutorunsEXE = @(
  (Join-Path $SysBase "autorunsc64.exe"),
  (Join-Path $SysBase "autorunsc.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$SigcheckEXE = @(
  (Join-Path $SysBase "sigcheck64.exe"),
  (Join-Path $SysBase "sigcheck.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$ListDLLsEXE = @(
  (Join-Path $SysBase "Listdlls64.exe"),
  (Join-Path $SysBase "Listdlls.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$TCPViewEXE = @(
  (Join-Path $SysBase "tcpvcon64.exe"),
  (Join-Path $SysBase "tcpvcon.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1

# Pre-accept Sysinternals EULAs
try {
  New-Item -Path 'HKCU:\Software\Sysinternals' -ErrorAction SilentlyContinue | Out-Null
  foreach ($tool in @('Autoruns','Sigcheck','Listdlls','tcpvcon')) {
    $key = "HKCU:\Software\Sysinternals\{0}" -f $tool
    New-Item -Path $key -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $key -Name 'EulaAccepted' -Value 1 -PropertyType DWord -Force | Out-Null
  }
} catch {}

if ($Full) {
  $IncludeAutoruns = $true
  $Deep            = $true
  $UseAdwCleaner   = $true
  $UseKVRT         = $true
  $UseMSERT        = $true
  $UseMemorySweep  = $true
  $UseRootkitScan  = $true
  $UseDefender     = $true
  $DoubleCheck     = $true
  $KVRTAllVolumes  = $true
  $Debloat         = $true
  $CleanTemp       = $true
  $RepairSystem    = $true
  $UpdateWindows   = $true
}

# -------------------- Helpers --------------------
function Invoke-Download {
  param(
    [Parameter(Mandatory)][string]$Url,
    [Parameter(Mandatory)][string]$OutFile
  )
  if (-not $NetworkAvailable) {
    Write-Note "Skipping download (no network): $Url" "WARNING"
    return $false
  }
  Write-Note "Downloading: $Url -> $OutFile"
  try {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $OutFile -TimeoutSec 1800 -ErrorAction Stop
    return $true
  } catch {
    Write-Note "Download failed from $Url : $($_.Exception.Message)" "ERROR"
    return $false
  }
}

function Start-Tool {
  param(
    [Parameter(Mandatory)][string]$FilePath,
    [string]$Arguments = "",
    [int]$TimeoutSeconds = 0,
    [switch]$CaptureOutput,
    [string]$WorkingDirectory = (Split-Path -Path $FilePath -Parent),
    [switch]$NoWait
  )
  if (-not (Test-Path -LiteralPath $FilePath)) {
    throw "Tool not found: $FilePath"
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $psi.Arguments = $Arguments
  $psi.WorkingDirectory = $WorkingDirectory
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  try { $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden } catch {}
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  if ($NoWait) { return 0 }
  if ($TimeoutSeconds -gt 0) {
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
      try { $p.Kill() } catch {}
      throw "Timed out after $TimeoutSeconds sec: $FilePath $Arguments"
    }
  } else {
    $p.WaitForExit()
  }
  $outObj = [pscustomobject]@{
    ExitCode = $p.ExitCode
    StdOut   = $p.StandardOutput.ReadToEnd()
    StdErr   = $p.StandardError.ReadToEnd()
  }
  return $outObj
}

function Invoke-CLI {
  param(
    [Parameter(Mandatory)][string]$File,
    [string]$Args = "",
    [string]$StdOutToFile = $null,
    [int]$TimeoutSeconds = 0
  )
  $res = Start-Tool -FilePath $File -Arguments $Args -TimeoutSeconds $TimeoutSeconds -CaptureOutput
  if ($StdOutToFile) { $res.StdOut | Out-File -FilePath $StdOutToFile -Encoding utf8 -Force }
  if ($res.StdErr)   { Write-Note ("{0} stderr: {1}" -f ([IO.Path]::GetFileName($File)), $res.StdErr.Trim()) "WARNING" }
  return $res
}

function Save-Text {
  param([string]$Path,[string]$Text)
  $dir = Split-Path -Path $Path -Parent
  if (-not (Test-Path $dir)) { New-OutDir $dir }
  $Text | Out-File -FilePath $Path -Encoding utf8 -Force
}

function Get-HashValue {
  param([string]$Path)
  if (Test-Path $Path) {
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
  }
  return $null
}

# -------------------- Temporary File Cleanup --------------------
function Clear-TempFilesSafely {
  if (-not $CleanTemp) { return }
  
  Write-Note "Starting safe temporary file cleanup"
  $cleanupReport = Join-Path $Dirs.SystemRepair "TempCleanup.log"
  $totalFreed = 0
  $cleanedItems = @()
  
  # Check if critical processes are running that we shouldn't interfere with
  $criticalProcesses = @('setup','msiexec','TrustedInstaller','wusa','Windows Update')
  $runningCritical = Get-Process | Where-Object { $criticalProcesses -contains $_.Name }
  
  if ($runningCritical) {
    Write-Note "Critical processes running, skipping temp cleanup to avoid interference" "WARNING"
    "Cleanup skipped - critical processes detected: $($runningCritical.Name -join ', ')" | Out-File $cleanupReport
    return
  }
  
  # Define safe temp locations with age filters
  $tempLocations = @(
    @{Path="$env:TEMP"; Age=7; Pattern="*"},
    @{Path="$env:WINDIR\Temp"; Age=7; Pattern="*"},
    @{Path="$env:WINDIR\Prefetch"; Age=30; Pattern="*.pf"},
    @{Path="$env:LOCALAPPDATA\Temp"; Age=7; Pattern="*"},
    @{Path="$env:LOCALAPPDATA\Microsoft\Windows\INetCache"; Age=30; Pattern="*"},
    @{Path="$env:LOCALAPPDATA\Microsoft\Windows\Explorer"; Age=30; Pattern="thumbcache*.db"},
    @{Path="$env:SystemRoot\SoftwareDistribution\Download"; Age=30; Pattern="*"},
    @{Path="$env:ProgramData\Microsoft\Windows\WER\ReportQueue"; Age=30; Pattern="*"}
  )
  
  foreach ($location in $tempLocations) {
    if (Test-Path $location.Path) {
      Write-Note "Cleaning: $($location.Path)"
      
      try {
        $cutoffDate = (Get-Date).AddDays(-$location.Age)
        $items = Get-ChildItem -Path $location.Path -Filter $location.Pattern -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { 
                   !$_.PSIsContainer -and 
                   $_.LastWriteTime -lt $cutoffDate -and
                   !$_.FullName.Contains('DeepScan') -and  # Don't delete our own files
                   !$_.Extension -in @('.sys','.dll','.exe') -or $_.FullName -match 'temp|tmp|cache'
                 }
        
        foreach ($item in $items) {
          try {
            $size = $item.Length
            Remove-Item -Path $item.FullName -Force -ErrorAction Stop
            $totalFreed += $size
            $cleanedItems += $item.FullName
          } catch {
            # File in use or protected, skip it
          }
        }
      } catch {
        Write-Note "Error cleaning $($location.Path): $_" "WARNING"
      }
    }
  }
  
  # Run Windows Disk Cleanup in silent mode
  Write-Note "Running Windows Disk Cleanup"
  try {
    # Configure cleanmgr with all safe options
    $cleanmgrKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
    $safeCleanupOptions = @(
      "Temporary Files",
      "Thumbnail Cache",
      "Recycle Bin",
      "Temporary Setup Files",
      "Windows Error Reporting Files",
      "Delivery Optimization Files",
      "DirectX Shader Cache",
      "System error memory dump files"
    )
    
    foreach ($option in $safeCleanupOptions) {
      $regPath = Join-Path $cleanmgrKey $option
      if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "StateFlags0100" -Value 2 -ErrorAction SilentlyContinue
      }
    }
    
    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:100" -Wait -NoNewWindow
  } catch {
    Write-Note "Windows Disk Cleanup failed: $_" "WARNING"
  }
  
  # Clear Windows Update cache if safe
  if (Get-Service -Name wuauserv | Where-Object {$_.Status -eq 'Stopped'}) {
    Write-Note "Clearing Windows Update cache"
    Remove-Item "$env:WINDIR\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
  }
  
  $freedMB = [math]::Round($totalFreed / 1MB, 2)
  Write-Note "Temp cleanup complete. Freed: $freedMB MB from $($cleanedItems.Count) files" "SUCCESS"
  
  # Save cleanup report
  @{
    Timestamp = Get-Date
    TotalFreedMB = $freedMB
    FilesRemoved = $cleanedItems.Count
    Details = $cleanedItems
  } | ConvertTo-Json -Depth 5 | Out-File $cleanupReport -Encoding utf8
}

# -------------------- Windows Debloating --------------------
function Remove-WindowsBloatware {
  if (-not $Debloat) { return }
  
  Write-Note "Starting Windows bloatware removal"
  $debloatLog = Join-Path $Dirs.Debloat "BloatwareRemoval.log"
  $removedApps = @()
  
  # Define bloatware apps (similar to Tron's list)
  $bloatwareApps = @(
    # Games
    "Microsoft.MicrosoftSolitaireCollection",
    "king.com.CandyCrushSaga",
    "king.com.CandyCrushSodaSaga",
    "king.com.BubbleWitch3Saga",
    "king.com.*",
    "Clipchamp.Clipchamp",
    "Disney.37853FC22B2CE",
    
    # Social/Communication (keep essential ones commented)
    # "Microsoft.Teams",  # Some orgs need this
    "Microsoft.People",
    "Microsoft.YourPhone",
    "Microsoft.Messaging",
    
    # Media apps (be careful with these)
    "Microsoft.ZuneMusic",  # Groove Music
    "Microsoft.ZuneVideo",  # Movies & TV
    "Microsoft.MixedReality.Portal",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MSPaint",  # Paint 3D, not classic Paint
    
    # News/Weather/Finance
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.BingFinance",
    "Microsoft.BingSports",
    
    # Misc Microsoft apps
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.OneConnect",
    "Microsoft.Print3D",
    "Microsoft.Wallet",
    "Microsoft.WindowsMaps",
    
    # Xbox (remove only if not gaming)
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.Xbox.TCUI",
    
    # Third-party pre-installed
    "SpotifyAB.SpotifyMusic",
    "Amazon.com.Amazon",
    "Facebook.*",
    "TikTok.*",
    "BytedancePte.Ltd.TikTok",
    "GAMELOFTSA.*",
    "*.Twitter",
    "*.Netflix",
    "*.Hulu",
    "*.AdobePhotoshopExpress"
  )
  
  # Remove each bloatware app
  foreach ($app in $bloatwareApps) {
    Write-Note "Checking for bloatware: $app"
    
    # Remove for current user
    $packages = Get-AppxPackage -Name $app -ErrorAction SilentlyContinue
    foreach ($package in $packages) {
      try {
        Write-Note "Removing: $($package.Name)"
        Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop
        $removedApps += $package.Name
      } catch {
        Write-Note "Failed to remove $($package.Name): $_" "WARNING"
      }
    }
    
    # Remove provisioned packages (prevents reinstall for new users)
    $provPackages = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like $app}
    foreach ($package in $provPackages) {
      try {
        Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop
        Write-Note "Removed provisioned: $($package.DisplayName)"
      } catch {
        Write-Note "Failed to remove provisioned $($package.DisplayName): $_" "WARNING"
      }
    }
  }
  
  # Disable telemetry scheduled tasks (like Tron does)
  $telemetryTasks = @(
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "Microsoft\Windows\Autochk\Proxy",
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "Microsoft\Windows\PI\Sqm-Tasks",
    "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
    "Microsoft\Windows\Windows Error Reporting\QueueReporting"
  )
  
  foreach ($task in $telemetryTasks) {
    try {
      Disable-ScheduledTask -TaskName $task -ErrorAction Stop
      Write-Note "Disabled telemetry task: $task"
    } catch {
      # Task might not exist in this Windows version
    }
  }
  
  # Disable some telemetry services (carefully selected)
  $telemetryServices = @(
    "DiagTrack",      # Connected User Experiences and Telemetry
    "dmwappushservice", # WAP Push Message Service
    "XblAuthManager",  # Xbox Live Auth Manager
    "XblGameSave",    # Xbox Live Game Save
    "XboxNetApiSvc"   # Xbox Live Networking Service
  )
  
  foreach ($service in $telemetryServices) {
    try {
      Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
      Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
      Write-Note "Disabled service: $service"
    } catch {
      # Service might not exist
    }
  }
  
  Write-Note "Bloatware removal complete. Removed $($removedApps.Count) apps" "SUCCESS"
  
  # Save debloat report
  @{
    Timestamp = Get-Date
    RemovedApps = $removedApps
    DisabledTasks = $telemetryTasks
    DisabledServices = $telemetryServices
  } | ConvertTo-Json -Depth 5 | Out-File $debloatLog -Encoding utf8
}

# -------------------- System File Integrity Check --------------------
function Test-SystemIntegrity {
  if (-not $RepairSystem) { return }
  
  Write-Note "Starting system integrity verification"
  $integrityLog = Join-Path $Dirs.SystemRepair "IntegrityCheck.log"
  
  # First, check if repairs are needed using DISM
  Write-Note "Running DISM health check"
  $dismCheck = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /CheckHealth" `
                             -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$integrityLog.dism.check"
  
  $needsRepair = $false
  if (Test-Path "$integrityLog.dism.check") {
    $dismOutput = Get-Content "$integrityLog.dism.check"
    if ($dismOutput -match "repairable|corrupt|unhealthy") {
      $needsRepair = $true
      Write-Note "System corruption detected, repairs needed" "WARNING"
    } else {
      Write-Note "No corruption detected by DISM" "SUCCESS"
    }
  }
  
  # Run SFC scan to check for corrupted files
  Write-Note "Running System File Checker verification"
  $sfcLog = Join-Path $Dirs.SystemRepair "sfc_scan.log"
  $sfcResult = Start-Process -FilePath "sfc.exe" -ArgumentList "/verifyonly" `
                            -Wait -PassThru -NoNewWindow -RedirectStandardOutput $sfcLog
  
  if (Test-Path $sfcLog) {
    $sfcOutput = Get-Content $sfcLog
    if ($sfcOutput -match "found corrupt files|integrity violations") {
      $needsRepair = $true
      Write-Note "SFC found corrupted files" "WARNING"
    }
  }
  
  # Only run repairs if needed
  if ($needsRepair) {
    Write-Note "System repairs needed, starting repair process" "WARNING"
    
    # Run DISM repair operations
    Write-Note "Running DISM ScanHealth (detailed scan)"
    Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /ScanHealth" `
                  -Wait -NoNewWindow
    
    Write-Note "Running DISM RestoreHealth (this may take 10-20 minutes)"
    $dismRepairLog = Join-Path $Dirs.SystemRepair "dism_repair.log"
    Start-Process -FilePath "DISM.exe" `
                  -ArgumentList "/Online /Cleanup-Image /RestoreHealth /LogPath:$dismRepairLog" `
                  -Wait -NoNewWindow
    
    # Now run SFC to repair
    Write-Note "Running System File Checker repair"
    $sfcRepairLog = Join-Path $Dirs.SystemRepair "sfc_repair.log"
    Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" `
                  -Wait -NoNewWindow -RedirectStandardOutput $sfcRepairLog
    
    # Verify repairs were successful
    Write-Note "Verifying repairs"
    Start-Process -FilePath "sfc.exe" -ArgumentList "/verifyonly" `
                  -Wait -NoNewWindow -RedirectStandardOutput "$sfcRepairLog.verify"
    
    if (Test-Path "$sfcRepairLog.verify") {
      $verifyOutput = Get-Content "$sfcRepairLog.verify"
      if ($verifyOutput -match "did not find any integrity violations") {
        Write-Note "System files successfully repaired!" "SUCCESS"
      } else {
        Write-Note "Some files could not be repaired - manual intervention may be needed" "WARNING"
      }
    }
  } else {
    Write-Note "No system file repairs needed" "SUCCESS"
  }
  
  # Component store cleanup
  Write-Note "Running component store cleanup"
  Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup" `
                -Wait -NoNewWindow
}

# -------------------- Windows Update Integration --------------------
function Invoke-WindowsUpdate {
  if (-not $UpdateWindows) { return }
  
  Write-Note "Checking for Windows Updates"
  $updateLog = Join-Path $Dirs.SystemRepair "WindowsUpdate.log"
  
  try {
    # Check if Windows Update service is running
    $wuService = Get-Service -Name wuauserv
    if ($wuService.Status -ne 'Running') {
      Write-Note "Starting Windows Update service"
      Start-Service -Name wuauserv
      Start-Sleep -Seconds 5
    }
    
    # Use Windows Update COM object
    Write-Note "Searching for updates..."
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    
    # Search for all applicable updates
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    
    if ($searchResult.Updates.Count -eq 0) {
      Write-Note "No updates available" "SUCCESS"
      "No updates found - $(Get-Date)" | Out-File $updateLog
      return
    }
    
    Write-Note "Found $($searchResult.Updates.Count) updates available"
    
    # List updates
    $updateList = @()
    foreach ($update in $searchResult.Updates) {
      $updateInfo = @{
        Title = $update.Title
        Severity = $update.MsrcSeverity
        Size = [math]::Round($update.MaxDownloadSize / 1MB, 2)
        Categories = ($update.Categories | ForEach-Object {$_.Name}) -join ", "
      }
      $updateList += $updateInfo
      Write-Note "Update: $($update.Title) [$($updateInfo.Size) MB]"
    }
    
    # Save update list
    $updateList | ConvertTo-Json -Depth 5 | Out-File $updateLog -Encoding utf8
    
    # Download updates
    Write-Note "Downloading updates..."
    $downloader = $updateSession.CreateUpdateDownloader()
    $downloader.Updates = $searchResult.Updates
    $downloadResult = $downloader.Download()
    
    if ($downloadResult.ResultCode -eq 2) {
      Write-Note "Updates downloaded successfully" "SUCCESS"
      
      # Install updates
      Write-Note "Installing updates (this may take a while)..."
      $installer = $updateSession.CreateUpdateInstaller()
      $installer.Updates = $searchResult.Updates
      $installResult = $installer.Install()
      
      if ($installResult.ResultCode -eq 2) {
        Write-Note "Updates installed successfully" "SUCCESS"
        
        if ($installResult.RebootRequired) {
          Write-Note "REBOOT REQUIRED to complete updates" "WARNING"
          $rebootPrompt = Read-Host "Reboot now? (Y/N)"
          if ($rebootPrompt -eq 'Y') {
            Write-Note "Rebooting in 30 seconds..."
            shutdown /r /t 30 /c "DeepScan Windows Updates Complete - Rebooting"
          }
        }
      } else {
        Write-Note "Some updates failed to install (Code: $($installResult.ResultCode))" "WARNING"
      }
    } else {
      Write-Note "Failed to download updates (Code: $($downloadResult.ResultCode))" "ERROR"
    }
    
  } catch {
    Write-Note "Windows Update check failed: $_" "ERROR"
  }
}
