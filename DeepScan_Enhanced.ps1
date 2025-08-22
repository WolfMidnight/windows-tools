# DeepScan Enhanced Security Toolkit v4.1
# Comprehensive Windows Security Scanner, Hardener, and Cleanup Utility
# Requires -RunAsAdministrator
# Requires -Version 5.1

param(
    [Parameter(HelpMessage="Run all scan components")]
    [switch]$Full,
    
    [Parameter(HelpMessage="Remove Windows bloatware")]
    [switch]$Debloat,
    
    [Parameter(HelpMessage="Run system file repairs")]
    [switch]$RepairSystem,
    
    [Parameter(HelpMessage="Check and install Windows updates")]
    [switch]$UpdateWindows,
    
    [Parameter(HelpMessage="Clean temporary files")]
    [switch]$CleanTemp,
    
    [Parameter(HelpMessage="Skip third-party AV scanners")]
    [switch]$SkipAVScans,
    
    [Parameter(HelpMessage="Skip memory analysis")]
    [switch]$SkipMemory,
    
    [Parameter(HelpMessage="Skip rootkit scans")]
    [switch]$SkipRootkit,
    
    [Parameter(HelpMessage="Skip browser analysis")]
    [switch]$SkipBrowser,
    
    [Parameter(HelpMessage="Skip PowerShell script analysis")]
    [switch]$SkipPowerShell,
    
    [Parameter(HelpMessage="Skip credential checks")]
    [switch]$SkipCredentials,
    
    [Parameter(HelpMessage="Enable verbose logging")]
    [switch]$VerboseLogging,
    
    [Parameter(HelpMessage="Export report in different formats")]
    [ValidateSet("HTML", "PDF", "JSON", "CSV", "All")]
    [string]$ExportFormat = "HTML",
    
    [Parameter(HelpMessage="Email report to specified address")]
    [string]$EmailReport,
    
    [Parameter(HelpMessage="Apply hardening recommendations automatically")]
    [switch]$AutoHarden,
    
    [Parameter(HelpMessage="Schedule regular scans")]
    [switch]$ScheduleScan,
    
    [Parameter(HelpMessage="Run in minimal interaction mode")]
    [switch]$Silent,
    
    [Parameter(HelpMessage="Specify custom output directory")]
    [string]$OutputDir,
    
    [Parameter(HelpMessage="Enable parallel processing for faster scans")]
    [switch]$Parallel,
    
    [Parameter(HelpMessage="Maximum number of parallel jobs")]
    [int]$MaxParallelJobs = 4,
    
    [Parameter(HelpMessage="Skip supply chain verification")]
    [switch]$SkipSupplyChain,
    
    [Parameter(HelpMessage="Skip network analysis")]
    [switch]$SkipNetwork,
    
    [Parameter(HelpMessage="Skip registry analysis")]
    [switch]$SkipRegistry,
    
    [Parameter(HelpMessage="Skip file system analysis")]
    [switch]$SkipFileSystem,
    
    [Parameter(HelpMessage="Skip Windows Defender analysis")]
    [switch]$SkipDefender,
    
    [Parameter(HelpMessage="Skip WMI persistence checks")]
    [switch]$SkipWMI
)

# If Full scan, enable everything except potentially destructive operations
if ($Full) {
    $Debloat = $true
    $RepairSystem = $true
    $UpdateWindows = $true
    $CleanTemp = $true
}

# ==================== CONSTANTS & INITIALIZATION ====================
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$Host.UI.RawUI.WindowTitle = "DeepScan Enhanced Security Toolkit v4.1"
$ScriptVersion = "4.1"
$global:ScanStartTime = Get-Date
$global:ThreatsFound = @()
$global:RemediationsApplied = @()
$global:RemediationsFailed = @()
$global:ToolsVerified = @()
$global:ToolsDownloaded = @()
$global:ToolsFailed = @()
$global:ParallelJobsRunning = 0
$global:ParallelJobsCompleted = 0
$global:ParallelJobsTotal = 0
$global:EstimatedTimeRemaining = $null
$global:LastProgressUpdate = Get-Date

# ==================== HELPER FUNCTIONS ====================

function Write-Log {
    param(
        [string]$Message,
        [string]$Type = "INFO",
        [switch]$NoLog,
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Type) {
        "ERROR"   { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "INFO"    { "Cyan" }
        "VERBOSE" { "Gray" }
        "DEBUG"   { "DarkGray" }
        default   { "White" }
    }
    
    $logMessage = "[$timestamp] [$Type] $Message"
    
    if (-not $NoConsole -and (-not $Silent -or $Type -eq "ERROR" -or $Type -eq "WARNING")) {
        Write-Host $logMessage -ForegroundColor $color
    }
    
    if (-not $NoLog -and $global:LogFile) {
        try {
            $logMessage | Out-File -FilePath $global:LogFile -Append -ErrorAction SilentlyContinue
        }
        catch {
            # If we can't write to the log file, try to create a fallback log
            try {
                $fallbackLog = Join-Path $env:TEMP "DeepScan_Fallback.log"
                $logMessage | Out-File -FilePath $fallbackLog -Append -ErrorAction SilentlyContinue
            }
            catch {
                # If all logging fails, we can't do much more
            }
        }
    }
    
    # Also log to verbose log if verbose mode is enabled
    if ($VerboseLogging -and $global:VerboseLogFile -and $Type -eq "VERBOSE") {
        try {
            $logMessage | Out-File -FilePath $global:VerboseLogFile -Append -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if verbose logging fails
        }
    }
    
    # Log errors to the error log
    if ($Type -eq "ERROR" -and $global:ErrorLogFile) {
        try {
            $logMessage | Out-File -FilePath $global:ErrorLogFile -Append -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if error logging fails
        }
    }
}

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Log "Failed to check admin privileges: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-FileHashSafe {
    param(
        [string]$Path,
        [string]$Algorithm = "SHA256"
    )
    try {
        if (Test-Path $Path -PathType Leaf) {
            return (Get-FileHash -Path $Path -Algorithm $Algorithm -ErrorAction Stop).Hash
        }
    } catch {
        Write-Log "Failed to hash file ${Path}: $($_.Exception.Message)" "WARNING"
    }
    return $null
}

function Get-ToolDownload {
    param(
        [string]$Url,
        [string]$OutFile,
        [string]$ToolName,
        [string]$ExpectedHash,
        [string]$HashAlgorithm = "SHA256"
    )
    
    Write-Log "Downloading $ToolName from $Url" "INFO"
    $maxRetries = 3
    $retryCount = 0
    $downloadSuccess = $false
    
    while ($retryCount -lt $maxRetries -and -not $downloadSuccess) {
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
            $ProgressPreference = 'Continue'
            
            # Verify hash if provided
            if ($ExpectedHash) {
                $fileHash = Get-FileHashSafe -Path $OutFile -Algorithm $HashAlgorithm
                if ($fileHash -ne $ExpectedHash) {
                    throw "Hash verification failed for $ToolName. Expected: $ExpectedHash, Got: $fileHash"
                }
                Write-Log "Hash verification successful for $ToolName" "SUCCESS"
            }
            
            $downloadSuccess = $true
            $global:ToolsDownloaded += $ToolName
            Write-Log "Successfully downloaded $ToolName" "SUCCESS"
            return $true
        } catch {
            $retryCount++
            Write-Log "Download attempt ${retryCount} failed for ${ToolName}: $($_.Exception.Message)" "WARNING"
            if ($retryCount -ge $maxRetries) {
                Write-Log "Failed to download $ToolName after $maxRetries attempts" "ERROR"
                $global:ToolsFailed += $ToolName
                return $false
            }
            Start-Sleep -Seconds 5
        }
    }
    return $downloadSuccess
}

function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete,
        [int]$SecondsRemaining = -1
    )
    
    # Update the last progress time
    $global:LastProgressUpdate = Get-Date
    
    # Calculate estimated time remaining if not provided
    if ($SecondsRemaining -lt 0 -and $PercentComplete -gt 0 -and $PercentComplete -lt 100) {
        $elapsedTime = (Get-Date) - $global:ScanStartTime
        $estimatedTotalTime = $elapsedTime.TotalSeconds / ($PercentComplete / 100)
        $estimatedRemainingTime = $estimatedTotalTime - $elapsedTime.TotalSeconds
        $SecondsRemaining = [math]::Max(0, [math]::Round($estimatedRemainingTime))
        $global:EstimatedTimeRemaining = $SecondsRemaining
    }
    
    # Format the time remaining string
    $timeRemaining = if ($SecondsRemaining -gt 0) {
        $ts = [timespan]::FromSeconds($SecondsRemaining)
        if ($ts.Hours -gt 0) {
            "{0:D2}h:{1:D2}m:{2:D2}s" -f $ts.Hours, $ts.Minutes, $ts.Seconds
        } elseif ($ts.Minutes -gt 0) {
            "{0:D2}m:{1:D2}s" -f $ts.Minutes, $ts.Seconds
        } else {
            "{0:D2}s" -f $ts.Seconds
        }
    } else {
        "Calculating..."
    }
    
    # Show progress with time remaining
    if (-not $Silent) {
        Write-Progress -Activity $Activity -Status "$Status (Est. remaining: $timeRemaining)" -PercentComplete $PercentComplete
    }
    
    # Log progress to verbose log
    Write-Log "Progress: $PercentComplete% - $Status (Est. remaining: $timeRemaining)" "VERBOSE" -NoConsole
}

function Get-SystemMetrics {
    param(
        [string]$Category, 
        [string]$Description,
        [hashtable]$Data = @{}
    )
    
    $metricsFile = Join-Path $global:Dirs.Summary "SystemMetrics.json"
    try {
        if (Test-Path $metricsFile) {
            $metrics = Get-Content $metricsFile -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        } else {
            $metrics = @{
                SystemInfo = @{}
                HardwareInfo = @{}
                Performance = @{}
                SecurityStatus = @{}
                NetworkStatus = @{}
                ScanResults = @{}
                SystemMaintenance = @{}
                SystemCleanup = @{}
            }
        }
        
        # Add metric to appropriate category
        if (-not $metrics.$Category) {
            $metrics.$Category = @{}
        }
        
        $metricData = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Data = $Data
        }
        
        $metrics.$Category.$Description = $metricData
        
        $metrics | ConvertTo-Json -Depth 10 | Out-File $metricsFile -Force
        return $true
    }
    catch {
        Write-Log "Failed to update system metrics: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Start-ParallelJob {
    param(
        [scriptblock]$ScriptBlock,
        [string]$Name,
        [hashtable]$ArgumentList = @{},
        [switch]$Wait
    )
    
    # If parallel processing is disabled, run synchronously
    if (-not $Parallel) {
        Write-Log "Running job '$Name' synchronously" "VERBOSE" -NoConsole
        try {
            $result = & $ScriptBlock @ArgumentList
            return $result
        }
        catch {
            Write-Log "Error in job '$Name': $($_.Exception.Message)" "ERROR"
            throw
        }
    }
    
    # Wait if we've reached the maximum number of parallel jobs
    while ($global:ParallelJobsRunning -ge $MaxParallelJobs) {
        Start-Sleep -Milliseconds 500
        # Check for completed jobs
        Get-Job | Where-Object { $_.State -eq "Completed" } | ForEach-Object {
            Receive-Job -Job $_ -AutoRemoveJob -Wait
            $global:ParallelJobsRunning--
            $global:ParallelJobsCompleted++
        }
    }
    
    # Start the job
    Write-Log "Starting parallel job '$Name'" "VERBOSE" -NoConsole
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    $global:ParallelJobsRunning++
    $global:ParallelJobsTotal++
    
    # Wait for the job to complete if requested
    if ($Wait) {
        $result = Receive-Job -Job $job -AutoRemoveJob -Wait
        $global:ParallelJobsRunning--
        $global:ParallelJobsCompleted++
        return $result
    }
    
    return $job
}

function Wait-AllJobs {
    Write-Log "Waiting for all parallel jobs to complete..." "VERBOSE" -NoConsole
    Get-Job | Wait-Job | Receive-Job -AutoRemoveJob
    $global:ParallelJobsRunning = 0
    Write-Log "All parallel jobs completed" "VERBOSE" -NoConsole
}

function Test-FileLock {
    param(
        [string]$Path
    )
    
    try {
        $fileInfo = New-Object System.IO.FileInfo $Path
        $stream = $fileInfo.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $stream.Close()
        return $false
    }
    catch {
        return $true
    }
}

function Wait-FileUnlock {
    param(
        [string]$Path,
        [int]$TimeoutSeconds = 30
    )
    
    $startTime = Get-Date
    $unlocked = $false
    
    while (-not $unlocked -and ((Get-Date) - $startTime).TotalSeconds -lt $TimeoutSeconds) {
        if (-not (Test-FileLock -Path $Path)) {
            $unlocked = $true
        }
        else {
            Start-Sleep -Milliseconds 500
        }
    }
    
    return $unlocked
}

function Add-Threat {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Path,
        [string]$Description,
        [string]$Severity = "Medium",
        [string]$RemediationAction = "None",
        [bool]$Remediated = $false,
        [hashtable]$AdditionalData = @{}
    )
    
    $threat = @{
        Category = $Category
        Name = $Name
        Path = $Path
        Description = $Description
        Severity = $Severity
        DetectionTime = Get-Date
        RemediationAction = $RemediationAction
        Remediated = $Remediated
        AdditionalData = $AdditionalData
    }
    
    $global:ThreatsFound += $threat
    
    # Log the threat
    $severityColor = switch($Severity) {
        "Critical" { "Red" }
        "High" { "Red" }
        "Medium" { "Yellow" }
        "Low" { "Cyan" }
        default { "White" }
    }
    # Use the color mapping to echo a colorized threat message to the console (optional)
    if (-not $Silent) {
        Write-Host ("Threat detected: [{0}] {1} - {2}" -f $Severity, $Name, $Description) -ForegroundColor $severityColor
    }
    
    return $threat
}

function Add-Remediation {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Description,
        [string]$Action,
        [bool]$Success = $true,
        [string]$ErrorMessage = "",
        [hashtable]$AdditionalData = @{}
    )
    
    $remediation = @{
        Category = $Category
        Name = $Name
        Description = $Description
        Action = $Action
        Success = $Success
        Time = Get-Date
        ErrorMessage = $ErrorMessage
        AdditionalData = $AdditionalData
    }
    
    if ($Success) {
        $global:RemediationsApplied += $remediation
        Write-Log "Remediation applied: $Name - $Description" "SUCCESS"
    }
    else {
        $global:RemediationsFailed += $remediation
        Write-Log "Remediation failed: $Name - $Description - $ErrorMessage" "ERROR"
    }
    
    return $remediation
}

function Test-InternetConnection {
    try {
        $testConnection = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet
        return $testConnection
    }
    catch {
        return $false
    }
}

function Get-RandomString {
    param(
        [int]$Length = 8,
        [char[]]$CharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray()
    )
    
    $random = New-Object System.Random
    $result = New-Object char[] $Length
    
    for ($i = 0; $i -lt $Length; $i++) {
        $result[$i] = $CharSet[$random.Next(0, $CharSet.Length)]
    }
    
    return -join $result
}

function Protect-String {
    param(
        [string]$String
    )
    
    try {
        $secureString = ConvertTo-SecureString -String $String -AsPlainText -Force
        return $secureString
    }
    catch {
        Write-Log "Failed to protect string: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Unprotect-String {
    param(
        [System.Security.SecureString]$SecureString
    )
    
    try {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        return $plainText
    }
    catch {
        Write-Log "Failed to unprotect string: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Compatibility wrapper for Get-WmiObject (removed in PowerShell 7)
function Get-WmiObject {
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(Mandatory=$true, Position=0)][string]$Class,
        [Parameter()][string]$Filter,
        [Parameter()][string]$Namespace
    )
    $nativeCmd = Get-Command -ErrorAction SilentlyContinue 'Microsoft.PowerShell.Management\Get-WmiObject'
    if ($nativeCmd) {
        if ($PSBoundParameters.ContainsKey('Filter')) {
            if ($PSBoundParameters.ContainsKey('Namespace')) {
                return & 'Microsoft.PowerShell.Management\Get-WmiObject' -Namespace $Namespace -Class $Class -Filter $Filter @PSBoundParameters
            } else {
                return & 'Microsoft.PowerShell.Management\Get-WmiObject' -Class $Class -Filter $Filter @PSBoundParameters
            }
        } else {
            if ($PSBoundParameters.ContainsKey('Namespace')) {
                return & 'Microsoft.PowerShell.Management\Get-WmiObject' -Namespace $Namespace -Class $Class @PSBoundParameters
            } else {
                return & 'Microsoft.PowerShell.Management\Get-WmiObject' -Class $Class @PSBoundParameters
            }
        }
    } else {
        if ($PSBoundParameters.ContainsKey('Filter')) {
            if ($PSBoundParameters.ContainsKey('Namespace')) {
                return Get-CimInstance -Namespace $Namespace -ClassName $Class -Filter $Filter @PSBoundParameters
            } else {
                return Get-CimInstance -ClassName $Class -Filter $Filter @PSBoundParameters
            }
        } else {
            if ($PSBoundParameters.ContainsKey('Namespace')) {
                return Get-CimInstance -Namespace $Namespace -ClassName $Class @PSBoundParameters
            } else {
                return Get-CimInstance -ClassName $Class @PSBoundParameters
            }
        }
    }
}

# ==================== SETUP OUTPUT DIRECTORIES ====================

# Verify admin rights
if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

# Setup output directories
$UserProfile = $env:USERPROFILE
$RootOut = if ($OutputDir) { $OutputDir } else { Join-Path $UserProfile "Desktop\Deep Scan" }
$Stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$global:OutDir = Join-Path $RootOut $Stamp

# Create main output directory
try {
    New-Item -ItemType Directory -Path $global:OutDir -Force -ErrorAction Stop | Out-Null
    Write-Host "Created scan directory: ${global:OutDir}" -ForegroundColor Green
} catch {
    Write-Host "CRITICAL: Cannot create scan directory: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Create organized subdirectories
$global:Dirs = @{
    Logs         = Join-Path $global:OutDir "01_Logs"
    Inventory    = Join-Path $global:OutDir "02_System_Inventory"
    Network      = Join-Path $global:OutDir "03_Network_Analysis"
    Memory       = Join-Path $global:OutDir "04_Memory_Analysis"
    FileSystem   = Join-Path $global:OutDir "05_FileSystem_Checks"
    Registry     = Join-Path $global:OutDir "06_Registry_Analysis"
    Defender     = Join-Path $global:OutDir "07_Windows_Defender"
    ThirdParty   = Join-Path $global:OutDir "08_ThirdParty_Scanners"
    Rootkits     = Join-Path $global:OutDir "09_Rootkit_Detection"
    SystemRepair = Join-Path $global:OutDir "10_System_Repairs"
    Debloat      = Join-Path $global:OutDir "11_Debloat_Results"
    TempCleanup  = Join-Path $global:OutDir "12_Cleanup_Reports"
    Browser      = Join-Path $global:OutDir "13_Browser_Analysis"
    WMI          = Join-Path $global:OutDir "14_WMI_Persistence"
    PowerShell   = Join-Path $global:OutDir "15_PowerShell_Analysis"
    Credentials  = Join-Path $global:OutDir "16_Credential_Security"
    Hardening    = Join-Path $global:OutDir "17_System_Hardening"
    Verification = Join-Path $global:OutDir "18_Verification_Pass"
    SupplyChain  = Join-Path $global:OutDir "19_Supply_Chain_Security"
    Summary      = $global:OutDir
    Tools        = Join-Path $global:OutDir "Tools"
}

# Create all subdirectories
foreach ($dirPath in $global:Dirs.Values | Sort-Object -Unique) {
    try {
        New-Item -ItemType Directory -Path $dirPath -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "Failed to create directory ${dirPath}: $($_.Exception.Message)" "WARNING"
    }
}

# Setup log files
$global:LogFile = Join-Path $global:Dirs.Logs "DeepScan.log"
$global:VerboseLogFile = Join-Path $global:Dirs.Logs "DeepScan_Verbose.log"
$global:ErrorLogFile = Join-Path $global:Dirs.Logs "DeepScan_Errors.log"

Write-Log "DeepScan Enhanced Security Toolkit v$ScriptVersion started at $(Get-Date)" "INFO"
Write-Log "Running with PowerShell version $($PSVersionTable.PSVersion)" "INFO"
Write-Log "Operating System: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)" "INFO"

# ==================== PHASE 1: SYSTEM INVENTORY ====================
function Get-SystemInventory {
    Write-Log "Phase 1: Collecting System Inventory" "INFO"
    $inventory = [ordered]@{}
    
    # Basic system info
    Write-Log "Collecting system information..."
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        
        $inventory.System = @{
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
            Domain = $env:USERDOMAIN
            OS = $osInfo.Caption
            Version = $osInfo.Version
            Architecture = $osInfo.OSArchitecture
            LastBoot = $osInfo.LastBootUpTime
            TimeZone = (Get-TimeZone).DisplayName
            Uptime = (Get-Date) - $osInfo.LastBootUpTime
            InstallDate = $osInfo.InstallDate
            WindowsDirectory = $env:windir
            SystemDirectory = $env:SystemRoot
            SystemDrive = $env:SystemDrive
            Manufacturer = $computerSystem.Manufacturer
            Model = $computerSystem.Model
            BIOSVersion = (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
            BIOSManufacturer = (Get-CimInstance Win32_BIOS).Manufacturer
            BIOSReleaseDate = (Get-CimInstance Win32_BIOS).ReleaseDate
        }
        Get-SystemMetrics -Category "SystemInfo" -Description "Basic system information collected" -Data @{
            OS = $osInfo.Caption
            Version = $osInfo.Version
            Architecture = $osInfo.OSArchitecture
            Uptime = [math]::Round(((Get-Date) - $osInfo.LastBootUpTime).TotalHours, 2)
        }
    } catch {
        Write-Log "Failed to collect system information: $($_.Exception.Message)" "ERROR"
        $inventory.System = @{
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
            Domain = $env:USERDOMAIN
        }
    }
    
    # Hardware info
    Write-Log "Collecting hardware information..."
    try {
        $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction Stop
        $inventory.Hardware = @{
            CPU = $cpuInfo.Name
            Cores = $cpuInfo.NumberOfCores
            LogicalProcessors = $cpuInfo.NumberOfLogicalProcessors
            MaxClockSpeed = $cpuInfo.MaxClockSpeed
            L2CacheSize = $cpuInfo.L2CacheSize
            L3CacheSize = $cpuInfo.L3CacheSize
            RAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            Disks = Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -eq 3 | ForEach-Object {
                @{
                    Drive = $_.DeviceID
                    Size = [math]::Round($_.Size / 1GB, 2)
                    Free = [math]::Round($_.FreeSpace / 1GB, 2)
                    UsedPercent = [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 2)
                    FileSystem = $_.FileSystem
                    VolumeName = $_.VolumeName
                }
            }
            GraphicsCards = Get-CimInstance Win32_VideoController | ForEach-Object {
                @{
                    Name = $_.Name
                    DriverVersion = $_.DriverVersion
                    VideoModeDescription = $_.VideoModeDescription
                    AdapterRAM = if ($_.AdapterRAM) { [math]::Round($_.AdapterRAM / 1MB, 2) } else { "Unknown" }
                }
            }
            NetworkAdapters = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true } | ForEach-Object {
                $config = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.Index -eq $_.Index }
                @{
                    Name = $_.Name
                    MACAddress = $_.MACAddress
                    AdapterType = $_.AdapterType
                    Speed = if ($_.Speed) { [math]::Round($_.Speed / 1MB, 2) } else { "Unknown" }
                    IPAddresses = $config.IPAddress
                    DHCPEnabled = $config.DHCPEnabled
                }
            }
        }
        Get-SystemMetrics -Category "HardwareInfo" -Description "Hardware information collected" -Data @{
            CPU = $cpuInfo.Name
            Cores = $cpuInfo.NumberOfCores
            RAM_GB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            DiskCount = ($inventory.Hardware.Disks | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to collect hardware information: $($_.Exception.Message)" "ERROR"
        $inventory.Hardware = @{}
    }
    
    # Processes with hashes
    Write-Log "Collecting process information with hashes..."
    try {
        $inventory.Processes = Get-Process | ForEach-Object {
            $proc = $_
            try {
                $wmiProc = Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                $procPath = $null
                if ($proc.Path) {
                    $procPath = $proc.Path
                } elseif ($wmiProc -and $wmiProc.ExecutablePath) {
                    $procPath = $wmiProc.ExecutablePath
                }
                
                $procHash = if ($procPath) { Get-FileHashSafe -Path $procPath } else { $null }
                $procSignature = $null
                
                if ($procPath -and (Test-Path $procPath)) {
                    try {
                        $signature = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
                        $procSignature = @{
                            Status = $signature.Status.ToString()
                            SignerCertificate = if ($signature.SignerCertificate) {
                                @{
                                    Subject = $signature.SignerCertificate.Subject
                                    Issuer = $signature.SignerCertificate.Issuer
                                    NotBefore = $signature.SignerCertificate.NotBefore
                                    NotAfter = $signature.SignerCertificate.NotAfter
                                    Thumbprint = $signature.SignerCertificate.Thumbprint
                                }
                            } else { $null }
                            TimeStamperCertificate = if ($signature.TimeStamperCertificate) {
                                @{
                                    Subject = $signature.TimeStamperCertificate.Subject
                                    Issuer = $signature.TimeStamperCertificate.Issuer
                                    NotBefore = $signature.TimeStamperCertificate.NotBefore
                                    NotAfter = $signature.TimeStamperCertificate.NotAfter
                                    Thumbprint = $signature.TimeStamperCertificate.Thumbprint
                                }
                            } else { $null }
                        }
                    } catch {
                        Write-Log "Failed to get signature for process $($proc.Name): $($_.Exception.Message)" "VERBOSE" -NoConsole
                    }
                }
                
                @{
                    Name = $proc.Name
                    Id = $proc.Id
                    Path = $procPath
                    CommandLine = if($wmiProc) { $wmiProc.CommandLine } else { $null }
                    Hash = $procHash
                    Company = $proc.Company
                    Product = $proc.Product
                    FileVersion = $proc.FileVersion
                    StartTime = $proc.StartTime
                    Signature = $procSignature
                    ParentProcessId = if($wmiProc) { $wmiProc.ParentProcessId } else { $null }
                    WorkingSet = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                    CPU = if ($proc.CPU) { [math]::Round($proc.CPU, 2) } else { 0 }
                    Threads = $proc.Threads.Count
                    Handles = $proc.HandleCount
                    Modules = $proc.Modules | ForEach-Object {
                        try {
                            @{
                                Name = $_.ModuleName
                                Path = $_.FileName
                                Company = $_.Company
                                Version = $_.FileVersion
                            }
                        } catch { $null }
                    } | Where-Object { $_ -ne $null }
                }
            } catch { 
                Write-Log "Failed to get info for process $($proc.Name): $($_.Exception.Message)" "VERBOSE" -NoConsole
                $null 
            }
        } | Where-Object { $_ -ne $null }
        Get-SystemMetrics -Category "SystemInfo" -Description "Process information collected" -Data @{
            ProcessCount = ($inventory.Processes | Measure-Object).Count
            SignedProcesses = ($inventory.Processes | Where-Object { $_.Signature -and $_.Signature.Status -eq "Valid" } | Measure-Object).Count
            UnsignedProcesses = ($inventory.Processes | Where-Object { -not $_.Signature -or $_.Signature.Status -ne "Valid" } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to collect process information: $($_.Exception.Message)" "ERROR"
        $inventory.Processes = @()
    }
    
    # Services
    Write-Log "Collecting service information..."
    try {
        $inventory.Services = Get-Service | ForEach-Object {
            $svc = $_
            try {
                $wmiSvc = Get-WmiObject Win32_Service -Filter "Name = '$($svc.Name)'" -ErrorAction SilentlyContinue
                $svcPath = if ($wmiSvc) { $wmiSvc.PathName } else { $null }
                $svcHash = if ($svcPath -and $svcPath -notmatch '^"?[A-Za-z]:\\Windows\\') { 
                    $cleanPath = $svcPath -replace '^"([^"]+)".*', '$1' -replace "^'([^']+)'.*", '$1' -replace '^([^ ]+).*', '$1'
                    Get-FileHashSafe -Path $cleanPath 
                } else { 
                    $null 
                }
                
                @{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status = $svc.Status.ToString()
                    StartType = $svc.StartType.ToString()
                    Path = $svcPath
                    Hash = $svcHash
                    Account = if ($wmiSvc) { $wmiSvc.StartName } else { $null }
                    Description = if ($wmiSvc) { $wmiSvc.Description } else { $null }
                    Dependencies = $svc.DependentServices | ForEach-Object { $_.Name }
                    ServicesDependedOn = $svc.ServicesDependedOn | ForEach-Object { $_.Name }
                }
            } catch {
                Write-Log "Failed to get detailed info for service $($svc.Name): $($_.Exception.Message)" "VERBOSE" -NoConsole
                @{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status = $svc.Status.ToString()
                    StartType = $svc.StartType.ToString()
                }
            }
        }
        Get-SystemMetrics -Category "SystemInfo" -Description "Service information collected" -Data @{
            ServiceCount = ($inventory.Services | Measure-Object).Count
            RunningServices = ($inventory.Services | Where-Object { $_.Status -eq "Running" } | Measure-Object).Count
            AutoStartServices = ($inventory.Services | Where-Object { $_.StartType -eq "Automatic" } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to collect service information: $($_.Exception.Message)" "ERROR"
        $inventory.Services = @()
    }
    
    # Scheduled Tasks
    Write-Log "Collecting scheduled tasks..."
    try {
        $inventory.ScheduledTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
            $task = $_
            try {
                $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $actions = $task.Actions | ForEach-Object {
                    @{
                        Execute = $_.Execute
                        Arguments = $_.Arguments
                        WorkingDirectory = $_.WorkingDirectory
                    }
                }
                
                $triggers = $task.Triggers | ForEach-Object {
                    @{
                        Type = $_.GetType().Name
                        Enabled = $_.Enabled
                        StartBoundary = $_.StartBoundary
                        EndBoundary = $_.EndBoundary
                        ExecutionTimeLimit = $_.ExecutionTimeLimit
                        Repetition = if ($_.Repetition) {
                            @{
                                Interval = $_.Repetition.Interval
                                Duration = $_.Repetition.Duration
                                StopAtDurationEnd = $_.Repetition.StopAtDurationEnd
                            }
                        } else { $null }
                    }
                }
                
                @{
                    Name = $task.TaskName
                    Path = $task.TaskPath
                    State = $task.State.ToString()
                    Author = $task.Author
                    Description = $task.Description
                    LastRun = if($info) { $info.LastRunTime } else { $null }
                    NextRun = if($info) { $info.NextRunTime } else { $null }
                    LastResult = if($info) { $info.LastTaskResult } else { $null }
                    Actions = $actions
                    Triggers = $triggers
                    Principal = @{
                        UserId = $task.Principal.UserId
                        LogonType = $task.Principal.LogonType.ToString()
                        RunLevel = $task.Principal.RunLevel.ToString()
                    }
                }
            } catch {
                Write-Log "Failed to get detailed info for task $($task.TaskName): $($_.Exception.Message)" "VERBOSE" -NoConsole
                @{
                    Name = $task.TaskName
                    Path = $task.TaskPath
                    State = $task.State.ToString()
                }
            }
        }
        Get-SystemMetrics -Category "SystemInfo" -Description "Scheduled tasks collected" -Data @{
            TaskCount = ($inventory.ScheduledTasks | Measure-Object).Count
            SystemTasks = ($inventory.ScheduledTasks | Where-Object { $_.Path -like "\Microsoft\Windows\*" } | Measure-Object).Count
            UserTasks = ($inventory.ScheduledTasks | Where-Object { $_.Path -notlike "\Microsoft\Windows\*" } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to collect scheduled tasks: $($_.Exception.Message)" "ERROR"
        $inventory.ScheduledTasks = @()
    }
    
    # Installed software
    Write-Log "Collecting installed software..."
    try {
        $uninstallKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        if (-not $Silent) {
            $uninstallKeys += @(
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
        }
        
        $inventory.InstalledSoftware = $uninstallKeys | ForEach-Object {
            Get-ItemProperty $_ -ErrorAction SilentlyContinue
        } | Where-Object { $_.DisplayName -and (-not $_.SystemComponent -or $_.SystemComponent -eq 0) } | ForEach-Object {
            @{
                Name = $_.DisplayName
                Version = $_.DisplayVersion
                Publisher = $_.Publisher
                InstallDate = $_.InstallDate
                InstallLocation = $_.InstallLocation
                UninstallString = $_.UninstallString
                EstimatedSize = if ($_.EstimatedSize) { [math]::Round($_.EstimatedSize / 1024, 2) } else { $null }
            }
        } | Sort-Object -Property Name
        
        Get-SystemMetrics -Category "SystemInfo" -Description "Installed software collected" -Data @{
            SoftwareCount = ($inventory.InstalledSoftware | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to collect installed software: $($_.Exception.Message)" "ERROR"
        $inventory.InstalledSoftware = @()
    }
    
    # Windows features
    Write-Log "Collecting Windows features..."
    try {
        $inventory.WindowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" } | ForEach-Object {
            @{
                Name = $_.FeatureName
                State = $_.State.ToString()
                Description = $_.Description
            }
        }
        
        Get-SystemMetrics -Category "SystemInfo" -Description "Windows features collected" -Data @{
            EnabledFeatureCount = ($inventory.WindowsFeatures | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to collect Windows features: $($_.Exception.Message)" "ERROR"
        $inventory.WindowsFeatures = @()
    }
    
    # Windows updates
    Write-Log "Collecting Windows update history..."
    try {
        $inventory.WindowsUpdates = Get-HotFix | ForEach-Object {
            @{
                HotFixID = $_.HotFixID
                Description = $_.Description
                InstalledBy = $_.InstalledBy
                InstalledOn = $_.InstalledOn
            }
        } | Sort-Object -Property InstalledOn -Descending
        
        Get-SystemMetrics -Category "SystemInfo" -Description "Windows updates collected" -Data @{
            UpdateCount = ($inventory.WindowsUpdates | Measure-Object).Count
            LastUpdate = if ($inventory.WindowsUpdates.Count -gt 0) { $inventory.WindowsUpdates[0].InstalledOn } else { $null }
        }
    } catch {
        Write-Log "Failed to collect Windows update history: $($_.Exception.Message)" "ERROR"
        $inventory.WindowsUpdates = @()
    }
    
    # User accounts
    Write-Log "Collecting user account information..."
    try {
        $inventory.UserAccounts = Get-LocalUser | ForEach-Object {
            @{
                Name = $_.Name
                FullName = $_.FullName
                Description = $_.Description
                Enabled = $_.Enabled
                LastLogon = $_.LastLogon
                PasswordRequired = $_.PasswordRequired
                PasswordLastSet = $_.PasswordLastSet
                PasswordExpires = $_.PasswordExpires
                UserMayChangePassword = $_.UserMayChangePassword
                PasswordNeverExpires = $_.PasswordNeverExpires
                AccountExpires = $_.AccountExpires
                SID = $_.SID.Value
            }
        }
        
        Get-SystemMetrics -Category "SystemInfo" -Description "User accounts collected" -Data @{
            UserCount = ($inventory.UserAccounts | Measure-Object).Count
            EnabledUsers = ($inventory.UserAccounts | Where-Object { $_.Enabled } | Measure-Object).Count
            AdminUsers = ($inventory.UserAccounts | Where-Object { 
                $user = $_
                Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $user.SID }
            } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to collect user account information: $($_.Exception.Message)" "ERROR"
        $inventory.UserAccounts = @()
    }
    
    # Local groups
    Write-Log "Collecting local group information..."
    try {
        $inventory.LocalGroups = Get-LocalGroup | ForEach-Object {
            $group = $_
            try {
                $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | ForEach-Object {
                    @{
                        Name = $_.Name
                        SID = $_.SID.Value
                        ObjectClass = $_.ObjectClass
                        PrincipalSource = $_.PrincipalSource.ToString()
                    }
                }
            } catch {
                $members = @()
            }
            
            @{
                Name = $group.Name
                Description = $group.Description
                SID = $group.SID.Value
                Members = $members
            }
        }
        
        Get-SystemMetrics -Category "SystemInfo" -Description "Local groups collected" -Data @{
            GroupCount = ($inventory.LocalGroups | Measure-Object).Count
            AdminGroupMembers = ($inventory.LocalGroups | Where-Object { $_.Name -eq "Administrators" } | Select-Object -ExpandProperty Members | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to collect local group information: $($_.Exception.Message)" "ERROR"
        $inventory.LocalGroups = @()
    }
    
    # Save inventory to files
    try {
        $inventoryJson = Join-Path $global:Dirs.Inventory "SystemInventory.json"
        $inventory | ConvertTo-Json -Depth 10 | Out-File $inventoryJson -Force
        
        # Save individual components to separate files for easier analysis
        $inventory.Keys | ForEach-Object {
            $component = $_
            $componentFile = Join-Path $global:Dirs.Inventory "$component.json"
            $inventory.$component | ConvertTo-Json -Depth 10 | Out-File $componentFile -Force
        }
        
        Write-Log "System inventory saved to $inventoryJson" "SUCCESS"
    } catch {
        Write-Log "Failed to save system inventory: $($_.Exception.Message)" "ERROR"
    }
    
    return $inventory
}

# ==================== PHASE 2: NETWORK SECURITY ====================
function Test-NetworkSecurity {
    Write-Log "Phase 2: Analyzing Network Security" "INFO"
    $networkResults = @{
        OpenPorts = @()
        Connections = @()
        FirewallRules = @()
        DNSCache = @()
        ARPCache = @()
        RoutingTable = @()
        NetworkShares = @()
        SMBShares = @()
        Vulnerabilities = @()
    }
    
    # Check open ports
    Write-Log "Checking open ports..."
    try {
        $networkResults.OpenPorts = Get-NetTCPConnection -State Listen | ForEach-Object {
            $conn = $_
            $proc = $null
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            } catch {}
            
            $port = @{
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State.ToString()
                OwningProcess = $conn.OwningProcess
                ProcessName = if ($proc) { $proc.Name } else { "Unknown" }
                CreationTime = $conn.CreationTime
            }
            
            # Check for suspicious ports
            $suspiciousPorts = @(4444, 31337, 1080, 6666, 6667, 6668, 6669, 6697, 8080, 8888, 9999, 12345, 54321)
            if ($suspiciousPorts -contains $conn.LocalPort) {
                $port.Suspicious = $true
                Add-Threat -Category "Network" -Name "Suspicious Port" -Path "TCP:$($conn.LocalPort)" `
                    -Description "Potentially suspicious port $($conn.LocalPort) is open and owned by process $($port.ProcessName) (PID: $($conn.OwningProcess))" `
                    -Severity "Medium" -RemediationAction "Investigate process and close port if not needed"
            } else {
                $port.Suspicious = $false
            }
            
            return $port
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "Open ports collected" -Data @{
            OpenPortCount = ($networkResults.OpenPorts | Measure-Object).Count
            SuspiciousPorts = ($networkResults.OpenPorts | Where-Object { $_.Suspicious } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to check open ports: $($_.Exception.Message)" "ERROR"
    }
    
    # Check active connections
    Write-Log "Checking active network connections..."
    try {
        $networkResults.Connections = Get-NetTCPConnection -State Established | ForEach-Object {
            $conn = $_
            $proc = $null
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            } catch {}
            
            $connection = @{
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State.ToString()
                OwningProcess = $conn.OwningProcess
                ProcessName = if ($proc) { $proc.Name } else { "Unknown" }
                CreationTime = $conn.CreationTime
            }
            
            # Check for suspicious connections
            $suspiciousIPs = @(
                "^10\.",  # Private networks (could be legitimate)
                "^172\.(1[6-9]|2[0-9]|3[0-1])\.",  # Private networks (could be legitimate)
                "^192\.168\.",  # Private networks (could be legitimate)
                "^127\.",  # Localhost (could be legitimate)
                "^0\.",  # Invalid
                "^169\.254\."  # APIPA (could indicate network issues)
            )
            
            $isSuspicious = $false
            foreach ($pattern in $suspiciousIPs) {
                if ($conn.RemoteAddress -match $pattern) {
                    $isSuspicious = $true
                    break
                }
            }
            
            # Check for suspicious ports
            $suspiciousPorts = @(4444, 31337, 1080, 6666, 6667, 6668, 6669, 6697, 8080, 8888, 9999, 12345, 54321)
            if ($suspiciousPorts -contains $conn.RemotePort) {
                $isSuspicious = $true
            }
            
            $connection.Suspicious = $isSuspicious
            
            if ($isSuspicious -and $conn.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" -and $proc.Name -notmatch "^(chrome|firefox|msedge|iexplore|opera|brave|vivaldi|safari)$") {
                Add-Threat -Category "Network" -Name "Suspicious Connection" -Path "$($conn.RemoteAddress):$($conn.RemotePort)" `
                    -Description "Potentially suspicious connection from $($connection.ProcessName) (PID: $($conn.OwningProcess)) to $($conn.RemoteAddress):$($conn.RemotePort)" `
                    -Severity "Medium" -RemediationAction "Investigate process and connection"
            }
            
            return $connection
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "Active connections collected" -Data @{
            ConnectionCount = ($networkResults.Connections | Measure-Object).Count
            SuspiciousConnections = ($networkResults.Connections | Where-Object { $_.Suspicious } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to check active connections: $($_.Exception.Message)" "ERROR"
    }
    
    # Check firewall rules
    Write-Log "Checking firewall rules..."
    try {
        $networkResults.FirewallRules = Get-NetFirewallRule -Enabled True | ForEach-Object {
            $rule = $_
            try {
                $filterPorts = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $filterAddresses = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                $filterApplications = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                
                $ruleInfo = @{
                    Name = $rule.Name
                    DisplayName = $rule.DisplayName
                    Description = $rule.Description
                    Enabled = $rule.Enabled
                    Direction = $rule.Direction.ToString()
                    Action = $rule.Action.ToString()
                    Profile = $rule.Profile.ToString()
                    Group = $rule.Group
                    LocalPorts = if ($filterPorts) { $filterPorts.LocalPort } else { $null }
                    RemotePorts = if ($filterPorts) { $filterPorts.RemotePort } else { $null }
                    Protocol = if ($filterPorts) { $filterPorts.Protocol } else { $null }
                    LocalAddresses = if ($filterAddresses) { $filterAddresses.LocalAddress } else { $null }
                    RemoteAddresses = if ($filterAddresses) { $filterAddresses.RemoteAddress } else { $null }
                    Program = if ($filterApplications) { $filterApplications.Program } else { $null }
                }
                
                # Check for potentially dangerous rules
                if ($rule.Action -eq "Allow" -and $rule.Direction -eq "Inbound" -and 
                    ($null -ne $filterAddresses -and ($filterAddresses.RemoteAddress -contains "Any" -or $filterAddresses.RemoteAddress -contains "*")) -and
                    ($null -eq $filterPorts -or $filterPorts.LocalPort -contains "Any" -or $filterPorts.LocalPort -contains "*" -or $null -eq $filterPorts.LocalPort)) {
                    $ruleInfo.Suspicious = $true
                    Add-Threat -Category "Network" -Name "Permissive Firewall Rule" -Path $rule.Name `
                        -Description "Overly permissive firewall rule '$($rule.DisplayName)' allows inbound connections from any address on any port" `
                        -Severity "Medium" -RemediationAction "Review and restrict firewall rule"
                } else {
                    $ruleInfo.Suspicious = $false
                }
                
                return $ruleInfo
            } catch {
                Write-Log "Failed to get detailed info for firewall rule $($rule.Name): $($_.Exception.Message)" "VERBOSE" -NoConsole
                return @{
                    Name = $rule.Name
                    DisplayName = $rule.DisplayName
                    Enabled = $rule.Enabled
                    Direction = $rule.Direction.ToString()
                    Action = $rule.Action.ToString()
                    Suspicious = $false
                }
            }
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "Firewall rules collected" -Data @{
            RuleCount = ($networkResults.FirewallRules | Measure-Object).Count
            InboundAllow = ($networkResults.FirewallRules | Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" } | Measure-Object).Count
            SuspiciousRules = ($networkResults.FirewallRules | Where-Object { $_.Suspicious } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to check firewall rules: $($_.Exception.Message)" "ERROR"
    }
    
    # Check DNS cache
    Write-Log "Checking DNS cache..."
    try {
        $networkResults.DNSCache = Get-DnsClientCache | ForEach-Object {
            @{
                Entry = $_.Entry
                Name = $_.Name
                Data = $_.Data
                Status = $_.Status.ToString()
                Type = $_.Type.ToString()
                TimeToLive = $_.TimeToLive
                Section = $_.Section.ToString()
                DataLength = $_.DataLength
            }
        }
        
        # Check for suspicious DNS entries
        $suspiciousDomains = @(
            "\.ru$", "\.cn$", "\.su$", "\.tk$", "\.cc$", "\.top$", "\.xyz$",
            "^[a-f0-9]{32}\.", "^[a-f0-9]{16}\.", "^[a-z0-9]{20,}\.",
            "pastebin\.com", "github\.io", "githubusercontent\.com",
            "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"  # IP addresses as domains
        )
        
        foreach ($entry in $networkResults.DNSCache) {
            foreach ($pattern in $suspiciousDomains) {
                if ($entry.Name -match $pattern) {
                    $entry.Suspicious = $true
                    Add-Threat -Category "Network" -Name "Suspicious DNS Entry" -Path $entry.Name `
                        -Description "Potentially suspicious DNS cache entry for domain $($entry.Name) resolving to $($entry.Data)" `
                        -Severity "Low" -RemediationAction "Investigate domain and clear DNS cache if suspicious"
                    break
                } else {
                    $entry.Suspicious = $false
                }
            }
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "DNS cache collected" -Data @{
            CacheEntryCount = ($networkResults.DNSCache | Measure-Object).Count
            SuspiciousEntries = ($networkResults.DNSCache | Where-Object { $_.Suspicious } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to check DNS cache: $($_.Exception.Message)" "ERROR"
    }
    
    # Check ARP cache
    Write-Log "Checking ARP cache..."
    try {
        $networkResults.ARPCache = Get-NetNeighbor | ForEach-Object {
            @{
                IPAddress = $_.IPAddress
                LinkLayerAddress = $_.LinkLayerAddress
                State = $_.State.ToString()
                Interface = $_.InterfaceAlias
                InterfaceIndex = $_.InterfaceIndex
            }
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "ARP cache collected" -Data @{
            ARPEntryCount = ($networkResults.ARPCache | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to check ARP cache: $($_.Exception.Message)" "ERROR"
    }
    
    # Check routing table
    Write-Log "Checking routing table..."
    try {
        $networkResults.RoutingTable = Get-NetRoute | ForEach-Object {
            $route = @{
                DestinationPrefix = $_.DestinationPrefix
                NextHop = $_.NextHop
                RouteMetric = $_.RouteMetric
                InterfaceIndex = $_.InterfaceIndex
                InterfaceAlias = $_.InterfaceAlias
                Protocol = $_.Protocol.ToString()
                AdminDistance = $_.AdminDistance
                Store = $_.Store.ToString()
            }
            
            # Check for suspicious routes
            if ($_.NextHop -ne "0.0.0.0" -and $_.NextHop -ne "::" -and $_.NextHop -ne "127.0.0.1" -and $_.NextHop -ne "::1") {
                if ($_.DestinationPrefix -match "^0\.0\.0\.0/0$" -or $_.DestinationPrefix -match "^::/0$") {
                    $route.Suspicious = $true
                    Add-Threat -Category "Network" -Name "Suspicious Route" -Path $_.DestinationPrefix `
                        -Description "Potentially suspicious default route pointing to $($_.NextHop) instead of expected gateway" `
                        -Severity "High" -RemediationAction "Investigate and correct routing table if compromised"
                } else {
                    $route.Suspicious = $false
                }
            } else {
                $route.Suspicious = $false
            }
            
            return $route
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "Routing table collected" -Data @{
            RouteCount = ($networkResults.RoutingTable | Measure-Object).Count
            SuspiciousRoutes = ($networkResults.RoutingTable | Where-Object { $_.Suspicious } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to check routing table: $($_.Exception.Message)" "ERROR"
    }
    
    # Check network shares
    Write-Log "Checking network shares..."
    try {
        $networkResults.NetworkShares = Get-WmiObject -Class Win32_Share | ForEach-Object {
            $share = @{
                Name = $_.Name
                Path = $_.Path
                Description = $_.Description
                Type = $_.Type
                Caption = $_.Caption
                AllowMaximum = $_.AllowMaximum
            }
            
            # Check for suspicious shares
            $defaultShares = @('ADMIN$', 'IPC$', 'C$', 'D$', 'E$', 'F$', 'G$', 'NETLOGON', 'SYSVOL', 'PRINT$')
            if ($_.Name -notin $defaultShares -and $_.Type -eq 0) {
                $share.Suspicious = $true
                Add-Threat -Category "Network" -Name "Non-Standard Share" -Path $_.Name `
                    -Description "Non-standard network share '$($_.Name)' exposing '$($_.Path)'" `
                    -Severity "Medium" -RemediationAction "Review share permissions and remove if not needed"
            } else {
                $share.Suspicious = $false
            }
            
            return $share
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "Network shares collected" -Data @{
            ShareCount = ($networkResults.NetworkShares | Measure-Object).Count
            SuspiciousShares = ($networkResults.NetworkShares | Where-Object { $_.Suspicious } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to check network shares: $($_.Exception.Message)" "ERROR"
    }
    
    # Check SMB shares
    Write-Log "Checking SMB shares..."
    try {
        $networkResults.SMBShares = Get-SmbShare | ForEach-Object {
            $share = $_
            try {
                $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                
                $shareInfo = @{
                    Name = $share.Name
                    Path = $share.Path
                    Description = $share.Description
                    ScopeName = $share.ScopeName
                    CurrentUsers = $share.CurrentUsers
                    EncryptData = $share.EncryptData
                    FolderEnumerationMode = $share.FolderEnumerationMode.ToString()
                    CachingMode = $share.CachingMode.ToString()
                    ContinuouslyAvailable = $share.ContinuouslyAvailable
                    ShareState = $share.ShareState.ToString()
                    ShareType = $share.ShareType.ToString()
                    ShadowCopy = $share.ShadowCopy
                    Special = $share.Special
                    Temporary = $share.Temporary
                    Access = $shareAccess | ForEach-Object {
                        @{
                            AccountName = $_.AccountName
                            AccessRight = $_.AccessRight.ToString()
                            AccessControlType = $_.AccessControlType.ToString()
                        }
                    }
                }
                
                # Check for suspicious share permissions
                $everyoneFullAccess = $shareAccess | Where-Object { 
                    $_.AccountName -match "Everyone" -and 
                    $_.AccessRight -eq "Full" -and 
                    $_.AccessControlType -eq "Allow" 
                }
                
                if ($everyoneFullAccess -and -not $share.Special) {
                    $shareInfo.Suspicious = $true
                    Add-Threat -Category "Network" -Name "Insecure Share Permissions" -Path $share.Name `
                        -Description "SMB share '$($share.Name)' grants 'Everyone' full access" `
                        -Severity "High" -RemediationAction "Restrict share permissions to specific users or groups"
                } else {
                    $shareInfo.Suspicious = $false
                }
                
                return $shareInfo
            } catch {
                Write-Log "Failed to get detailed info for SMB share $($share.Name): $($_.Exception.Message)" "VERBOSE" -NoConsole
                return @{
                    Name = $share.Name
                    Path = $share.Path
                    Description = $share.Description
                    Special = $share.Special
                    Suspicious = $false
                }
            }
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "SMB shares collected" -Data @{
            SMBShareCount = ($networkResults.SMBShares | Measure-Object).Count
            SuspiciousSMBShares = ($networkResults.SMBShares | Where-Object { $_.Suspicious } | Measure-Object).Count
        }
    } catch {
        Write-Log "Failed to check SMB shares: $($_.Exception.Message)" "ERROR"
    }
    
    # Check for common network vulnerabilities
    Write-Log "Checking for common network vulnerabilities..."
    try {
        # Check SMBv1
        $smbv1Enabled = $false
        try {
            $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($smbv1 -and $smbv1.State -eq "Enabled") {
                $smbv1Enabled = $true
                $networkResults.Vulnerabilities += @{
                    Name = "SMBv1 Enabled"
                    Description = "SMBv1 protocol is enabled, which is vulnerable to various attacks including EternalBlue"
                    Severity = "High"
                    RemediationAction = "Disable SMBv1 using 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'"
                }
                
                Add-Threat -Category "Network" -Name "SMBv1 Enabled" -Path "SMB1Protocol" `
                    -Description "SMBv1 protocol is enabled, which is vulnerable to various attacks including EternalBlue" `
                    -Severity "High" -RemediationAction "Disable SMBv1 using 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'"
            }
        } catch {
            Write-Log "Failed to check SMBv1 status: $($_.Exception.Message)" "WARNING"
        }
        
        # Check LLMNR
        $llmnrEnabled = $false
        try {
            $llmnrKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
            if (-not (Test-Path $llmnrKey) -or (Get-ItemProperty -Path $llmnrKey -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast -ne 0) {
                $llmnrEnabled = $true
                $networkResults.Vulnerabilities += @{
                    Name = "LLMNR Enabled"
                    Description = "Link-Local Multicast Name Resolution (LLMNR) is enabled, which is vulnerable to spoofing attacks"
                    Severity = "Medium"
                    RemediationAction = "Disable LLMNR through Group Policy or registry"
                }
                
                Add-Threat -Category "Network" -Name "LLMNR Enabled" -Path "LLMNR" `
                    -Description "Link-Local Multicast Name Resolution (LLMNR) is enabled, which is vulnerable to spoofing attacks" `
                    -Severity "Medium" -RemediationAction "Disable LLMNR through Group Policy or registry"
            }
        } catch {
            Write-Log "Failed to check LLMNR status: $($_.Exception.Message)" "WARNING"
        }
        
        # Check NetBIOS
        $netbiosEnabled = $false
        try {
            $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
            foreach ($adapter in $adapters) {
                if ($adapter.TcpipNetbiosOptions -ne 2) {  # 2 means disabled
                    $netbiosEnabled = $true
                    $networkResults.Vulnerabilities += @{
                        Name = "NetBIOS Enabled"
                        Description = "NetBIOS is enabled on one or more network adapters, which is vulnerable to spoofing attacks"
                        Severity = "Medium"
                        RemediationAction = "Disable NetBIOS on all network adapters"
                    }
                    
                    Add-Threat -Category "Network" -Name "NetBIOS Enabled" -Path "NetBIOS" `
                        -Description "NetBIOS is enabled on one or more network adapters, which is vulnerable to spoofing attacks" `
                        -Severity "Medium" -RemediationAction "Disable NetBIOS on all network adapters"
                    break
                }
            }
        } catch {
            Write-Log "Failed to check NetBIOS status: $($_.Exception.Message)" "WARNING"
        }
        
        # Check RDP
        $rdpEnabled = $false
        try {
            $rdpKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
            if ((Get-ItemProperty -Path $rdpKey -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0) {
                $rdpEnabled = $true
                
                # Check NLA
                $nlaEnabled = $false
                $nlaKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                if ((Get-ItemProperty -Path $nlaKey -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication -eq 1) {
                    $nlaEnabled = $true
                }
                
                if (-not $nlaEnabled) {
                    $networkResults.Vulnerabilities += @{
                        Name = "RDP Without NLA"
                        Description = "Remote Desktop Protocol is enabled without Network Level Authentication, which is vulnerable to attacks"
                        Severity = "High"
                        RemediationAction = "Enable Network Level Authentication for RDP"
                    }
                    
                    Add-Threat -Category "Network" -Name "RDP Without NLA" -Path "RDP" `
                        -Description "Remote Desktop Protocol is enabled without Network Level Authentication, which is vulnerable to attacks" `
                        -Severity "High" -RemediationAction "Enable Network Level Authentication for RDP"
                }
                
                # Check if RDP is exposed to the internet
                $rdpFirewallRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq "Inbound" }
                foreach ($rule in $rdpFirewallRules) {
                    $addressFilter = $rule | Get-NetFirewallAddressFilter
                    if ($addressFilter.RemoteAddress -contains "Any" -or $addressFilter.RemoteAddress -contains "*") {
                        $networkResults.Vulnerabilities += @{
                            Name = "RDP Exposed"
                            Description = "Remote Desktop Protocol is potentially exposed to the internet through firewall rule '$($rule.DisplayName)'"
                            Severity = "Critical"
                            RemediationAction = "Restrict RDP access to specific IP addresses or use a VPN"
                        }
                        
                        Add-Threat -Category "Network" -Name "RDP Exposed" -Path "RDP Firewall" `
                            -Description "Remote Desktop Protocol is potentially exposed to the internet through firewall rule '$($rule.DisplayName)'" `
                            -Severity "Critical" -RemediationAction "Restrict RDP access to specific IP addresses or use a VPN"
                        break
                    }
                }
            }
        } catch {
            Write-Log "Failed to check RDP status: $($_.Exception.Message)" "WARNING"
        }
        
        # Check UPnP
        $upnpEnabled = $false
        try {
            $upnpService = Get-Service -Name "upnphost" -ErrorAction SilentlyContinue
            if ($upnpService -and $upnpService.Status -eq "Running") {
                $upnpEnabled = $true
                $networkResults.Vulnerabilities += @{
                    Name = "UPnP Enabled"
                    Description = "Universal Plug and Play (UPnP) service is running, which can expose system to attacks"
                    Severity = "Medium"
                    RemediationAction = "Disable UPnP service if not needed"
                }
                
                Add-Threat -Category "Network" -Name "UPnP Enabled" -Path "upnphost" `
                    -Description "Universal Plug and Play (UPnP) service is running, which can expose system to attacks" `
                    -Severity "Medium" -RemediationAction "Disable UPnP service if not needed"
            }
        } catch {
            Write-Log "Failed to check UPnP status: $($_.Exception.Message)" "WARNING"
        }
        
        Get-SystemMetrics -Category "NetworkStatus" -Description "Network vulnerabilities collected" -Data @{
            VulnerabilityCount = ($networkResults.Vulnerabilities | Measure-Object).Count
            SMBv1Enabled = $smbv1Enabled
            LLMNREnabled = $llmnrEnabled
            NetBIOSEnabled = $netbiosEnabled
            RDPEnabled = $rdpEnabled
            UPnPEnabled = $upnpEnabled
        }
    } catch {
        Write-Log "Failed to check for network vulnerabilities: $($_.Exception.Message)" "ERROR"
    }
    
    # Save network results
    try {
        $networkJson = Join-Path $global:Dirs.Network "NetworkAnalysis.json"
        $networkResults | ConvertTo-Json -Depth 10 | Out-File $networkJson -Force
        
        # Save individual components to separate files for easier analysis
        $networkResults.Keys | ForEach-Object {
            $component = $_
            $componentFile = Join-Path $global:Dirs.Network "$component.json"
            $networkResults.$component | ConvertTo-Json -Depth 10 | Out-File $componentFile -Force
        }
        
        Write-Log "Network security analysis saved to $networkJson" "SUCCESS"
    } catch {
        Write-Log "Failed to save network security analysis: $($_.Exception.Message)" "ERROR"
    }
    
    return $networkResults
}

# ==================== PHASE 3: WINDOWS DEFENDER ====================
function Invoke-DefenderScan {
    Write-Log "Phase 3: Running Windows Defender Scan" "INFO"
    
    if ($SkipDefender) {
        Write-Log "Skipping Windows Defender scan as requested" "WARNING"
        return @{
            Skipped = $true
            Threats = @()
            Settings = @{}
        }
    }
    
    $defenderResults = @{
        Threats = @()
        Settings = @{}
        Exclusions = @()
        History = @()
        Signatures = @{}
    }
    
    # Check if Defender cmdlets are available
    $hasDefender = $null -ne (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)
    if (-not $hasDefender) {
        Write-Log "Windows Defender cmdlets not available in this session. Skipping Defender scan." "WARNING"
        $defenderResults.Status = @{ Available = $false }
    }
    
    # Check Windows Defender status
    if ($hasDefender) {
        Write-Log "Checking Windows Defender status..."
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
            $defenderResults.Status = @{
                AMServiceEnabled = $defenderStatus.AMServiceEnabled
                AntispywareEnabled = $defenderStatus.AntispywareEnabled
                AntivirusEnabled = $defenderStatus.AntivirusEnabled
                BehaviorMonitorEnabled = $defenderStatus.BehaviorMonitorEnabled
                IoavProtectionEnabled = $defenderStatus.IoavProtectionEnabled
                NISEnabled = $defenderStatus.NISEnabled
                OnAccessProtectionEnabled = $defenderStatus.OnAccessProtectionEnabled
                RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                TamperProtectionEnabled = $defenderStatus.TamperProtectionEnabled
                AntivirusSignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                AntivirusSignatureVersion = $defenderStatus.AntivirusSignatureVersion
                FullScanAge = $defenderStatus.FullScanAge
                QuickScanAge = $defenderStatus.QuickScanAge
                AntivirusSignatureAge = $defenderStatus.AntivirusSignatureAge
            }
            
            # Check for disabled protections
            if (-not $defenderStatus.RealTimeProtectionEnabled) {
                $null = Add-Threat -Category "Defender" -Name "Real-Time Protection Disabled" -Path "Windows Defender" `
                    -Description "Windows Defender real-time protection is disabled, leaving system vulnerable to active threats" `
                    -Severity "Critical" -RemediationAction "Enable real-time protection"
            }
            
            if (-not $defenderStatus.BehaviorMonitorEnabled) {
                $null = Add-Threat -Category "Defender" -Name "Behavior Monitoring Disabled" -Path "Windows Defender" `
                    -Description "Windows Defender behavior monitoring is disabled, reducing protection against zero-day threats" `
                    -Severity "High" -RemediationAction "Enable behavior monitoring"
            }
            
            if (-not $defenderStatus.IoavProtectionEnabled) {
                $null = Add-Threat -Category "Defender" -Name "IOAV Protection Disabled" -Path "Windows Defender" `
                    -Description "Windows Defender IOAV (Internet downloaded files) protection is disabled" `
                    -Severity "Medium" -RemediationAction "Enable IOAV protection"
            }
            
            if ($defenderStatus.AntivirusSignatureAge -gt 7) {
                $null = Add-Threat -Category "Defender" -Name "Outdated Signatures" -Path "Windows Defender" `
                    -Description "Windows Defender signatures are $($defenderStatus.AntivirusSignatureAge) days old" `
                    -Severity "High" -RemediationAction "Update Windows Defender signatures"
            }
            
            Get-SystemMetrics -Category "SecurityStatus" -Description "Windows Defender status collected" -Data @{
                RealTimeProtection = $defenderStatus.RealTimeProtectionEnabled
                BehaviorMonitor = $defenderStatus.BehaviorMonitorEnabled
                SignatureAge = $defenderStatus.AntivirusSignatureAge
                FullScanAge = $defenderStatus.FullScanAge
            }
        } catch {
            Write-Log "Failed to check Windows Defender status: $($_.Exception.Message)" "ERROR"
            $defenderStatus = $null
        }
    }
    
    # Check Windows Defender settings
    if ($hasDefender) {
        Write-Log "Checking Windows Defender settings..."
        try {
            $defenderPreferences = Get-MpPreference -ErrorAction Stop
            $defenderResults.Settings = @{
                ExclusionPath = $defenderPreferences.ExclusionPath
                ExclusionExtension = $defenderPreferences.ExclusionExtension
                ExclusionProcess = $defenderPreferences.ExclusionProcess
                ExclusionIpAddress = $defenderPreferences.ExclusionIpAddress
                DisableRealtimeMonitoring = $defenderPreferences.DisableRealtimeMonitoring
                DisableBehaviorMonitoring = $defenderPreferences.DisableBehaviorMonitoring
                DisableBlockAtFirstSeen = $defenderPreferences.DisableBlockAtFirstSeen
                DisableIOAVProtection = $defenderPreferences.DisableIOAVProtection
                DisablePrivacyMode = $defenderPreferences.DisablePrivacyMode
                DisableArchiveScanning = $defenderPreferences.DisableArchiveScanning
                DisableIntrusionPreventionSystem = $defenderPreferences.DisableIntrusionPreventionSystem
                DisableScriptScanning = $defenderPreferences.DisableScriptScanning
                SubmitSamplesConsent = $defenderPreferences.SubmitSamplesConsent
                MAPSReporting = $defenderPreferences.MAPSReporting
                HighThreatDefaultAction = $defenderPreferences.HighThreatDefaultAction
                ModerateThreatDefaultAction = $defenderPreferences.ModerateThreatDefaultAction
                LowThreatDefaultAction = $defenderPreferences.LowThreatDefaultAction
                SevereThreatDefaultAction = $defenderPreferences.SevereThreatDefaultAction
                ScanScheduleDay = $defenderPreferences.ScanScheduleDay
                ScanScheduleTime = $defenderPreferences.ScanScheduleTime
                RemediationScheduleDay = $defenderPreferences.RemediationScheduleDay
                RemediationScheduleTime = $defenderPreferences.RemediationScheduleTime
                SignatureUpdateInterval = $defenderPreferences.SignatureUpdateInterval
            }
            
            # Check for suspicious exclusions
            $suspiciousExclusions = @(
                "C:\\", "D:\\", "E:\\", "F:\\", "G:\\",
                "C:\\Windows\\", "C:\\Windows\\System32\\",
                "C:\\Program Files\\", "C:\\Program Files (x86)\\",
                "C:\\Users\\", "C:\\Documents and Settings\\",
                "C:\\ProgramData\\", "C:\\Users\\All Users\\",
                "*.exe", "*.dll", "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js"
            )
            
            $foundSuspiciousExclusions = @()
            
            foreach ($exclusion in ($defenderPreferences.ExclusionPath | Where-Object { $_ })) {
                foreach ($suspicious in $suspiciousExclusions) {
                    if ($exclusion -like $suspicious) {
                        $foundSuspiciousExclusions += $exclusion
                        $null = Add-Threat -Category "Defender" -Name "Suspicious Exclusion Path" -Path $exclusion `
                            -Description "Windows Defender has a suspicious exclusion path: $exclusion" `
                            -Severity "High" -RemediationAction "Review and remove suspicious exclusion"
                        break
                    }
                }
            }
            
            foreach ($exclusion in ($defenderPreferences.ExclusionExtension | Where-Object { $_ })) {
                if ($exclusion -in @("exe", "dll", "ps1", "bat", "cmd", "vbs", "js")) {
                    $foundSuspiciousExclusions += "*.$exclusion"
                    $null = Add-Threat -Category "Defender" -Name "Suspicious Exclusion Extension" -Path "*.$exclusion" `
                        -Description "Windows Defender has a suspicious exclusion extension: *.$exclusion" `
                        -Severity "High" -RemediationAction "Review and remove suspicious exclusion"
                }
            }
            
            $defenderResults.SuspiciousExclusions = $foundSuspiciousExclusions
            
            Get-SystemMetrics -Category "SecurityStatus" -Description "Windows Defender settings collected" -Data @{
                ExclusionCount = (($defenderPreferences.ExclusionPath | Measure-Object).Count) + 
                                (($defenderPreferences.ExclusionExtension | Measure-Object).Count) + 
                                (($defenderPreferences.ExclusionProcess | Measure-Object).Count)
                SuspiciousExclusionCount = ($foundSuspiciousExclusions | Measure-Object).Count
                ArchiveScanning = -not $defenderPreferences.DisableArchiveScanning
                ScriptScanning = -not $defenderPreferences.DisableScriptScanning
            }
        } catch {
            Write-Log "Failed to check Windows Defender settings: $($_.Exception.Message)" "ERROR"
        }
        
        # Get Windows Defender exclusions
        Write-Log "Collecting Windows Defender exclusions..."
        try {
            $defenderResults.Exclusions = @{
                Paths = $defenderPreferences.ExclusionPath | ForEach-Object { $_ }
                Extensions = $defenderPreferences.ExclusionExtension | ForEach-Object { $_ }
                Processes = $defenderPreferences.ExclusionProcess | ForEach-Object { $_ }
                IpAddresses = $defenderPreferences.ExclusionIpAddress | ForEach-Object { $_ }
            }
        } catch {
            Write-Log "Failed to collect Windows Defender exclusions: $($_.Exception.Message)" "ERROR"
        }
        
        # Get Windows Defender threat history
        Write-Log "Collecting Windows Defender threat history..."
        try {
            $defenderResults.History = Get-MpThreatDetection | ForEach-Object {
                @{
                    ThreatID = $_.ThreatID
                    ThreatName = $_.ThreatName
                    Path = $_.Path
                    ProcessName = $_.ProcessName
                    Resources = $_.Resources
                    InitialDetectionTime = $_.InitialDetectionTime
                    LastThreatStatusChangeTime = $_.LastThreatStatusChangeTime
                    ActionSuccess = $_.ActionSuccess
                    CurrentThreatExecutionStatus = $_.CurrentThreatExecutionStatus
                    CurrentThreatStatus = $_.CurrentThreatStatus
                    ThreatStatusChangeReason = $_.ThreatStatusChangeReason
                    RemediationTime = $_.RemediationTime
                    DomainUser = $_.DomainUser
                }
            }
            
            # Add recent threats to the threats list
            $recentThreats = $defenderResults.History | Where-Object { 
                $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) -and 
                $_.CurrentThreatStatus -ne "Resolved" 
            }
            
            foreach ($threat in $recentThreats) {
                $threatObj = Add-Threat -Category "Defender" -Name $threat.ThreatName -Path $threat.Path `
                    -Description "Windows Defender detected threat: $($threat.ThreatName) at $($threat.Path)" `
                    -Severity "High" -RemediationAction "Run full Windows Defender scan"
                $defenderResults.Threats += $threatObj
            }
            
            Get-SystemMetrics -Category "SecurityStatus" -Description "Windows Defender history collected" -Data @{
                ThreatHistoryCount = ($defenderResults.History | Measure-Object).Count
                RecentThreatsCount = ($recentThreats | Measure-Object).Count
            }
        } catch {
            Write-Log "Failed to collect Windows Defender threat history: $($_.Exception.Message)" "ERROR"
        }
        
        # Get Windows Defender signature information
        if ($defenderStatus) {
            Write-Log "Collecting Windows Defender signature information..."
            try {
                $defenderResults.Signatures = @{
                    AntivirusSignatureVersion = $defenderStatus.AntivirusSignatureVersion
                    AntivirusSignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                    AntivirusSignatureAge = $defenderStatus.AntivirusSignatureAge
                    AntispywareSignatureVersion = $defenderStatus.AntispywareSignatureVersion
                    AntispywareSignatureLastUpdated = $defenderStatus.AntispywareSignatureLastUpdated
                    AntispywareSignatureAge = $defenderStatus.AntispywareSignatureAge
                    NISSignatureVersion = $defenderStatus.NISSignatureVersion
                    NISSignatureLastUpdated = $defenderStatus.NISSignatureLastUpdated
                    NISSignatureAge = $defenderStatus.NISSignatureAge
                }
            } catch {
                Write-Log "Failed to collect Windows Defender signature information: $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Run a quick scan if no recent scans
        if ($defenderStatus -and $defenderStatus.QuickScanAge -gt 7 -and $defenderPreferences -and -not $defenderPreferences.DisableRealtimeMonitoring) {
            Write-Log "No recent Windows Defender quick scan found. Running quick scan..." "WARNING"
            try {
                Start-MpScan -ScanType QuickScan -ErrorAction Stop
                Write-Log "Windows Defender quick scan completed" "SUCCESS"
                
                # Get updated threat detections
                $updatedThreats = Get-MpThreatDetection | Where-Object { 
                    $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-30) 
                }
                
                foreach ($threat in $updatedThreats) {
                    $threatObj = Add-Threat -Category "Defender" -Name $threat.ThreatName -Path $threat.Path `
                        -Description "Windows Defender quick scan detected threat: $($threat.ThreatName) at $($threat.Path)" `
                        -Severity "High" -RemediationAction "Run full Windows Defender scan and clean threats"
                    $defenderResults.Threats += $threatObj
                }
                
                Get-SystemMetrics -Category "SecurityStatus" -Description "Windows Defender quick scan completed" -Data @{
                    NewThreatsFound = ($updatedThreats | Measure-Object).Count
                }
            } catch {
                Write-Log "Failed to run Windows Defender quick scan: $($_.Exception.Message)" "ERROR"
            }
        }
    }
    
    # Save defender results
    try {
        $defenderJson = Join-Path $global:Dirs.Defender "DefenderAnalysis.json"
        $defenderResults | ConvertTo-Json -Depth 10 | Out-File $defenderJson -Force
        
        # Save individual components to separate files for easier analysis
        $defenderResults.Keys | ForEach-Object {
            $component = $_
            $componentFile = Join-Path $global:Dirs.Defender "$component.json"
            $defenderResults.$component | ConvertTo-Json -Depth 10 | Out-File $componentFile -Force
        }
        
        Write-Log "Windows Defender analysis saved to $defenderJson" "SUCCESS"
    } catch {
        Write-Log "Failed to save Windows Defender analysis: $($_.Exception.Message)" "ERROR"
    }
    
    return $defenderResults
}

# ==================== PHASE 4-18 AND UTILITIES: IMPLEMENTATIONS ====================

function Get-MemoryAnalysis {
    Write-Log "Phase 4: Analyzing Memory" "INFO"
    $results = @{
        TopMemoryProcesses = @()
        SuspiciousModules = @()
    }
    try {
        $top = Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 25
        $results.TopMemoryProcesses = $top | ForEach-Object {
            $proc = $_
            @{
                Name = $proc.Name
                Id = $proc.Id
                WorkingSetMB = [math]::Round($proc.WorkingSet64/1MB,2)
                PagedMemoryMB = [math]::Round($proc.PagedMemorySize64/1MB,2)
                PeakWorkingSetMB = [math]::Round($proc.PeakWorkingSet64/1MB,2)
                Company = $proc.Company
                StartTime = $proc.StartTime
            }
        }
    } catch {
        Write-Log "Failed to enumerate top memory processes: $($_.Exception.Message)" "ERROR"
    }
    
    # Basic suspicious module heuristic: unsigned DLLs loaded into system processes
    try {
        $systemProcNames = @('lsass','winlogon','services','svchost','csrss')
        $sus = @()
        foreach ($p in (Get-Process | Where-Object { $_.Name -in $systemProcNames } )) {
            foreach ($m in $p.Modules) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $m.FileName -ErrorAction SilentlyContinue
                    if (-not $sig -or $sig.Status -ne 'Valid') {
                        $sus += @{
                            Process = $p.Name
                            Pid = $p.Id
                            ModulePath = $m.FileName
                            Company = $m.Company
                            SignatureStatus = if ($sig) { $sig.Status.ToString() } else { 'Unknown' }
                        }
                    }
                } catch { }
            }
        }
        $results.SuspiciousModules = $sus
    } catch {
        Write-Log "Failed to analyze loaded modules: $($_.Exception.Message)" "WARNING"
    }
    
    try {
        $out = Join-Path $global:Dirs.Memory "MemoryAnalysis.json"
        $results | ConvertTo-Json -Depth 10 | Out-File $out -Force
        Write-Log "Memory analysis saved to $out" "SUCCESS"
    } catch {
        Write-Log "Failed to save memory analysis: $($_.Exception.Message)" "ERROR"
    }
    return $results
}

function Test-RegistryPersistence {
    Write-Log "Phase 5: Checking Registry Persistence" "INFO"
    $results = @{
        RunKeys = @()
        Winlogon = @{}
        IFEO = @()
        AppInitDLLs = @()
        ServicesAnomalies = @()
        Suspicious = @()
    }
    
    $runPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($path in $runPaths) {
        try {
            if (Test-Path $path) {
                $item = Get-Item $path
                $item.GetValueNames() | ForEach-Object {
                    $value = $item.GetValue($_)
                    $entry = @{ Key = $path; Name = $_; Value = $value }
                    if ($value -match 'cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32|\\Users\\|Temp|AppData' ) {
                        $entry.Suspicious = $true
                        $null = Add-Threat -Category "Registry" -Name "Run Key Persistence" -Path "$path\\$_" -Description "Suspicious Run entry: $value" -Severity "Medium" -RemediationAction "Review and remove if malicious"
                        $results.Suspicious += $entry
                    }
                    $results.RunKeys += $entry
                }
            }
        } catch { Write-Log ("Failed reading {0}: {1}" -f $path, $_.Exception.Message) "WARNING" }
    }
    
    # Winlogon Shell/Userinit
    try {
        $wkey = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $shell = (Get-ItemProperty -Path $wkey -Name 'Shell' -ErrorAction SilentlyContinue).Shell
        $userinit = (Get-ItemProperty -Path $wkey -Name 'Userinit' -ErrorAction SilentlyContinue).Userinit
        $results.Winlogon = @{ Shell = $shell; Userinit = $userinit }
        if ($shell -and $shell -notmatch '^explorer\.exe$') {
            $null = Add-Threat -Category "Registry" -Name "Non-standard Shell" -Path "$wkey\\Shell" -Description "Winlogon Shell is '$shell'" -Severity "High" -RemediationAction "Restore to explorer.exe"
        }
        if ($userinit -and $userinit -notmatch 'userinit\.exe,?') {
            $null = Add-Threat -Category "Registry" -Name "Userinit Modified" -Path "$wkey\\Userinit" -Description "Winlogon Userinit is '$userinit'" -Severity "High" -RemediationAction "Restore to userinit.exe,"
        }
    } catch { Write-Log "Failed to read Winlogon keys: $($_.Exception.Message)" "WARNING" }
    
    # IFEO Debugger
    try {
        $ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        if (Test-Path $ifeo) {
            Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
                $dbg = (Get-ItemProperty -Path $_.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
                if ($dbg) {
                    $results.IFEO += @{ Image = $_.PSChildName; Debugger = $dbg }
                    $null = Add-Threat -Category "Registry" -Name "IFEO Debugger" -Path $_.PSPath -Description "Debugger set to '$dbg'" -Severity "High" -RemediationAction "Remove malicious debugger value"
                }
            }
        }
    } catch { Write-Log "Failed to read IFEO: $($_.Exception.Message)" "WARNING" }
    
    # AppInit_DLLs
    try {
        $ai = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows'
        $appinit = (Get-ItemProperty -Path $ai -Name 'AppInit_DLLs' -ErrorAction SilentlyContinue).AppInit_DLLs
        if ($appinit) {
            $results.AppInitDLLs += $appinit
            $null = Add-Threat -Category "Registry" -Name "AppInit_DLLs" -Path "$ai\\AppInit_DLLs" -Description "AppInit_DLLs configured: $appinit" -Severity "High" -RemediationAction "Clear AppInit_DLLs if malicious"
        }
    } catch { Write-Log "Failed to read AppInit_DLLs: $($_.Exception.Message)" "WARNING" }
    
    # Service image paths outside Windows and unsigned
    try {
        $svcs = Get-CimInstance Win32_Service | ForEach-Object {
            $path = $_.PathName
            if ($path) {
                $cleanQuotedDouble = $path -replace '^[\"]([^\"]+)[\"].*', '$1'
                $cleanQuotedSingle = $cleanQuotedDouble -replace "^'([^']+)'.*", '$1'
                $clean = $cleanQuotedSingle -replace '^([^ ]+).*', '$1'
                @{ Name = $_.Name; State = $_.State; Path = $path; CleanPath = $clean }
            }
        }
        foreach ($s in $svcs) {
            try {
                if ($s.CleanPath -and (Test-Path $s.CleanPath) -and ($s.CleanPath -notmatch '^C:\\Windows\\')) {
                    $sig = Get-AuthenticodeSignature -FilePath $s.CleanPath -ErrorAction SilentlyContinue
                    if (-not $sig -or $sig.Status -ne 'Valid') {
                        $entry = @{ Service = $s.Name; Path = $s.CleanPath; Signature = if ($sig) { $sig.Status.ToString() } else { 'Unknown' } }
                        $results.ServicesAnomalies += $entry
                        $null = Add-Threat -Category "Registry" -Name "Unsigned Non-System Service" -Path $s.CleanPath -Description "Service $($s.Name) runs unsigned binary outside Windows" -Severity "High" -RemediationAction "Investigate service"
                    }
                }
            } catch {}
        }
    } catch { Write-Log "Failed to analyze services: $($_.Exception.Message)" "WARNING" }
    
    try {
        $out = Join-Path $global:Dirs.Registry "RegistryAnalysis.json"
        $results | ConvertTo-Json -Depth 10 | Out-File $out -Force
        Write-Log "Registry analysis saved to $out" "SUCCESS"
    } catch { Write-Log "Failed to save registry analysis: $($_.Exception.Message)" "ERROR" }
    return $results
}

function Test-FileSystemThreats {
    Write-Log "Phase 6: Checking File System" "INFO"
    $results = @{
        StartupItems = @()
        SuspiciousFiles = @()
        AlternateDataStreams = @()
    }
    $startupDirs = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($d in $startupDirs) {
        try {
            if (Test-Path $d) {
                Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $results.StartupItems += @{ Path = $_.FullName; Hash = (Get-FileHashSafe -Path $_.FullName) }
                }
            }
        } catch { Write-Log ("Failed to enumerate {0}: {1}" -f $d, $_.Exception.Message) "WARNING" }
    }
    
    $suspPaths = @(
        $env:TEMP,
        "$env:WINDIR\Temp",
        "$env:USERPROFILE\Downloads"
    )
    $exts = @('exe','dll','ps1','vbs','js','bat','cmd','scr','lnk')
    foreach ($p in $suspPaths) {
        try {
            if (Test-Path $p) {
                Get-ChildItem -Path $p -Recurse -Include ($exts | ForEach-Object { "*.$_" }) -ErrorAction SilentlyContinue | ForEach-Object {
                    $sig = $null
                    try { $sig = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue } catch {}
                    $isSusp = ($_.Length -gt 0MB -and (-not $sig -or $sig.Status -ne 'Valid'))
                    $fi = @{ Path = $_.FullName; Size = $_.Length; Signature = if ($sig) { $sig.Status.ToString() } else { 'Unknown' } }
                    if ($isSusp) { $null = Add-Threat -Category "FileSystem" -Name "Suspicious File" -Path $_.FullName -Description "Unsigned file in $p" -Severity "Medium" -RemediationAction "Quarantine or delete if malicious"; $results.SuspiciousFiles += $fi }
                }
            }
        } catch { Write-Log ("Failed to scan {0}: {1}" -f $p, $_.Exception.Message) "WARNING" }
    }
    
    # Alternate Data Streams in user profile
    try {
        $userProfile = $env:USERPROFILE
        Get-ChildItem -Path $userProfile -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne '::$DATA' -and $_.Length -gt 0 }
                foreach ($s in $streams) {
                    $entry = @{ Path = $_.FullName; Stream = $s.Stream; Length = $s.Length }
                    $results.AlternateDataStreams += $entry
                    $null = Add-Threat -Category "FileSystem" -Name "Alternate Data Stream" -Path ("$($_.FullName):$($s.Stream)") -Description "Non-empty ADS found" -Severity "Low" -RemediationAction "Remove stream if not needed"
                }
            } catch {}
        }
    } catch { Write-Log "Failed to scan for Alternate Data Streams: $($_.Exception.Message)" "WARNING" }
    
    try { $out = Join-Path $global:Dirs.FileSystem "FileSystemAnalysis.json"; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force; Write-Log "File system analysis saved to $out" "SUCCESS" } catch { Write-Log "Failed to save file system analysis: $($_.Exception.Message)" "ERROR" }
    return $results
}

function Invoke-ThirdPartyAV {
    Write-Log "Phase 7: Running Third-Party AV Scanners" "INFO"
    $results = @{
        Attempted = @()
        Logs = @()
        Errors = @()
    }
    if (-not (Test-InternetConnection)) {
        Write-Log "No internet connection. Skipping third-party AV downloads." "WARNING"
        return $results
    }
    
    # Microsoft Safety Scanner (MSERT)
    try {
        $msertUrl = 'https://go.microsoft.com/fwlink/?LinkID=2126431'
        $msertExe = Join-Path $global:Dirs.Tools 'msert.exe'
        if (Get-ToolDownload -Url $msertUrl -OutFile $msertExe -ToolName 'MSERT' -ExpectedHash $null) {
            $results.Attempted += 'MSERT'
            Write-Log "Starting Microsoft Safety Scanner (silent quick scan)" "INFO"
            Start-Process -FilePath $msertExe -ArgumentList "/Q /F:Y" -Wait -NoNewWindow
            $log = Join-Path $env:WINDIR 'debug\msert.log'
            if (Test-Path $log) { Copy-Item $log (Join-Path $global:Dirs.ThirdParty 'msert.log') -Force; $results.Logs += 'msert.log' }
        }
    } catch { $results.Errors += $_.Exception.Message; Write-Log "MSERT failed: $($_.Exception.Message)" "WARNING" }
    
    # Kaspersky KVRT
    try {
        $kvrtUrl = 'https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe'
        $kvrtExe = Join-Path $global:Dirs.Tools 'KVRT.exe'
        if (Get-ToolDownload -Url $kvrtUrl -OutFile $kvrtExe -ToolName 'KVRT' -ExpectedHash $null) {
            $results.Attempted += 'KVRT'
            Write-Log "Starting KVRT (consentless mode)" "INFO"
            Start-Process -FilePath $kvrtExe -ArgumentList "-accepteula -adinsilent -dontcryptsupportinfo -silent -processlevel 1" -Wait -NoNewWindow
            Get-ChildItem "$env:SystemDrive\KVRT_Data\*" -ErrorAction SilentlyContinue | Copy-Item -Destination $global:Dirs.ThirdParty -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch { $results.Errors += $_.Exception.Message; Write-Log "KVRT failed: $($_.Exception.Message)" "WARNING" }
    
    try { $out = Join-Path $global:Dirs.ThirdParty 'ThirdPartyAV.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Invoke-RootkitDetection {
    Write-Log "Phase 8: Rootkit Detection" "INFO"
    $results = @{
        UnsignedDrivers = @()
        HiddenDrivers = @()
    }
    try {
        $drivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' }
        foreach ($d in $drivers) {
            $path = $null
            if ($d.PathName) {
                $cleanQuotedDouble = $d.PathName -replace '^[\"]([^\"]+)[\"].*', '$1'
                $cleanQuotedSingle = $cleanQuotedDouble -replace "^'([^']+)'.*", '$1'
                $path = $cleanQuotedSingle -replace '^([^ ]+).*', '$1'
            }
            if ($path -and (Test-Path $path)) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                    if (-not $sig -or $sig.Status -ne 'Valid') {
                        $results.UnsignedDrivers += @{ Name = $d.Name; DisplayName = $d.DisplayName; Path = $path; Signature = if ($sig) { $sig.Status.ToString() } else { 'Unknown' } }
                        $null = Add-Threat -Category "Rootkit" -Name "Unsigned Kernel Driver" -Path $path -Description "Unsigned driver '$($d.DisplayName)' running" -Severity "High" -RemediationAction "Investigate driver"
                    }
                } catch {}
            }
        }
    } catch { Write-Log "Failed to enumerate drivers: $($_.Exception.Message)" "ERROR" }
    try { $out = Join-Path $global:Dirs.Rootkits 'RootkitAnalysis.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Test-SystemIntegrity {
    Write-Log "Phase 9: System Repairs" "INFO"
    $results = @{
        SFC = @{}
        DISM = @{}
    }
    try {
        Write-Log "Running SFC /SCANNOW..." "INFO"
        $sfcLog = Join-Path $global:Dirs.SystemRepair 'sfc.log'
        Start-Process -FilePath 'sfc.exe' -ArgumentList '/scannow' -Wait -NoNewWindow | Out-Null
        $results.SFC = @{ Ran = $true; Time = (Get-Date) }
        Get-Content "$env:windir\Logs\CBS\CBS.log" -ErrorAction SilentlyContinue | Out-File $sfcLog -Force
    } catch { Write-Log "SFC failed: $($_.Exception.Message)" "ERROR" }
    
    try {
        $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
        if ($osVersion -like '10.*' -or $osVersion -like '6.3.*' -or $osVersion -like '6.2.*' -or $osVersion -like '6.1.*' -or $osVersion -like '11.*') {
            Write-Log "Running DISM RestoreHealth..." "INFO"
            $dismLog = Join-Path $global:Dirs.SystemRepair 'dism.log'
            Start-Process -FilePath 'dism.exe' -ArgumentList '/Online /Cleanup-Image /RestoreHealth' -Wait -NoNewWindow | Out-Null
            Get-Content "$env:windir\Logs\DISM\dism.log" -ErrorAction SilentlyContinue | Out-File $dismLog -Force
            $results.DISM = @{ Ran = $true; Time = (Get-Date) }
        }
    } catch { Write-Log "DISM failed: $($_.Exception.Message)" "ERROR" }
    try { $out = Join-Path $global:Dirs.SystemRepair 'SystemRepair.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Invoke-WindowsUpdate {
    Write-Log "Phase 10: Windows Update" "INFO"
    $results = @{
        Found = 0
        Installed = 0
        Updates = @()
        Errors = @()
    }
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $criteria = "IsInstalled=0 and Type='Software'"
        $searchResult = $searcher.Search($criteria)
        $results.Found = $searchResult.Updates.Count
        if ($searchResult.Updates.Count -gt 0) {
            $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
            for ($i=0; $i -lt $searchResult.Updates.Count; $i++) { [void]$toInstall.Add($searchResult.Updates.Item($i)); $results.Updates += $searchResult.Updates.Item($i).Title }
            $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $toInstall; $null = $downloader.Download()
            $installer = $session.CreateUpdateInstaller(); $installer.Updates = $toInstall; $res = $installer.Install(); $results.Installed = $res.UpdatesInstalled
            if ($res.RebootRequired) { Write-Log "Windows Update requires a reboot to complete." "WARNING" }
        }
    } catch { $results.Errors += $_.Exception.Message; Write-Log "Windows Update failed: $($_.Exception.Message)" "ERROR" }
    try { $out = Join-Path $global:Dirs.Summary 'WindowsUpdate.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Remove-WindowsBloatware {
    Write-Log "Phase 11: Debloating Windows (safe set)" "INFO"
    $results = @{
        RemovedAppx = @()
        RemovedProvisioned = @()
        Errors = @()
    }
    $safeList = @(
        'Microsoft.3DBuilder','Microsoft.Microsoft3DViewer','Microsoft.BingNews','Microsoft.BingWeather','Microsoft.GetHelp','Microsoft.Getstarted','Microsoft.Messaging','Microsoft.MicrosoftOfficeHub','Microsoft.MicrosoftSolitaireCollection','Microsoft.MixedReality.Portal','Microsoft.OneConnect','Microsoft.People','Microsoft.Print3D','Microsoft.SkypeApp','Microsoft.Todos','Microsoft.XboxApp','Microsoft.XboxGamingOverlay','Microsoft.XboxGameOverlay','Microsoft.XboxIdentityProvider','Microsoft.XboxSpeechToTextOverlay','Microsoft.YourPhone','Microsoft.ZuneMusic','Microsoft.ZuneVideo','Microsoft.MicrosoftStickyNotes','Microsoft.WindowsFeedbackHub','Microsoft.WindowsMaps','Microsoft.Xbox.TCUI','Clipchamp.Clipchamp','Disney.37853FC22B2CE','Facebook.Facebook','SpotifyAB.SpotifyMusic'
    )
    try {
        Get-AppxPackage | Where-Object { $_.Name -in $safeList } | ForEach-Object { try { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction Stop; $results.RemovedAppx += $_.Name } catch { $results.Errors += $_.Name } }
    } catch { Write-Log "Failed removing Appx packages: $($_.Exception.Message)" "WARNING" }
    try {
        Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -in $safeList } | ForEach-Object { try { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop | Out-Null; $results.RemovedProvisioned += $_.DisplayName } catch { $results.Errors += $_.DisplayName } }
    } catch { Write-Log "Failed removing provisioned packages: $($_.Exception.Message)" "WARNING" }
    try { $out = Join-Path $global:Dirs.Debloat 'Debloat.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Clear-TempFiles {
    Write-Log "Phase 12: Cleaning Temporary Files" "INFO"
    $results = @{
        PathsCleaned = @()
        BytesFreed = 0
        Errors = @()
    }
    $targets = @($env:TEMP, "$env:WINDIR\Temp")
    foreach ($t in $targets) {
        try {
            if (Test-Path $t) {
                $sizeBefore = (Get-ChildItem -Path $t -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                Get-ChildItem -Path $t -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                $results.PathsCleaned += $t
                $results.BytesFreed += [int64]$sizeBefore
            }
        } catch { $results.Errors += ("Failed to clean {0}: {1}" -f $t, $_.Exception.Message) }
    }
    try { $out = Join-Path $global:Dirs.TempCleanup 'TempCleanup.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Test-BrowserSecurity {
    Write-Log "Phase 13: Browser Analysis" "INFO"
    $results = @{
        Chrome = @{}
        Edge = @{}
        Firefox = @{}
    }
    try {
        $chromeExtPath = Join-Path $env:LOCALAPPDATA 'Google\\Chrome\\User Data\\Default\\Extensions'
        if (Test-Path $chromeExtPath) {
            $exts = Get-ChildItem $chromeExtPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $dir = $_
                $manifest = Get-ChildItem -Path $dir.FullName -Recurse -Filter 'manifest.json' -ErrorAction SilentlyContinue | Sort-Object -Property FullName -Descending | Select-Object -First 1
                if ($manifest) {
                    try {
                        $mj = Get-Content $manifest.FullName -Raw | ConvertFrom-Json
                        [PSCustomObject]@{ name = $mj.name; version = $mj.version; description = $mj.description }
                    } catch {
                        [PSCustomObject]@{ name = $dir.Name; version = 'unknown'; description = $null }
                    }
                } else {
                    [PSCustomObject]@{ name = $dir.Name; version = 'unknown'; description = $null }
                }
            }
            $results.Chrome = @{ ExtensionCount = ($exts | Measure-Object).Count; Extensions = $exts }
        }
    } catch { Write-Log "Chrome analysis failed: $($_.Exception.Message)" "WARNING" }
    try {
        $edgeExtPath = Join-Path $env:LOCALAPPDATA 'Microsoft\\Edge\\User Data\\Default\\Extensions'
        if (Test-Path $edgeExtPath) {
            $exts = Get-ChildItem $edgeExtPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $dir = $_
                $manifest = Get-ChildItem -Path $dir.FullName -Recurse -Filter 'manifest.json' -ErrorAction SilentlyContinue | Sort-Object -Property FullName -Descending | Select-Object -First 1
                if ($manifest) {
                    try {
                        $mj = Get-Content $manifest.FullName -Raw | ConvertFrom-Json
                        [PSCustomObject]@{ name = $mj.name; version = $mj.version; description = $mj.description }
                    } catch {
                        [PSCustomObject]@{ name = $dir.Name; version = 'unknown'; description = $null }
                    }
                } else {
                    [PSCustomObject]@{ name = $dir.Name; version = 'unknown'; description = $null }
                }
            }
            $results.Edge = @{ ExtensionCount = ($exts | Measure-Object).Count; Extensions = $exts }
        }
    } catch { Write-Log "Edge analysis failed: $($_.Exception.Message)" "WARNING" }
    try {
        $ffProfiles = Join-Path $env:APPDATA 'Mozilla\\Firefox\\Profiles'
        if (Test-Path $ffProfiles) {
            $exts = Get-ChildItem $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $addons = Join-Path $_.FullName 'extensions.json'
                if (Test-Path $addons) { try { (Get-Content $addons -Raw | ConvertFrom-Json).addons | Select-Object -Property defaultLocale,version -ErrorAction SilentlyContinue } catch { $null } }
            } | Where-Object { $_ }
            $results.Firefox = @{ ExtensionCount = ($exts | Measure-Object).Count; Extensions = $exts }
        }
    } catch { Write-Log "Firefox analysis failed: $($_.Exception.Message)" "WARNING" }
    try { $out = Join-Path $global:Dirs.Browser 'BrowserAnalysis.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Test-PowerShellScripts {
    Write-Log "Phase 14: PowerShell Script Analysis" "INFO"
    $results = @{
        Scanned = 0
        Suspicious = @()
    }
    $paths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Documents",
        "$env:ProgramData",
        "$env:WINDIR\System32\WindowsPowerShell\v1.0\Modules"
    )
    $patterns = @('FromBase64String','Invoke-Expression','IEX','DownloadString','Net\.WebClient','Add-MpPreference','Write-Host\s+-NoNewline')
    foreach ($p in $paths) {
        try {
            if (Test-Path $p) {
                Get-ChildItem -Path $p -Recurse -Include '*.ps1','*.psm1' -ErrorAction SilentlyContinue | ForEach-Object {
                    $results.Scanned++
                    $content = ''
                    try { $content = Get-Content -Path $_.FullName -Raw -ErrorAction SilentlyContinue } catch {}
                    foreach ($pat in $patterns) {
                        if ($content -match $pat) {
                            $entry = @{ Path = $_.FullName; Pattern = $pat; Hash = (Get-FileHashSafe -Path $_.FullName) }
                            $results.Suspicious += $entry
                            $null = Add-Threat -Category "PowerShell" -Name "Suspicious Script" -Path $_.FullName -Description "Matched pattern '$pat'" -Severity "Medium" -RemediationAction "Review script"
                            break
                        }
                    }
                }
            }
        } catch { Write-Log ("Failed to scan {0}: {1}" -f $p, $_.Exception.Message) "WARNING" }
    }
    try { $out = Join-Path $global:Dirs.PowerShell 'PowerShellAnalysis.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Test-CredentialSecurity {
    Write-Log "Phase 15: Credential Security" "INFO"
    $results = @{
        WDigest = @{}
        LSAPPL = @{}
        CachedLogons = @{}
        RDP = @{}
    }
    try {
        $wdKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
        $useCred = (Get-ItemProperty -Path $wdKey -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential
        $results.WDigest = @{ UseLogonCredential = $useCred }
        if ($useCred -eq 1) { $null = Add-Threat -Category 'Credentials' -Name 'WDigest Enabled' -Path $wdKey -Description 'WDigest UseLogonCredential=1 allows plaintext password in memory' -Severity 'High' -RemediationAction 'Set UseLogonCredential=0' }
    } catch {}
    try {
        $lsappKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $runAsPpl = (Get-ItemProperty -Path $lsappKey -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
        $results.LSAPPL = @{ RunAsPPL = $runAsPpl }
        if ($runAsPpl -ne 1) { $null = Add-Threat -Category 'Credentials' -Name 'LSA Protection Disabled' -Path $lsappKey -Description 'LSA not running as a protected process' -Severity 'High' -RemediationAction 'Set RunAsPPL=1 (reboot required)' }
    } catch {}
    try {
        $polKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $cached = (Get-ItemProperty -Path $polKey -Name 'CachedLogonsCount' -ErrorAction SilentlyContinue).CachedLogonsCount
        $results.CachedLogons = @{ CachedLogonsCount = $cached }
    } catch {}
    try {
        $rdpKey = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $nla = (Get-ItemProperty -Path $rdpKey -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
        $results.RDP = @{ NLA = ($nla -eq 1) }
    } catch {}
    try { $out = Join-Path $global:Dirs.Credentials 'CredentialSecurity.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Set-SystemHardening {
    Write-Log "Phase 16: Applying System Hardening (conservative)" "INFO"
    $changes = @()
    try { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0; $changes += 'LLMNR Disabled' } catch {}
    try {
        Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object { try { $_.SetTcpipNetbios(2) | Out-Null } catch {} }
        $changes += 'NetBIOS Disabled'
    } catch {}
    try { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null; $changes += 'SMBv1 Disabled' } catch {}
    try { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Type DWord -Value 0 -ErrorAction SilentlyContinue; $changes += 'WDigest Disabled' } catch {}
    try { New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Type DWord -Value 1 -ErrorAction SilentlyContinue; $changes += 'LSA PPL Enabled' } catch {}
    try { $rdp = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Set-ItemProperty -Path $rdp -Name 'UserAuthentication' -Type DWord -Value 1 -ErrorAction SilentlyContinue; $changes += 'RDP NLA Enabled' } catch {}
    $results = @{ Changes = $changes }
    try { $out = Join-Path $global:Dirs.Hardening 'Hardening.json'; $results | ConvertTo-Json -Depth 5 | Out-File $out -Force } catch {}
    return $results
}

function Test-WMIPersistence {
    Write-Log "Phase 17: WMI Persistence" "INFO"
    $results = @{
        EventFilters = @()
        Consumers = @()
        Bindings = @()
        Suspicious = @()
    }
    try {
        $ns = 'root\\subscription'
        $filters = Get-WmiObject -Namespace $ns -Class __EventFilter -ErrorAction SilentlyContinue
        $consumers = Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
        $bindings = Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        $results.EventFilters = $filters | ForEach-Object { @{ Name = $_.Name; Query = $_.Query; CreatorSID = $_.CreatorSID } }
        $results.Consumers = $consumers | ForEach-Object { @{ Name = $_.Name; CommandLineTemplate = $_.CommandLineTemplate } }
        $results.Bindings = $bindings | ForEach-Object { @{ Filter = $_.Filter; Consumer = $_.Consumer } }
        foreach ($c in $consumers) { if ($c.CommandLineTemplate -match 'powershell|cmd\.exe|wscript|mshta|http') { $results.Suspicious += @{ Name = $c.Name; Command = $c.CommandLineTemplate }; $null = Add-Threat -Category 'WMI' -Name 'Suspicious WMI Consumer' -Path $c.__PATH -Description ($c.CommandLineTemplate) -Severity 'High' -RemediationAction 'Remove malicious consumer' } }
    } catch { Write-Log "Failed to query WMI persistence: $($_.Exception.Message)" "ERROR" }
    try { $out = Join-Path $global:Dirs.WMI 'WMIAnalysis.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Test-SupplyChainSecurity {
    Write-Log "Phase 18: Supply Chain Security" "INFO"
    $results = @{
        UnsignedInProgramFiles = @()
        InsecurePathDirs = @()
    }
    try {
        $programDirs = @("$env:ProgramFiles","$env:ProgramFiles(x86)") | Where-Object { $_ }
        foreach ($dir in $programDirs) {
            if (Test-Path $dir) {
                Get-ChildItem -Path $dir -Recurse -Include '*.exe','*.dll' -ErrorAction SilentlyContinue | Select-Object -First 500 | ForEach-Object {
                    try { $sig = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue; if (-not $sig -or $sig.Status -ne 'Valid') { $results.UnsignedInProgramFiles += $_.FullName } } catch {}
                }
            }
        }
    } catch { Write-Log "Supply chain binary signature scan failed: $($_.Exception.Message)" "WARNING" }
    try {
        $pathDirs = ($env:PATH -split ';') | Where-Object { $_ }
        foreach ($p in $pathDirs) {
            try {
                if (Test-Path $p) {
                    $acl = Get-Acl -Path $p -ErrorAction SilentlyContinue
                    $worldWritable = $false
                    foreach ($ace in $acl.Access) { if ($ace.IdentityReference -match 'Everyone|Users|Authenticated Users' -and $ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl' -and $ace.AccessControlType -eq 'Allow') { $worldWritable = $true; break } }
                    if ($worldWritable) { $results.InsecurePathDirs += $p; $null = Add-Threat -Category 'SupplyChain' -Name 'Insecure PATH directory' -Path $p -Description 'Directory in PATH is writable by non-admin users' -Severity 'High' -RemediationAction 'Harden ACLs or remove from PATH' }
                }
            } catch {}
        }
    } catch { Write-Log "PATH ACL scan failed: $($_.Exception.Message)" "WARNING" }
    try { $out = Join-Path $global:Dirs.SupplyChain 'SupplyChain.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Invoke-VerificationPass {
    Write-Log "Final Verification Pass" "INFO"
    $results = @{
        RequiredDirsPresent = @{}
        ThreatsCount = $global:ThreatsFound.Count
        RemediationsApplied = $global:RemediationsApplied.Count
        RemediationsFailed = $global:RemediationsFailed.Count
    }
    foreach ($k in $global:Dirs.Keys) { $dir = $global:Dirs[$k]; $results.RequiredDirsPresent[$k] = (Test-Path $dir) }
    try { $out = Join-Path $global:Dirs.Verification 'Verification.json'; $results | ConvertTo-Json -Depth 10 | Out-File $out -Force } catch {}
    return $results
}

function Set-ScheduledScan {
    Write-Log "Creating Scheduled Scan Task" "INFO"
    try {
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Path }
        if (-not $scriptPath) { Write-Log 'Cannot determine script path for scheduling.' 'ERROR'; return }
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Full -Silent"
        $trigger = New-ScheduledTaskTrigger -Daily -At 2am
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable)
        Register-ScheduledTask -TaskName 'DeepScan_Enhanced' -InputObject $task -Force | Out-Null
        Write-Log "Scheduled task 'DeepScan_Enhanced' created." "SUCCESS"
    } catch { Write-Log "Failed to create scheduled task: $($_.Exception.Message)" "ERROR" }
}

function Send-EmailReport {
    param(
        [Parameter(Mandatory=$true)][string]$EmailAddress
    )
    Write-Log "Preparing to send email report to $EmailAddress" "INFO"
    $smtpServer = $env:DEEPSCAN_SMTP_SERVER
    $smtpPort = if ($env:DEEPSCAN_SMTP_PORT) { [int]$env:DEEPSCAN_SMTP_PORT } else { 587 }
    $smtpUser = $env:DEEPSCAN_SMTP_USER
    $smtpPass = $env:DEEPSCAN_SMTP_PASS
    $html = Join-Path $global:OutDir 'ThreatAnalysis.html'
    if (-not (Test-Path $html)) { Write-Log 'HTML report not found; cannot email.' 'WARNING'; return }
    if (-not $smtpServer -or -not $smtpUser -or -not $smtpPass) { Write-Log 'SMTP settings not provided via environment variables; skipping email.' 'WARNING'; return }
    try {
        $securePass = ConvertTo-SecureString -String $smtpPass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($smtpUser,$securePass)
        Send-MailMessage -To $EmailAddress -From $smtpUser -Subject 'DeepScan Report' -Body (Get-Content $html -Raw) -BodyAsHtml -SmtpServer $smtpServer -Port $smtpPort -UseSsl -Credential $cred -Attachments $html -ErrorAction Stop
        Write-Log "Email sent to $EmailAddress" "SUCCESS"
    } catch { Write-Log "Failed to send email: $($_.Exception.Message)" "ERROR" }
}

function Invoke-Cleanup {
    Write-Log "Cleanup tasks" "INFO"
    try { Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue } catch {}
}

function New-HTMLReport {
    param([Parameter(Mandatory=$true)][hashtable]$AllResults)
    try {
        $htmlPath = Join-Path $global:OutDir 'ThreatAnalysis.html'
        $threats = $global:ThreatsFound | Select-Object Category,Name,Severity,Path,Description,DetectionTime
        $remediations = $global:RemediationsApplied | Select-Object Category,Name,Success,Time,ErrorMessage
        $summary = [PSCustomObject]@{
            StartTime = $AllResults.StartTime
            EndTime = Get-Date
            DurationHours = [math]::Round($AllResults.ScanDuration,2)
            Threats = $AllResults.ThreatCount
            RemediationsApplied = $global:RemediationsApplied.Count
            RemediationsFailed = $global:RemediationsFailed.Count
            OutputDir = $global:OutDir
        }
        $style = '<style>body{font-family:Segoe UI,Tahoma,Arial;font-size:12px} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px} th{background:#f4f4f4} h1{color:#2c7} .sev-High{color:#c00} .sev-Critical{color:#900}</style>'
        $html = "<html><head>$style<title>DeepScan Report</title></head><body><h1>DeepScan Enhanced Security Toolkit Report</h1>"
        $html += ($summary | ConvertTo-Html -Fragment -PreContent '<h2>Summary</h2>')
        $html += ($threats | ConvertTo-Html -Fragment -PreContent '<h2>Threats Found</h2>')
        $html += ($remediations | ConvertTo-Html -Fragment -PreContent '<h2>Remediations</h2>')
        $html += '</body></html>'
        $html | Out-File $htmlPath -Force -Encoding utf8
        Write-Log "HTML report saved to $htmlPath" "SUCCESS"
    } catch { Write-Log "Failed to generate HTML report: $($_.Exception.Message)" "ERROR" }
}

function New-PDFReport {
    param([Parameter(Mandatory=$true)][hashtable]$AllResults)
    try {
        $htmlPath = Join-Path $global:OutDir 'ThreatAnalysis.html'
        if (-not (Test-Path $htmlPath)) { New-HTMLReport -AllResults $AllResults }
        $pdfPath = Join-Path $global:OutDir 'ThreatAnalysis.pdf'
        $edgePaths = @(
            'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
            'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
        )
        $edge = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($edge) {
            $edgeArgs = "--headless --disable-gpu --print-to-pdf=`"$pdfPath`" `"$htmlPath`""
            Start-Process -FilePath $edge -ArgumentList $edgeArgs -Wait -NoNewWindow
            if (Test-Path $pdfPath) { Write-Log "PDF report saved to $pdfPath" "SUCCESS" } else { Write-Log "Edge headless print did not produce PDF." "WARNING" }
        } else {
            Write-Log "Microsoft Edge not found for PDF export. Skipping PDF generation." "WARNING"
        }
    } catch { Write-Log "Failed to generate PDF report: $($_.Exception.Message)" "ERROR" }
}

# ==================== MAIN EXECUTION ====================
$separator = "-" * 80

Write-Host ""
Write-Host $separator -ForegroundColor Cyan
Write-Host "           DEEPSCAN ENHANCED SECURITY TOOLKIT v4.1" -ForegroundColor Green
Write-Host $separator -ForegroundColor Cyan
Write-Host ""

$global:AllResults = @{
    StartTime = Get-Date
    Threats = @()
    ThreatCount = 0
    ProcessCount = 0
    ServicesCount = 0
    ScanDuration = 0
}

Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Initializing..." -PercentComplete 0

# Phase 1: System Inventory
Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Collecting System Inventory..." -PercentComplete 5
$inventory = Get-SystemInventory
$global:AllResults.ProcessCount = $inventory.Processes.Count
$global:AllResults.ServicesCount = $inventory.Services.Count

# Phase 2: Network Analysis
if (-not $SkipNetwork) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Analyzing Network Security..." -PercentComplete 10
    $networkResults = Test-NetworkSecurity
} else {
    Write-Log "Skipping network analysis as requested" "WARNING"
}

# Phase 3: Windows Defender
if (-not $SkipDefender) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Scanning with Windows Defender..." -PercentComplete 15
    $defenderResults = Invoke-DefenderScan
} else {
    Write-Log "Skipping Windows Defender analysis as requested" "WARNING"
}

# Phase 4: Memory Analysis
if (-not $SkipMemory) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Analyzing Memory..." -PercentComplete 20
    Get-MemoryAnalysis
} else {
    Write-Log "Skipping memory analysis as requested" "WARNING"
}

# Phase 5: Registry Analysis
if (-not $SkipRegistry) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Analyzing Registry..." -PercentComplete 25
    Test-RegistryPersistence
} else {
    Write-Log "Skipping registry analysis as requested" "WARNING"
}

# Phase 6: File System
if (-not $SkipFileSystem) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Checking File System..." -PercentComplete 30
    Test-FileSystemThreats
} else {
    Write-Log "Skipping file system analysis as requested" "WARNING"
}

# Phase 7: Third-Party AV
if (-not $SkipAVScans) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Running Third-Party AV Scanners..." -PercentComplete 35
    Invoke-ThirdPartyAV
} else {
    Write-Log "Skipping third-party AV scans as requested" "WARNING"
}

# Phase 8: Rootkit Detection
if (-not $SkipRootkit) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Detecting Rootkits..." -PercentComplete 40
    Invoke-RootkitDetection
} else {
    Write-Log "Skipping rootkit detection as requested" "WARNING"
}

# Phase 9: System Repairs
if ($RepairSystem) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Checking System Integrity..." -PercentComplete 45
    Test-SystemIntegrity
} else {
    Write-Log "Skipping system repairs as requested" "INFO"
}

# Phase 10: Windows Updates
if ($UpdateWindows) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Checking Windows Updates..." -PercentComplete 50
    Invoke-WindowsUpdate
} else {
    Write-Log "Skipping Windows updates as requested" "INFO"
}

# Phase 11: Debloating
if ($Debloat) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Removing Bloatware..." -PercentComplete 55
    Remove-WindowsBloatware
} else {
    Write-Log "Skipping Windows debloating as requested" "INFO"
}

# Phase 12: Cleanup
if ($CleanTemp) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Cleaning Temporary Files..." -PercentComplete 60
    Clear-TempFiles
} else {
    Write-Log "Skipping temporary file cleanup as requested" "INFO"
}

# Phase 13: Browser Analysis
if (-not $SkipBrowser) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Analyzing Browser Security..." -PercentComplete 65
    Test-BrowserSecurity
} else {
    Write-Log "Skipping browser analysis as requested" "WARNING"
}

# Phase 14: PowerShell Script Analysis
if (-not $SkipPowerShell) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Analyzing PowerShell Scripts..." -PercentComplete 70
    Test-PowerShellScripts
} else {
    Write-Log "Skipping PowerShell script analysis as requested" "WARNING"
}

# Phase 15: Credential Security
if (-not $SkipCredentials) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Checking Credential Security..." -PercentComplete 75
    Test-CredentialSecurity
} else {
    Write-Log "Skipping credential security checks as requested" "WARNING"
}

# Phase 16: System Hardening
if ($AutoHarden) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Applying System Hardening..." -PercentComplete 80
    Set-SystemHardening
} else {
    Write-Log "Skipping automatic system hardening as requested" "INFO"
}

# Phase 17: WMI Persistence
if (-not $SkipWMI) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Checking WMI Persistence..." -PercentComplete 85
    Test-WMIPersistence
} else {
    Write-Log "Skipping WMI persistence checks as requested" "WARNING"
}

# Phase 18: Supply Chain Security
if (-not $SkipSupplyChain) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Checking Supply Chain Security..." -PercentComplete 87
    Test-SupplyChainSecurity
} else {
    Write-Log "Skipping supply chain security checks as requested" "WARNING"
}

# Final Verification
Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Running Final Verification..." -PercentComplete 90
Invoke-VerificationPass

# Schedule scan if requested
if ($ScheduleScan) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Setting Scheduled Scan..." -PercentComplete 92
    Set-ScheduledScan
} else {
    Write-Log "Skipping scheduled scan setup as requested" "INFO"
}

# Send email report if requested
if ($EmailReport) {
    Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Preparing Email Report..." -PercentComplete 94
    Send-EmailReport -EmailAddress $EmailReport
} else {
    Write-Log "Skipping email report as no address was provided" "INFO"
}

# Cleanup
Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Cleaning Up..." -PercentComplete 96
Invoke-Cleanup

# Calculate scan duration
$global:AllResults.EndTime = Get-Date
$global:AllResults.ScanDuration = ($global:AllResults.EndTime - $global:AllResults.StartTime).TotalHours
$global:AllResults.ThreatCount = $global:ThreatsFound.Count

Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Generating Reports..." -PercentComplete 98

# Generate reports based on requested format
switch ($ExportFormat) {
    "HTML" { New-HTMLReport -AllResults $global:AllResults }
    "PDF" { New-PDFReport -AllResults $global:AllResults }
    "JSON" { 
        $jsonReport = Join-Path $global:OutDir "ThreatAnalysis.json"
        $global:AllResults | ConvertTo-Json -Depth 10 | Out-File $jsonReport
    }
    "CSV" {
        $csvReport = Join-Path $global:OutDir "ThreatAnalysis.csv"
        $global:ThreatsFound | Export-Csv $csvReport -NoTypeInformation
    }
    "All" {
        New-HTMLReport -AllResults $global:AllResults
        New-PDFReport -AllResults $global:AllResults
        $jsonReport = Join-Path $global:OutDir "ThreatAnalysis.json"
        $global:AllResults | ConvertTo-Json -Depth 10 | Out-File $jsonReport
        $csvReport = Join-Path $global:OutDir "ThreatAnalysis.csv"
        $global:ThreatsFound | Export-Csv $csvReport -NoTypeInformation
    }
}

# Save final summary
try {
    $summaryFile = Join-Path $global:OutDir "ScanSummary.json"
    $global:AllResults | ConvertTo-Json -Depth 10 | Out-File $summaryFile
    Write-Log "Scan summary saved to $summaryFile" "SUCCESS"
} catch {
    Write-Log "Failed to save scan summary: $($_.Exception.Message)" "ERROR"
}

Show-Progress -Activity "DeepScan Enhanced Security Toolkit" -Status "Complete" -PercentComplete 100

# Display results
Write-Host ""
Write-Host $separator -ForegroundColor Cyan
Write-Host "                    SCAN COMPLETE" -ForegroundColor Green
Write-Host $separator -ForegroundColor Cyan
Write-Host ""
Write-Host "Scan Duration: $([math]::Round($global:AllResults.ScanDuration, 2)) hours" -ForegroundColor Cyan
Write-Host "Threats Found: $($global:AllResults.ThreatCount)" -ForegroundColor $(if ($global:AllResults.ThreatCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "Remediations Applied: $($global:RemediationsApplied.Count)" -ForegroundColor $(if ($global:RemediationsApplied.Count -gt 0) { "Green" } else { "Gray" })
Write-Host "Remediations Failed: $($global:RemediationsFailed.Count)" -ForegroundColor $(if ($global:RemediationsFailed.Count -gt 0) { "Red" } else { "Gray" })
Write-Host ""
Write-Host "Report Location: $global:OutDir" -ForegroundColor Cyan
Write-Host ""
Write-Host $separator -ForegroundColor Cyan
Write-Host "               REPORT SUMMARY" -ForegroundColor Green
Write-Host $separator -ForegroundColor Cyan
Write-Host ""
Write-Host ("HTML Report: {0}" -f (Join-Path $global:OutDir 'ThreatAnalysis.html')) -ForegroundColor Cyan
Write-Host ("PDF Report: {0}" -f (Join-Path $global:OutDir 'ThreatAnalysis.pdf')) -ForegroundColor Cyan
Write-Host ("JSON Report: {0}" -f (Join-Path $global:OutDir 'ThreatAnalysis.json')) -ForegroundColor Cyan
Write-Host ("CSV Report: {0}" -f (Join-Path $global:OutDir 'ThreatAnalysis.csv')) -ForegroundColor Cyan
