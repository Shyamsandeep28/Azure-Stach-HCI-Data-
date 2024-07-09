# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (-not $isAdmin) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1

    if($PSVersionTable.PSEdition -eq "Core") {

        Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    } else {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    }

    exit
}

#region Functions
#region Output logging
function WriteInfo($message) {
    Write-Host $message
}

function WriteInfoHighlighted($message) {
    Write-Host $message -ForegroundColor Cyan
}

function WriteSuccess($message) {
    Write-Host $message -ForegroundColor Green
}

function WriteError($message) {
    Write-Host $message -ForegroundColor Red
}

function WriteErrorAndExit($message) {
    Write-Host $message -ForegroundColor Red
    Write-Host "Press enter to continue ..."
    Stop-Transcript
    Read-Host | Out-Null
    Exit
}
#endregion

#region Telemetry
Function Merge-Hashtables {
    $Output = @{}
    ForEach ($Hashtable in ($Input + $Args)) {
        If ($Hashtable -is [Hashtable]) {
            ForEach ($Key in $Hashtable.Keys) {$Output.$Key = $Hashtable.$Key}
        }
    }
    $Output
}
function Get-StringHash {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline, Mandatory = $true)]
        [string]$String,
        $Hash = "SHA1"
    )
    
    process {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
        $algorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Hash)
        $StringBuilder = New-Object System.Text.StringBuilder 
      
        $algorithm.ComputeHash($bytes) | 
        ForEach-Object { 
            $null = $StringBuilder.Append($_.ToString("x2")) 
        } 
      
        $StringBuilder.ToString() 
    }
}

function Get-VolumePhysicalDisk {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume
    )

    process {
        if(-not $Volume.EndsWith(":")) {
            $Volume += ":"
        }

        $physicalDisks = Get-cimInstance "win32_diskdrive"
        foreach($disk in $physicalDisks) {
            $partitions = Get-cimInstance -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($disk.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"
            foreach($partition in $partitions) {
                $partitionVolumes = Get-cimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($partition.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"
                foreach($partitionVolume in $partitionVolumes) {
                    if($partitionVolume.Name -eq $Volume) {
                        $physicalDisk = Get-PhysicalDisk | Where-Object DeviceID -eq $disk.Index
                        return $physicalDisk
                    }
                }
            }
        }
    }
}

function Get-TelemetryLevel {
    param(
        [switch]$OptOut
    )
    process {
        $acceptedTelemetryLevels = "None", "Basic", "Full"

        # LabConfig value has a priority
        if($LabConfig.TelemetryLevel -and $LabConfig.TelemetryLevel -in $acceptedTelemetryLevels) {
            return $LabConfig.TelemetryLevel
        }

        # Environment variable as a fallback
        if($env:MSLAB_TELEMETRY_LEVEL -and $env:MSLAB_TELEMETRY_LEVEL -in $acceptedTelemetryLevels) {
            return $env:MSLAB_TELEMETRY_LEVEL
        }

        # If nothing is explicitely configured and OptOut flag enabled, explicitely disable telemetry
        if($OptOut) {
            return "None"
        }

        # as a last option return nothing to allow asking the user
    }
}

function Get-TelemetryLevelSource {
    param(
        [switch]$OptOut
    )
    process {
        $acceptedTelemetryLevels = "None", "Basic", "Full"

        # Is it set interactively?
        if($LabConfig.ContainsKey("TelemetryLevelSource")) {
            return $LabConfig.TelemetryLevelSource
        }

        # LabConfig value has a priority
        if($LabConfig.TelemetryLevel -and $LabConfig.TelemetryLevel -in $acceptedTelemetryLevels) {
            return "LabConfig"
        }

        # Environment variable as a fallback
        if($env:MSLAB_TELEMETRY_LEVEL -and $env:MSLAB_TELEMETRY_LEVEL -in $acceptedTelemetryLevels) {
            return "Environment"
        }
    }
}

function Get-PcSystemType {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Id
    )
    process {
        $type = switch($Id) {
            1 { "Desktop" }
            2 { "Laptop" }
            3 { "Workstation" }
            4 { "Server" }
            7 { "Server" }
            5 { "Server" }
            default { $Id }
        }

        $type
    }
}

$aiPropertyCache = @{}

function Initialize-TelemetryEvent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Event,
        $Properties,
        $Metrics,
        $NickName
    )

    process {
        if(-not $TelemetryInstrumentationKey) {
            WriteInfo "Instrumentation key is required to send telemetry data."
            return
        }
        
        $level = Get-TelemetryLevel
        $levelSource = Get-TelemetryLevelSource

        $r = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $build = "$($r.CurrentMajorVersionNumber).$($r.CurrentMinorVersionNumber).$($r.CurrentBuildNumber).$($r.UBR)"
        $osVersion = "$($r.ProductName) ($build)"
        $hw = Get-CimInstance -ClassName Win32_ComputerSystem
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $machineHash = (((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid) | Get-StringHash)

        if(-not $NickName) {
            $NickName = "?"
        }

        $osType = switch ($os.ProductType) {
            1 { "Workstation" }
            default { "Server" }
        }

        $extraMetrics = @{}
        $extraProperties = @{
            'telemetry.level' = $level
            'telemetry.levelSource' = $levelSource
            'telemetry.nick' = $NickName
            'powershell.edition' = $PSVersionTable.PSEdition
            'powershell.version' = $PSVersionTable.PSVersion.ToString()
            'host.isAzure' = (Get-CimInstance win32_systemenclosure).SMBIOSAssetTag -eq "7783-7084-3265-9085-8269-3286-77"
            'host.os.type' = $osType
            'host.os.build' = $r.CurrentBuildNumber
            'hw.type' = Get-PcSystemType -Id $hw.PCSystemType
        }
        if($level -eq "Full") {
            # OS
            $extraProperties.'device.locale' = (Get-WinsystemLocale).Name

            # RAM
            $extraMetrics.'memory.total' = [Math]::Round(($hw.TotalPhysicalMemory)/1024KB, 0)
            
            # CPU
            $extraMetrics.'cpu.logical.count' = $hw.NumberOfLogicalProcessors
            $extraMetrics.'cpu.sockets.count' = $hw.NumberOfProcessors

            if(-not $aiPropertyCache.ContainsKey("cpu.model")) {
                $aiPropertyCache["cpu.model"] = (Get-CimInstance "Win32_Processor" | Select-Object -First 1).Name
            }
            $extraProperties.'cpu.model' = $aiPropertyCache["cpu.model"]

            # Disk
            $driveLetter = $ScriptRoot -Split ":" | Select-Object -First 1
            $volume = Get-Volume -DriveLetter $driveLetter
            $disk = Get-VolumePhysicalDisk -Volume $driveLetter
            $extraMetrics.'volume.size' = [Math]::Round($volume.Size / 1024MB)
            $extraProperties.'volume.fs' = $volume.FileSystemType
            $extraProperties.'disk.type' = $disk.MediaType
            $extraProperties.'disk.busType' = $disk.BusType
        }

        $payload = @{
            name = "Microsoft.ApplicationInsights.Event"
            time = $([System.dateTime]::UtcNow.ToString("o")) 
            iKey = $TelemetryInstrumentationKey
            tags = @{ 
                "ai.internal.sdkVersion" = 'mslab-telemetry:1.0.2'
                "ai.application.ver" = $mslabVersion
                "ai.cloud.role" = Split-Path -Path $PSCommandPath -Leaf
                "ai.session.id" = $TelemetrySessionId
                "ai.user.id" = $machineHash
                "ai.device.id" = $machineHash
                "ai.device.type" = $extraProperties["hw.type"]
                "ai.device.locale" = "" # not propagated anymore
                "ai.device.os" = ""
                "ai.device.osVersion" = ""
                "ai.device.oemName" = ""
                "ai.device.model" = ""
            }
            data = @{
                baseType = "EventData"
                baseData = @{
                    ver = 2 
                    name = $Event
                    properties = ($Properties, $extraProperties | Merge-Hashtables)
                    measurements = ($Metrics, $extraMetrics | Merge-Hashtables)
                }
            }
        }

        if($level -eq "Full") {
            $payload.tags.'ai.device.os' = $osVersion
            $payload.tags.'ai.device.osVersion' = $build
        }
    
        $payload
    }
}

function Send-TelemetryObject {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data
    )

    process {
        $json = "{0}" -f (($Data) | ConvertTo-Json -Depth 10 -Compress)

        if($LabConfig.ContainsKey('TelemetryDebugLog')) {
            Add-Content -Path "$ScriptRoot\Telemetry.log" -Value ((Get-Date -Format "s") + "`n" + $json)
        }

        try {
            $response = Invoke-RestMethod -Uri 'https://dc.services.visualstudio.com/v2/track' -Method Post -UseBasicParsing -Body $json -TimeoutSec 20
        } catch { 
            WriteInfo "`tSending telemetry failed with an error: $($_.Exception.Message)"
            $response = $_.Exception.Message
        }

        if($LabConfig.ContainsKey('TelemetryDebugLog')) {
            Add-Content -Path "$ScriptRoot\Telemetry.log" -Value $response
            Add-Content -Path "$ScriptRoot\Telemetry.log" -Value "`n------------------------------`n"
        }
    }
}

function Send-TelemetryEvent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Event,

        $Properties,
        $Metrics,
        $NickName
    )

    process {
        $telemetryEvent = Initialize-TelemetryEvent -Event $Event -Properties $Properties -Metrics $Metrics -NickName $NickName
        Send-TelemetryObject -Data $telemetryEvent
    }
}

function Send-TelemetryEvents {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events
    )

    process {
        Send-TelemetryObject -Data $Events
    }
}

function Read-TelemetryLevel {
    process {
        # Ask user for consent
        WriteInfoHighlighted "`nLab telemetry"
        WriteInfo "By providing a telemetry information you will help us to improve MSLab scripts. There are two levels of a telemetry information and we are not collecting any personally identifiable information (PII)."
        WriteInfo "Details about telemetry levels and the content of telemetry messages can be found in documentation https://aka.ms/mslab/telemetry"
        WriteInfo "Available telemetry levels are:"
        WriteInfo " * None  -- No information will be sent"
        WriteInfo " * Basic -- Information about lab will be sent (e.g. script execution time, number of VMs, guest OSes)"
        WriteInfo " * Full  -- Information about lab and the host machine (e.g. type of disk)"
        WriteInfo "Would you be OK with providing an information about your MSLab usage?"
        WriteInfo "`nTip: You can also configure telemetry settings explicitly in LabConfig.ps1 file or by setting an environmental variable and suppress this prompt."

        $options = [System.Management.Automation.Host.ChoiceDescription[]] @(
          <# 0 #> New-Object System.Management.Automation.Host.ChoiceDescription "&None", "No information will be sent"
          <# 1 #> New-Object System.Management.Automation.Host.ChoiceDescription "&Basic", "Lab info will be sent (e.g. script execution time, number of VMs)"
          <# 2 #> New-Object System.Management.Automation.Host.ChoiceDescription "&Full", "More details about the host machine and deployed VMs (e.g. guest OS)"
        )
        $response = $host.UI.PromptForChoice("MSLab telemetry level", "Please choose a telemetry level for this MSLab instance. For more details please see MSLab documentation.", $options, 1 <#default option#>)

        $telemetryLevel = $null
        switch($response) {
            0 {
                $telemetryLevel = 'None'
                WriteInfo "`nNo telemetry information will be sent."
            }
            1 {
                $telemetryLevel = 'Basic'
                WriteInfo "`nTelemetry has been set to Basic level, thank you for your valuable feedback."
            }
            2 {
                $telemetryLevel = 'Full'
                WriteInfo "`nTelemetry has been set to Full level, thank you for your valuable feedback."
            }
        }

        $telemetryLevel
    }
}

# Instance values
$ScriptRoot = $PSScriptRoot
$mslabVersion = "v24.06.2"
$TelemetryEnabledLevels = "Basic", "Full"
$TelemetryInstrumentationKey = "9ebf64de-01f8-4f60-9942-079262e3f6e0"
$TelemetrySessionId = $ScriptRoot + $env:COMPUTERNAME + ((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid) | Get-StringHash
#endregion

    #Create Unattend for VHD
    Function CreateUnattendFileVHD {
        param (
            [parameter(Mandatory=$true)]
            [string]
            $Computername,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $Path,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone
        )

        if ( Test-Path "$path\Unattend.xml" ) {
            Remove-Item "$Path\Unattend.xml"
        }
        $unattendFile = New-Item "$Path\Unattend.xml" -type File

        $fileContent =  @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <settings pass="offlineServicing">
   <component
        xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        language="neutral"
        name="Microsoft-Windows-PartitionManager"
        processorArchitecture="amd64"
        publicKeyToken="31bf3856ad364e35"
        versionScope="nonSxS"
        >
      <SanPolicy>1</SanPolicy>
    </component>
 </settings>
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        $oeminformation
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>Contoso</RegisteredOrganization>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content -path $unattendFile -value $fileContent

        #return the file object
        Return $unattendFile
    }

#endregion

#region Initialization
    #Start Log
        Start-Transcript -Path "$PSScriptRoot\CreateParentDisks.log"
        $StartDateTime = Get-Date
        WriteInfo "Script started at $StartDateTime"
        WriteInfo "`nMSLab Version $mslabVersion"

    #Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

    # Telemetry
        if(-not (Get-TelemetryLevel)) {
            $telemetryLevel = Read-TelemetryLevel
            $LabConfig.TelemetryLevel = $telemetryLevel
            $LabConfig.TelemetryLevelSource = "Prompt"
            $promptShown = $true
        }

        if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
            if(-not $promptShown) {
                WriteInfo "Telemetry is set to $(Get-TelemetryLevel) level from $(Get-TelemetryLevelSource)"
            }
            Send-TelemetryEvent -Event "CreateParentDisks.Start" -NickName $LabConfig.TelemetryNickName | Out-Null
        }

    #create variables if not already in LabConfig
        If (!$LabConfig.DomainNetbiosName){
            $LabConfig.DomainNetbiosName="Corp"
        }

        If (!$LabConfig.DomainName){
            $LabConfig.DomainName="Corp.contoso.com"
        }

        If (!$LabConfig.DefaultOUName){
            $LabConfig.DefaultOUName="Workshop"
        }

        If ($LabConfig.PullServerDC -eq $null){
            $LabConfig.PullServerDC=$true
        }

        If (!$LabConfig.DHCPscope){
            $LabConfig.DHCPscope="10.0.0.0"
        }


    #create some built-in variables
        $DN=$null
        $LabConfig.DomainName.Split(".") | ForEach-Object {
            $DN+="DC=$_,"
        }
        
        $LabConfig.DN=$DN.TrimEnd(",")

        $AdminPassword=$LabConfig.AdminPassword
        $Switchname="DC_HydrationSwitch_$([guid]::NewGuid())"
        $DCName='DC'

    #Grab TimeZone
    $TimeZone = (Get-TimeZone).id

    #Grab Installation type
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType

    #DCHP scope
    $DHCPscope = $LabConfig.DHCPscope
    $ReverseDNSrecord = $DHCPscope -replace '^(\d+)\.(\d+)\.\d+\.(\d+)$','$3.$2.$1.in-addr.arpa'
    $DHCPscope = $DHCPscope.Substring(0,$DHCPscope.Length-1)

#endregion

#region Check prerequisites

    #Check if not running in root folder
    if (($PSScriptRoot).Length -eq 3) {
        WriteErrorAndExit "`t MSLab canot run in root folder. Please put MSLab scripts into a folder. Exiting"
    }

    #check Hyper-V
        WriteInfoHighlighted "Checking if Hyper-V is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V not installed. Please install hyper-v feature including Hyper-V management tools. Exiting"
        }

        WriteInfoHighlighted "Checking if Hyper-V Powershell module is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V tools are not installed. Please install Hyper-V management tools. Exiting"
        }

    #check if VMM prereqs files are present if InstallSCVMM or SCVMM prereq is requested and tools.vhdx not present
        if (-not (Get-ChildItem -Path "$PSScriptRoot\ParentDisks" -ErrorAction SilentlyContinue).name -contains "tools.vhdx"){
            if ($LabConfig.InstallSCVMM -eq "Yes"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SCVMM\setup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe","Temp\ToolsVHD\SCVMM\ADK\Installers\Windows PE x86 x64-x86_en-us.msi" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SCVMM install not found. Exitting"
                    }
                }    
            }

            if ($LabConfig.InstallSCVMM -eq "Prereqs"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe","Temp\ToolsVHD\SCVMM\ADK\Installers\Windows PE x86 x64-x86_en-us.msi" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SCVMM Prereqs install not found. Exitting"
                    }
                } 
            }
        
            if ($LabConfig.InstallSCVMM -eq "SQL"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SQL install not found. Exitting"
                    }
                }
            }    

            if ($LabConfig.InstallSCVMM -eq "ADK"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for ADK install not found. Exitting"
                    }
                }
            }
        }

    #check if parent images already exist (this is useful if you have parent disks from another lab and you want to rebuild for example scvmm)
        WriteInfoHighlighted "Testing if some parent disk already exists and can be used"
        
        #grab all files in parentdisks folder
            $ParentDisksNames=(Get-ChildItem -Path "$PSScriptRoot\ParentDisks" -ErrorAction SilentlyContinue).Name

    #check if running on Core Server and check proper values in LabConfig
        If ($WindowsInstallationType -eq "Server Core"){
            If (!$LabConfig.ServerISOFolder){
                WriteErrorAndExit "Server Core detected. Please use ServerISOFolder variable in LabConfig to specify Server iso location"
            }
        }

    #Check if at least 2GB (+200Mb just to be sure) memory is available
        WriteInfoHighlighted "Checking if at least 2GB RAM is available"
        $MemoryAvailableMB=(Get-Ciminstance Win32_OperatingSystem).FreePhysicalMemory/1KB
        if ($MemoryAvailableMB -gt (2048+200)){
            WriteSuccess "`t $("{0:n0}" -f $MemoryAvailableMB) MB RAM Available"
        }else{
            WriteErrorAndExit "`t Please make sure you have at least 2 GB available memory. Exiting"
        }

    #check if filesystem on volume is NTFS or ReFS
    WriteInfoHighlighted "Checking if volume filesystem is NTFS or ReFS"
    $driveletter=$PSScriptRoot -split ":" | Select-Object -First 1
    if ($PSScriptRoot -like "c:\ClusterStorage*"){
        WriteSuccess "`t Volume Cluster Shared Volume. Mountdir will be $env:Temp\MSLabMountdir"
        $mountdir="$env:Temp\MSLabMountdir"
        $VolumeFileSystem="CSVFS"
    }else{
        $mountdir="$PSScriptRoot\Temp\MountDir"
        $VolumeFileSystem=(Get-Volume -DriveLetter $driveletter).FileSystemType
        if ($VolumeFileSystem -match "NTFS"){
            WriteSuccess "`t Volume filesystem is $VolumeFileSystem"
        }elseif ($VolumeFileSystem -match "ReFS") {
            WriteSuccess "`t Volume filesystem is $VolumeFileSystem"
        }else {
            WriteErrorAndExit "`t Volume filesystem is $VolumeFileSystem. Must be NTFS or ReFS. Exiting"
        }
    }
#endregion

#region Ask for ISO images and Cumulative updates
    #Grab Server ISO
        if ($LabConfig.ServerISOFolder){
            $ServerISOItem = Get-ChildItem -Path $LabConfig.ServerISOFolder -Recurse -Include '*.iso' -ErrorAction SilentlyContinue
            if ($ServerISOItem.count -gt 1){
                WriteInfoHighlighted "Multiple ISO files found. Please select Server ISO one you want"
                $ServerISOItem=$ServerISOItem | Select-Object Name,FullName | Out-GridView -Title "Multiple ISO files found. Please select Server ISO you want" -OutputMode Single
            }
            if (!$ServerISOItem){
                WriteErrorAndExit  "No iso was found in $($LabConfig.ServerISOFolder) ... Exitting"
            }
            $ISOServer = Mount-DiskImage -ImagePath $ServerISOItem.FullName -PassThru
        }else{
            WriteInfoHighlighted "Please select ISO image with Windows Server 2016, 2019, 2022 or Server Insider"
            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                Title="Please select ISO image with Windows Server 2016, 2019, 2022 or Server Insider"
            }
            $openFile.Filter = "iso files (*.iso)|*.iso|All files (*.*)|*.*"
            If($openFile.ShowDialog() -eq "OK"){
                WriteInfo  "File $($openfile.FileName) selected"
            } 
            if (!$openFile.FileName){
                WriteErrorAndExit  "Iso was not selected... Exitting"
            }
            #Mount ISO
                $ISOServer = Mount-DiskImage -ImagePath $openFile.FileName -PassThru
        }
    #Grab Server Media Letter
        $ServerMediaDriveLetter = (Get-Volume -DiskImage $ISOServer).DriveLetter

    #Test if it's server media
        WriteInfoHighlighted "Testing if selected ISO is Server Media"
        $WindowsImage=Get-WindowsImage -ImagePath "$($ServerMediaDriveLetter):\sources\install.wim"
        If ($WindowsImage.ImageName[0].contains("Server")){
            WriteInfo "`t Server Edition found"
        }else{
            $ISOServer | Dismount-DiskImage
            WriteErrorAndExit "`t Selected media does not contain Windows Server. Exitting."
        }
        if ($WindowsImage.ImageName[0].contains("Server") -and $windowsimage.count -eq 2){
            WriteInfo "`t Semi-Annual Server Media detected"
            $ISOServer | Dismount-DiskImage
            WriteErrorAndExit "Please provide LTSC media. Exitting."
        }
    #Test if it's Windows Server 2016 and newer
        $BuildNumber=(Get-ItemProperty -Path "$($ServerMediaDriveLetter):\setup.exe").versioninfo.FileBuildPart
        If ($BuildNumber -lt 14393){
            $ISOServer | Dismount-DiskImage
            WriteErrorAndExit "Please provide Windows Server 2016 and newer. Exitting."
        }
    #Check ISO Language
        $imageInfo=(Get-WindowsImage -ImagePath "$($ServerMediaDriveLetter):\sources\install.wim" -Index 4)
        $OSLanguage=$imageInfo.Languages | Select-Object -First 1

#Grab packages
    #grab server packages
        if ($LabConfig.ServerISOFolder){
            if ($LabConfig.ServerMSUsFolder){
                $packages = (Get-ChildItem -Path $LabConfig.ServerMSUsFolder -Recurse -Include '*.msu' -ErrorAction SilentlyContinue | Sort-Object -Property Length).FullName
            }
        }elseif($WindowsInstallationType -eq "Server Core"){
            WriteInfoHighlighted "Server Core detected, MSU folder not specified. Skipping MSU prompt"
        }else{
            #ask for MSU patches
            WriteInfoHighlighted "Please select Windows Server Updates (*.msu). Click Cancel if you don't want any."
            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $msupackages = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                Multiselect = $true;
                Title = "Please select Windows Server Updates (*.msu). Click Cancel if you don't want any."
            }
            $msupackages.Filter = "msu files (*.msu)|*.msu|All files (*.*)|*.*"
            If($msupackages.ShowDialog() -eq "OK"){
                WriteInfoHighlighted  "Following patches selected:"
                WriteInfo "`t $($msupackages.filenames)"
            }
            $files=@()
            foreach ($Filename in $msupackages.filenames){$files+=Get-ChildItem -Path $filename}
            #sort by size (to apply Servicing Stack Update first)
            $packages=($files |Sort-Object -Property Length).Fullname
        }

#endregion

#region Generate VHD Config
    $ServerVHDs=@()

    if ($BuildNumber -eq 14393){
        #Windows Server 2016
        $ServerVHDs += @{
            Kind = "Full"
            Edition="4"
            VHDName="Win2016_G2.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="Win2016Core_G2.vhdx"
            Size=127GB
        }
        <# Removed since it does not work with newer than 14393.2724
        $ServerVHDs += @{
            Edition="DataCenterNano"
            VHDName="Win2016NanoHV_G2.vhdx"
            NanoPackages="Microsoft-NanoServer-DSC-Package","Microsoft-NanoServer-FailoverCluster-Package","Microsoft-NanoServer-Guest-Package","Microsoft-NanoServer-Storage-Package","Microsoft-NanoServer-SCVMM-Package","Microsoft-NanoServer-Compute-Package","Microsoft-NanoServer-SCVMM-Compute-Package","Microsoft-NanoServer-SecureStartup-Package","Microsoft-NanoServer-DCB-Package","Microsoft-NanoServer-ShieldedVM-Package"
            Size=30GB
        }
        #>
    }elseif ($BuildNumber -eq 17763){
        #Windows Server 2019
        $ServerVHDs += @{
            Kind = "Full"
            Edition="4"
            VHDName="Win2019_G2.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="Win2019Core_G2.vhdx"
            Size=127GB
        }
    }elseif ($BuildNumber -eq 20348){
        #Windows Server 2022
        $ServerVHDs += @{
            Kind = "Full"
            Edition="4"
            VHDName="Win2022_G2.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="Win2022Core_G2.vhdx"
            Size=127GB
        }
    }elseif ($BuildNumber -eq 26100){
        #Windows Server 2025
        $ServerVHDs += @{
            Kind = "Full"
            Edition="4"
            VHDName="Win2025_G2.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="Win2025Core_G2.vhdx"
            Size=127GB
        }        
    }elseif ($BuildNumber -gt 26100 -and $SAC){
        $ServerVHDs += @{
            Kind = "Core"
            Edition="2"
            VHDName="WinSrvInsiderCore_$BuildNumber.vhdx"
            Size=127GB
        }
        #DCEdition fix
        if ($LabConfig.DCEdition -gt 2){
            $LabConfig.DCEdition=2
        }
    }elseif ($BuildNumber -gt 26100){
        #Windows Sever Insider
        $ServerVHDs += @{
            Kind = "Full"
            Edition="4"
            VHDName="WinSrvInsider_$BuildNumber.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="WinSrvInsiderCore_$BuildNumber.vhdx"
            Size=127GB
        }
    }else{
        $ISOServer | Dismount-DiskImage
        WriteErrorAndExit "Plese provide Windows Server 2016, 2019 or Insider greater or equal to build 17744"
    }

    #Test if Tools.vhdx already exists
        if ($ParentDisksNames -contains "tools.vhdx"){
            WriteSuccess "`t Tools.vhdx already exists. Creation will be skipped"
        }else{
            WriteInfo "`t Tools.vhdx not found, will be created"
        }

    #check if DC exists
        if (Get-ChildItem -Path "$PSScriptRoot\LAB\DC\" -Recurse -ErrorAction SilentlyContinue){
            $DCFilesExists=$true
            WriteInfoHighlighted "Files found in $PSScriptRoot\LAB\DC\. DC Creation will be skipped"
        }else{
            $DCFilesExists=$false
        }

#endregion

#region Create parent disks
    #create some folders
        'ParentDisks','Temp','Temp\mountdir' | ForEach-Object {
            if (!( Test-Path "$PSScriptRoot\$_" )) {
                WriteInfoHighlighted "Creating Directory $_"
                New-Item -Type Directory -Path "$PSScriptRoot\$_"
            }
        }

    #load Convert-WindowsImage to memory
        . "$PSScriptRoot\Temp\Convert-WindowsImage.ps1"

      #Create Servers Parent VHDs
        WriteInfoHighlighted "Creating Server Parent disk(s)"
        $vhdStatusInfo = @{}
        foreach ($ServerVHD in $ServerVHDs){
            $vhdStatus = @{
                Kind = $ServerVHD.Kind
                Name = $ServerVHD.VHDName
                AlreadyExists = $false
                BuildStartDate = Get-Date
            }
            if ($serverVHD.Edition -notlike "*nano"){
                if (!(Test-Path "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)")){
                    WriteInfo "`t Creating Server Parent $($ServerVHD.VHDName)"

                    #exit if server wim not found
                    If (!(Test-Path -Path "$($ServerMediaDriveLetter):\sources\install.wim")){
                        WriteInfo "`t Dismounting ISO Images"
                            if ($ISOServer -ne $Null){
                                $ISOServer | Dismount-DiskImage
                            }
                            if ($ISOClient -ne $Null){
                                $ISOClient | Dismount-DiskImage
                            }
                        WriteErrorAndExit "$($ServerMediaDriveLetter):\sources\install.wim not found. Can you try different Server media?"
                    }

                    if ($packages){
                        Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\sources\install.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package $packages
                    }else{
                        Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\sources\install.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI
                    }
                }else{
                    $vhdStatus.AlreadyExists = $true
                    WriteSuccess "`t Server Parent $($ServerVHD.VHDName) found, skipping creation"
                }
            }
            if ($serverVHD.Edition -like "*nano"){
                if (!(Test-Path "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)")){
                    #grab Nano packages
                        $NanoPackages=@()
                        foreach ($NanoPackage in $serverVHD.NanoPackages){
                            $NanoPackages+=(Get-ChildItem -Path "$($ServerMediaDriveLetter):\NanoServer\" -Recurse | Where-Object Name -like $NanoPackage*).FullName
                        }
                    #create parent disks
                        WriteInfo "`t Creating Server Parent $($ServerVHD.VHDName)"
                        if ($packages){
                            Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\NanoServer\NanoServer.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package ($NanoPackages+$packages)
                        }else{
                            Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\NanoServer\NanoServer.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package $NanoPackages
                        }
                }else{
                    WriteSuccess "`t Server Parent $($ServerVHD.VHDName) found, skipping creation"
                }
            }
            $vhdStatus.BuildEndDate = Get-Date

            $vhdStatusInfo[$vhdStatus.Kind] = $vhdStatus
        }

    #create Tools VHDX from .\Temp\ToolsVHD
        $toolsVhdStatus = @{
            Kind = "Tools"
            Name = "tools.vhdx"
            AlreadyExists = $false
            BuildStartDate = Get-Date
        }
        if (!(Test-Path "$PSScriptRoot\ParentDisks\tools.vhdx")){
            WriteInfoHighlighted "Creating Tools.vhdx"
            $toolsVHD=New-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx" -SizeBytes 300GB -Dynamic
            #mount and format VHD
                $VHDMount = Mount-VHD $toolsVHD.Path -Passthru
                $vhddisk = $VHDMount| get-disk
                $vhddiskpart = $vhddisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter |Format-Volume -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel ToolsDisk

            $VHDPathTest=Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\"
            if (!$VHDPathTest){
                New-Item -Type Directory -Path "$PSScriptRoot\Temp\ToolsVHD"
            }
            if ($VHDPathTest){
                WriteInfo "Found $PSScriptRoot\Temp\ToolsVHD\*, copying files into VHDX"
                Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\*" -Destination "$($vhddiskpart.DriveLetter):\" -Recurse -Force
            }else{
                WriteInfo "Files not found" 
                WriteInfoHighlighted "Add required tools into $PSScriptRoot\Temp\ToolsVHD and Press any key to continue..."
                $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
                Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\*" -Destination ($vhddiskpart.DriveLetter+':\') -Recurse -Force
            }

            Dismount-VHD $vhddisk.Number

            $toolsVhdStatus.BuildEndDate = Get-Date
        }else{
            $toolsVhdStatus.AlreadyExists = $true
            WriteSuccess "`t Tools.vhdx found in Parent Disks, skipping creation"
            $toolsVHD = Get-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx"
        }

        $vhdStatusInfo[$toolsVhdStatus.Kind] = $toolsVhdStatus
#endregion

#region Hydrate DC
    if (-not $DCFilesExists){
        WriteInfoHighlighted "Starting DC Hydration"
        $dcHydrationStartTime = Get-Date

        $vhdpath="$PSScriptRoot\LAB\$DCName\Virtual Hard Disks\$DCName.vhdx"
        $VMPath="$PSScriptRoot\LAB\"

        #reuse VHD if already created
            $DCVHDName=($ServerVHDs | Where-Object Edition -eq $LabConfig.DCEdition).VHDName
            if ((($DCVHDName) -ne $null) -and (Test-Path -Path "$PSScriptRoot\ParentDisks\$DCVHDName")){
                WriteSuccess "`t $DCVHDName found, reusing, and copying to $vhdpath"
                New-Item -Path "$VMPath\$DCName" -Name "Virtual Hard Disks" -ItemType Directory
                Copy-Item -Path "$PSScriptRoot\ParentDisks\$DCVHDName" -Destination $vhdpath
            }else{
                #Create Parent VHD
                WriteInfoHighlighted "`t Creating VHD for DC"
                if ($packages){
                    Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\sources\install.wim" -Edition $LabConfig.DCEdition -VHDPath $vhdpath -SizeBytes 60GB -VHDFormat VHDX -DiskLayout UEFI -package $packages
                }else{
                    Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\sources\install.wim" -Edition $LabConfig.DCEdition -VHDPath $vhdpath -SizeBytes 60GB -VHDFormat VHDX -DiskLayout UEFI
                }
            }

        #Get VM Version
        [System.Version]$VMVersion=(Get-WindowsImage -ImagePath $VHDPath -Index 1).Version
        WriteInfo "`t VM Version is $($VMVersion.Build).$($VMVersion.Revision)"

        #If the switch does not already exist, then create a switch with the name $SwitchName
            if (-not [bool](Get-VMSwitch -Name $Switchname -ErrorAction SilentlyContinue)) {
                WriteInfoHighlighted "`t Creating temp hydration switch $Switchname"
                New-VMSwitch -SwitchType Private -Name $Switchname
            }

        #create VM DC
            WriteInfoHighlighted "`t Creating DC VM"
            if ($LabConfig.DCVMVersion){
                $DC=New-VM -Name $DCName -VHDPath $vhdpath -MemoryStartupBytes 2GB -path $vmpath -SwitchName $Switchname -Generation 2 -Version $LabConfig.DCVMVersion
            }else{
                $DC=New-VM -Name $DCName -VHDPath $vhdpath -MemoryStartupBytes 2GB -path $vmpath -SwitchName $Switchname -Generation 2
            }
            $DC | Set-VMProcessor -Count 2
            $DC | Set-VMMemory -DynamicMemoryEnabled $true -MinimumBytes 2GB
            if ($LabConfig.Secureboot -eq $False) {$DC | Set-VMFirmware -EnableSecureBoot Off}
            if ($DC.AutomaticCheckpointsEnabled -eq $True){
                $DC | Set-VM -AutomaticCheckpointsEnabled $False
            }
            if ($LabConfig.InstallSCVMM -eq "Yes"){
                #SCVMM 2022 requires 4GB of memory
                $DC | Set-VMMemory -StartupBytes 4GB -MinimumBytes 4GB
            }

        #Apply Unattend to VM
            if ($VMVersion.Build -ge 17763){
                $oeminformation=@"
                <OEMInformation>
                    <SupportProvider>MSLab</SupportProvider>
                    <SupportURL>https://aka.ms/mslab</SupportURL>
                </OEMInformation>
"@
            }else{
                $oeminformation=$null
            }

            WriteInfoHighlighted "`t Applying Unattend and copying Powershell DSC Modules"
            if (Test-Path $mountdir){
                Remove-Item -Path $mountdir -Recurse -Force
            }
            if (Test-Path "$PSScriptRoot\Temp\unattend"){
                Remove-Item -Path "$PSScriptRoot\Temp\unattend.xml"
            }
            $unattendfile=CreateUnattendFileVHD -Computername $DCName -AdminPassword $AdminPassword -path "$PSScriptRoot\temp\" -TimeZone $TimeZone
            New-item -type directory -Path $mountdir -force
            [System.Version]$VMVersion=(Get-WindowsImage -ImagePath $VHDPath -Index 1).Version
            Mount-WindowsImage -Path $mountdir -ImagePath $VHDPath -Index 1
            Use-WindowsUnattend -Path $mountdir -UnattendPath $unattendFile
            #&"$PSScriptRoot\Temp\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$mountdir
            #&"$PSScriptRoot\Temp\dism\dism" /image:$mountdir /Apply-Unattend:$unattendfile
            New-item -type directory -Path "$mountdir\Windows\Panther" -force
            Copy-Item -Path $unattendfile -Destination "$mountdir\Windows\Panther\unattend.xml" -force
            Copy-Item -Path "$PSScriptRoot\Temp\DSC\*" -Destination "$mountdir\Program Files\WindowsPowerShell\Modules\" -Recurse -force
            WriteInfoHighlighted "`t Adding Hyper-V feature into DC"
            #Install Hyper-V feature
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Path "$mountdir"

        #Create credentials for DSC

            $username = "$($LabConfig.DomainNetbiosName)\Administrator"
            $password = $AdminPassword
            $secstr = New-Object -TypeName System.Security.SecureString
            $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
            $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

        #Create DSC configuration
            configuration DCHydration
            {
                param
                ( 
                    [Parameter(Mandatory)]
                    [pscredential]$safemodeAdministratorCred,
            
                    [Parameter(Mandatory)]
                    [pscredential]$domainCred,

                    [Parameter(Mandatory)]
                    [pscredential]$NewADUserCred

                )

                Import-DscResource -ModuleName ActiveDirectoryDsc -ModuleVersion "6.3.0"
                Import-DscResource -ModuleName DnsServerDsc -ModuleVersion "3.0.0"
                Import-DSCResource -ModuleName NetworkingDSC -ModuleVersion "9.0.0"
                Import-DSCResource -ModuleName xDHCPServer -ModuleVersion "3.1.1"
                Import-DSCResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion "9.1.0"
                Import-DSCResource -ModuleName xHyper-V -ModuleVersion "3.18.0"
                Import-DscResource -ModuleName PSDesiredStateConfiguration

                Node $AllNodes.Where{$_.Role -eq "Parent DC"}.Nodename

                {
                    WindowsFeature ADDSInstall
                    { 
                        Ensure = "Present"
                        Name = "AD-Domain-Services"
                    }

                    WindowsFeature FeatureGPMC
                    {
                        Ensure = "Present"
                        Name = "GPMC"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    }

                    WindowsFeature FeatureADPowerShell
                    {
                        Ensure = "Present"
                        Name = "RSAT-AD-PowerShell"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    } 

                    WindowsFeature FeatureADAdminCenter
                    {
                        Ensure = "Present"
                        Name = "RSAT-AD-AdminCenter"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    } 

                    WindowsFeature FeatureADDSTools
                    {
                        Ensure = "Present"
                        Name = "RSAT-ADDS-Tools"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    } 

                    WindowsFeature Hyper-V-PowerShell
                    {
                        Ensure = "Present"
                        Name = "Hyper-V-PowerShell"
                    }

                    xVMSwitch VMSwitch
                    {
                        Ensure = "Present"
                        Name = "vSwitch"
                        Type = "External"
                        AllowManagementOS = $true
                        NetAdapterName = "Ethernet"
                        EnableEmbeddedTeaming = $true
                        DependsOn = "[WindowsFeature]Hyper-V-PowerShell"
                    }

                    ADDomain FirstDS 
                    { 
                        DomainName = $Node.DomainName
                        Credential = $domainCred
                        SafemodeAdministratorPassword = $safemodeAdministratorCred
                        DomainNetbiosName = $node.DomainNetbiosName
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    }
                
                    WaitForADDomain DscForestWait
                    { 
                        DomainName = $Node.DomainName
                        Credential = $domainCred
                        DependsOn = "[ADDomain]FirstDS"
                    }
                    
                    ADOrganizationalUnit DefaultOU
                    {
                        Name = $Node.DefaultOUName
                        Path = $Node.DomainDN
                        ProtectedFromAccidentalDeletion = $true
                        Description = 'Default OU for all user and computer accounts'
                        Ensure = 'Present'
                        DependsOn = "[ADDomain]FirstDS"
                    }

                    ADUser SQL_SA
                    {
                        DomainName = $Node.DomainName
                        Credential = $domainCred
                        UserName = "SQL_SA"
                        Password = $NewADUserCred
                        Ensure = "Present"
                        DependsOn = "[ADOrganizationalUnit]DefaultOU"
                        Description = "SQL Service Account"
                        Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                        PasswordNeverExpires = $true
                    }

                    ADUser SQL_Agent
                    {
                        DomainName = $Node.DomainName
                        Credential = $domainCred
                        UserName = "SQL_Agent"
                        Password = $NewADUserCred
                        Ensure = "Present"
                        DependsOn = "[ADOrganizationalUnit]DefaultOU"
                        Description = "SQL Agent Account"
                        Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                        PasswordNeverExpires = $true
                    }

                    ADUser Domain_Admin
                    {
                        DomainName = $Node.DomainName
                        Credential = $domainCred
                        UserName = $Node.DomainAdminName
                        Password = $NewADUserCred
                        Ensure = "Present"
                        DependsOn = "[ADOrganizationalUnit]DefaultOU"
                        Description = "DomainAdmin"
                        Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                        PasswordNeverExpires = $true
                    }

                    ADUser VMM_SA
                    {
                        DomainName = $Node.DomainName
                        Credential = $domainCred
                        UserName = "VMM_SA"
                        Password = $NewADUserCred
                        Ensure = "Present"
                        DependsOn = "[ADUser]Domain_Admin"
                        Description = "VMM Service Account"
                        Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                        PasswordNeverExpires = $true
                    }

                    ADGroup DomainAdmins
                    {
                        GroupName = "Domain Admins"
                        DependsOn = "[ADUser]VMM_SA"
                        MembersToInclude = "VMM_SA",$Node.DomainAdminName
                    }

                    ADGroup SchemaAdmins
                    {
                        GroupName = "Schema Admins"
                        GroupScope = "Universal"
                        DependsOn = "[ADUser]VMM_SA"
                        MembersToInclude = $Node.DomainAdminName
                    }

                    ADGroup EntAdmins
                    {
                        GroupName = "Enterprise Admins"
                        GroupScope = "Universal"
                        DependsOn = "[ADUser]VMM_SA"
                        MembersToInclude = $Node.DomainAdminName
                    }

                    ADUser AdministratorNeverExpires
                    {
                        DomainName = $Node.DomainName
                        UserName = "Administrator"
                        Ensure = "Present"
                        DependsOn = "[ADDomain]FirstDS"
                        PasswordNeverExpires = $true
                    }

                    IPaddress IP
                    {
                        IPAddress = ($DHCPscope+"1/24")
                        AddressFamily = "IPv4"
                        InterfaceAlias = "vEthernet (vSwitch)"
                        DependsOn = "[xVMSwitch]VMSwitch"
                    }

                    WindowsFeature DHCPServer
                    {
                        Ensure = "Present"
                        Name = "DHCP"
                        DependsOn = "[ADDomain]FirstDS"
                    }

                    Service DHCPServer #since insider 17035 dhcpserver was not starting for some reason
                    {
                        Name = "DHCPServer"
                        State = "Running"
                        DependsOn =  "[WindowsFeature]DHCPServer"
                    }

                    WindowsFeature DHCPServerManagement
                    {
                        Ensure = "Present"
                        Name = "RSAT-DHCP"
                        DependsOn = "[WindowsFeature]DHCPServer"
                    } 

                    xDhcpServerScope ManagementScope
                    {
                        Ensure = 'Present'
                        ScopeId = ($DHCPscope+"0")
                        IPStartRange = ($DHCPscope+"10")
                        IPEndRange = ($DHCPscope+"254")
                        Name = 'ManagementScope'
                        SubnetMask = '255.255.255.0'
                        LeaseDuration = '00:08:00'
                        State = 'Active'
                        AddressFamily = 'IPv4'
                        DependsOn = "[Service]DHCPServer"
                    }

                    # Setting scope gateway
                    DhcpScopeOptionValue 'ScopeOptionGateway'
                    {
                        OptionId      = 3
                        Value         = ($DHCPscope+"1")
                        ScopeId       = ($DHCPscope+"0")
                        VendorClass   = ''
                        UserClass     = ''
                        AddressFamily = 'IPv4'
                        DependsOn = "[xDhcpServerScope]ManagementScope"
                    }

                    # Setting scope DNS servers
                    DhcpScopeOptionValue 'ScopeOptionDNS'
                    {
                        OptionId      = 6
                        Value         = ($DHCPscope+"1")
                        ScopeId       = ($DHCPscope+"0")
                        VendorClass   = ''
                        UserClass     = ''
                        AddressFamily = 'IPv4'
                        DependsOn = "[xDhcpServerScope]ManagementScope"
                    }

                    # Setting scope DNS domain name
                    DhcpScopeOptionValue 'ScopeOptionDNSDomainName'
                    {
                        OptionId      = 15
                        Value         = $Node.DomainName
                        ScopeId       = ($DHCPscope+"0")
                        VendorClass   = ''
                        UserClass     = ''
                        AddressFamily = 'IPv4'
                        DependsOn = "[xDhcpServerScope]ManagementScope"
                    }
                    
                    xDhcpServerAuthorization LocalServerActivation
                    {
                        IsSingleInstance = 'Yes'
                        Ensure = 'Present'
                    }

                    WindowsFeature DSCServiceFeature
                    {
                        Ensure = "Present"
                        Name   = "DSC-Service"
                    }

                    DnsServerADZone addReverseADZone
                    {
                        Name = $ReverseDNSrecord
                        DynamicUpdate = "Secure"
                        ReplicationScope = "Forest"
                        Ensure = "Present"
                        DependsOn = "[DhcpScopeOptionValue]ScopeOptionGateway"
                    }

                    If ($LabConfig.PullServerDC){
                        xDscWebService PSDSCPullServer
                        {
                            UseSecurityBestPractices = $false
                            Ensure                  = "Present"
                            EndpointName            = "PSDSCPullServer"
                            Port                    = 8080
                            PhysicalPath            = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
                            CertificateThumbPrint   = "AllowUnencryptedTraffic"
                            ModulePath              = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
                            ConfigurationPath       = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
                            State                   = "Started"
                            DependsOn               = "[WindowsFeature]DSCServiceFeature"
                        }
                        
                        File RegistrationKeyFile
                        {
                            Ensure = 'Present'
                            Type   = 'File'
                            DestinationPath = "$env:ProgramFiles\WindowsPowerShell\DscService\RegistrationKeys.txt"
                            Contents        = $Node.RegistrationKey
                        }
                    }
                }
            }

            $ConfigData = @{ 
            
                AllNodes = @( 
                    @{ 
                        Nodename = $DCName
                        Role = "Parent DC"
                        DomainAdminName=$LabConfig.DomainAdminName
                        DomainName = $LabConfig.DomainName
                        DomainNetbiosName = $LabConfig.DomainNetbiosName
                        DomainDN = $LabConfig.DN
                        DefaultOUName=$LabConfig.DefaultOUName
                        RegistrationKey='14fc8e72-5036-4e79-9f89-5382160053aa'
                        PSDscAllowPlainTextPassword = $true
                        PsDscAllowDomainUser= $true
                        RetryCount = 50
                        RetryIntervalSec = 30
                    }         
                ) 
            } 

        #create LCM config
            [DSCLocalConfigurationManager()]
            configuration LCMConfig
            {
                Node DC
                {
                    Settings
                    {
                        RebootNodeIfNeeded = $true
                        ActionAfterReboot = 'ContinueConfiguration'
                    }
                }
            }

        #create DSC MOF files
            WriteInfoHighlighted "`t Creating DSC Configs for DC"
            LCMConfig       -OutputPath "$PSScriptRoot\Temp\config" -ConfigurationData $ConfigData
            DCHydration     -OutputPath "$PSScriptRoot\Temp\config" -ConfigurationData $ConfigData -safemodeAdministratorCred $cred -domainCred $cred -NewADUserCred $cred
        
        #copy DSC MOF files to DC
            WriteInfoHighlighted "`t Copying DSC configurations (pending.mof and metaconfig.mof)"
            New-item -type directory -Path "$PSScriptRoot\Temp\config" -ErrorAction Ignore
            Copy-Item -path "$PSScriptRoot\Temp\config\dc.mof"      -Destination "$mountdir\Windows\system32\Configuration\pending.mof"
            Copy-Item -Path "$PSScriptRoot\Temp\config\dc.meta.mof" -Destination "$mountdir\Windows\system32\Configuration\metaconfig.mof"

        #close VHD and apply changes
            WriteInfoHighlighted "`t Applying changes to VHD"
            Dismount-WindowsImage -Path $mountdir -Save
            #&"$PSScriptRoot\Temp\dism\dism" /Unmount-Image /MountDir:$mountdir /Commit

        #Start DC VM and wait for configuration
            WriteInfoHighlighted "`t Starting DC"
            $DC | Start-VM

            $VMStartupTime = 250
            WriteInfoHighlighted "`t Configuring DC using DSC takes a while."
            WriteInfo "`t `t Initial configuration in progress. Sleeping $VMStartupTime seconds"
            Start-Sleep $VMStartupTime
            $i=1
            do{
                $test=Invoke-Command -VMGuid $DC.id -ScriptBlock {Get-DscConfigurationStatus} -Credential $cred -ErrorAction SilentlyContinue
                if ($test -eq $null) {
                    WriteInfo "`t `t Configuration in Progress. Sleeping 10 seconds"
                    Start-Sleep 10
                }elseif ($test.status -ne "Success" -and $i -eq 1) {
                    WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                    WriteInfoHighlighted "`t `t Invoking DSC Configuration again"
                    Invoke-Command -VMGuid $DC.id -ScriptBlock {Start-DscConfiguration -UseExisting} -Credential $cred
                    $i++
                }elseif ($test.status -ne "Success" -and $i -gt 1) {
                    WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                    WriteInfoHighlighted "`t `t Restarting DC"
                    Invoke-Command -VMGuid $DC.id -ScriptBlock {Restart-Computer} -Credential $cred
                }elseif ($test.status -eq "Success" ) {
                    WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                    WriteInfoHighlighted "`t `t DSC Configured DC Successfully"
                }
            }until ($test.Status -eq 'Success' -and $test.rebootrequested -eq $false)
            $test

        #configure default OU where new Machines will be created using redircmp and add reverse lookup zone (as setting reverse lookup does not work with DSC)
            Invoke-Command -VMGuid $DC.id -Credential $cred -ErrorAction SilentlyContinue -ArgumentList $LabConfig -ScriptBlock {
                Param($LabConfig);
                redircmp "OU=$($LabConfig.DefaultOUName),$($LabConfig.DN)"
                Add-DnsServerPrimaryZone -NetworkID ($DHCPscope+"/24") -ReplicationScope "Forest"
            }
        #install SCVMM or its prereqs if specified so
            if (($LabConfig.InstallSCVMM -eq "Yes") -or ($LabConfig.InstallSCVMM -eq "SQL") -or ($LabConfig.InstallSCVMM -eq "ADK") -or ($LabConfig.InstallSCVMM -eq "Prereqs")){
                $DC | Add-VMHardDiskDrive -Path $toolsVHD.Path
            }

            if ($LabConfig.InstallSCVMM -eq "Yes"){
                WriteInfoHighlighted "Installing System Center Virtual Machine Manager and its prerequisites"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\1_SQL_Install.ps1
                    d:\scvmm\2_ADK_Install.ps1
                    #install prereqs
                    if (Test-Path "D:\SCVMM\SCVMM\Prerequisites\VCRedist\amd64\vcredist_x64.exe"){
                        Start-Process -FilePath "D:\SCVMM\SCVMM\Prerequisites\VCRedist\amd64\vcredist_x64.exe" -ArgumentList "/passive /quiet /norestart" -Wait
                    }
                    Restart-Computer
                }
                Start-Sleep 10

                WriteInfoHighlighted "$($DC.name) was restarted, waiting for Active Directory on $($DC.name) to be started."
                do{
                $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $LabConfig -ErrorAction SilentlyContinue -ScriptBlock {
                    param($LabConfig);
                    Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue}
                    Start-Sleep 5
                }
                until ($test -ne $Null)
                WriteSuccess "Active Directory on $($DC.name) is up."

                Start-Sleep 30 #Wait as sometimes VMM failed to install without this.
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\3_SCVMM_Install.ps1
                }
            }

            if ($LabConfig.InstallSCVMM -eq "SQL"){
                WriteInfoHighlighted "Installing SQL"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\1_SQL_Install.ps1
                }
            }

            if ($LabConfig.InstallSCVMM -eq "ADK"){
                WriteInfoHighlighted "Installing ADK"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\2_ADK_Install.ps1
                }
            }

            if ($LabConfig.InstallSCVMM -eq "Prereqs"){
                WriteInfoHighlighted "Installing System Center VMM Prereqs"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\1_SQL_Install.ps1
                    d:\scvmm\2_ADK_Install.ps1
                }
            }

            if (($LabConfig.InstallSCVMM -eq "Yes") -or ($LabConfig.InstallSCVMM -eq "SQL") -or ($LabConfig.InstallSCVMM -eq "ADK") -or ($LabConfig.InstallSCVMM -eq "Prereqs")){
                $DC | Get-VMHardDiskDrive | Where-Object path -eq $toolsVHD.Path | Remove-VMHardDiskDrive
            }

            $dcHydrationEndTime = Get-Date
    }
#endregion

#region backup DC and cleanup
    #cleanup DC
    if (-not $DCFilesExists){
        WriteInfoHighlighted "Backup DC and cleanup"
        #shutdown DC 
            WriteInfo "`t Disconnecting VMNetwork Adapter from DC"
            $DC | Get-VMNetworkAdapter | Disconnect-VMNetworkAdapter
            WriteInfo "`t Shutting down DC"
            $DC | Stop-VM
            $DC | Set-VM -MemoryMinimumBytes 512MB

        #Backup DC config, remove from Hyper-V, return DC config
            WriteInfo "`t Creating backup of DC VM configuration"
            Copy-Item -Path "$vmpath\$DCName\Virtual Machines\" -Destination "$vmpath\$DCName\Virtual Machines_Bak\" -Recurse
            WriteInfo "`t Removing DC"
            $DC | Remove-VM -Force
            WriteInfo "`t Returning VM config and adding to Virtual Machines.zip"
            Remove-Item -Path "$vmpath\$DCName\Virtual Machines\" -Recurse
            Rename-Item -Path "$vmpath\$DCName\Virtual Machines_Bak\" -NewName 'Virtual Machines'
            Compress-Archive -Path "$vmpath\$DCName\Virtual Machines\" -DestinationPath "$vmpath\$DCName\Virtual Machines.zip"
        #cleanup vswitch
            WriteInfo "`t Removing switch $Switchname"
            Remove-VMSwitch -Name $Switchname -Force -ErrorAction SilentlyContinue
    }

    #Cleanup The rest
        WriteInfo "`t Dismounting ISO Images"
        if ($ISOServer -ne $Null){
            $ISOServer | Dismount-DiskImage
        }

#endregion

#region finishing
    WriteSuccess "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    $options = [System.Management.Automation.Host.ChoiceDescription[]] @(
        <# 0 #> New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Cleanup .\Temp\ 1_Prereq.ps1 2_CreateParentDisks.ps1 and rename 3_deploy.ps1 to just deploy.ps1"
        <# 1 #> New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Keep files (in case DC was not created sucessfully)"
    )
    
    If (!$LabConfig.AutoCleanUp) {
        $response = $host.UI.PromptForChoice("Unnecessary files cleanup","Do you want to cleanup unnecessary files and folders?", $options, 0 <#default option#>)
    }
    else {
        $response = 0
    }

    If ($response -eq 1){
        $renamed = $false
        WriteInfo "Skipping cleanup"
    }else{
        $renamed = $true
        WriteInfo "`t `t Cleaning unnecessary items"
        Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse
        "$PSScriptRoot\Temp","$PSScriptRoot\1_Prereq.ps1","$PSScriptRoot\2_CreateParentDisks.ps1" | ForEach-Object {
            WriteInfo "`t `t `t Removing $_"
            Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
        } 
        WriteInfo "`t `t `t Renaming $PSScriptRoot\3_Deploy.ps1 to Deploy.ps1"
        Rename-Item -Path "$PSScriptRoot\3_Deploy.ps1" -NewName "Deploy.ps1" -ErrorAction SilentlyContinue
    }

    # Telemetry Event
    if($LabConfig.TelemetryLevel -in $TelemetryEnabledLevels) {
        WriteInfo "Sending telemetry info"
        $metrics = @{
            'script.duration' = ((Get-Date) - $StartDateTime).TotalSeconds
            'msu.count' = ($packages | Measure-Object).Count
        }
        if(-not $DCFilesExists) {
            $metrics['dc.duration'] = ($dcHydrationEndTime - $dcHydrationEndTime).TotalSeconds
        }

        $properties = @{
            'dc.exists' = [int]$DCFilesExists
            'dc.edition' = $LabConfig.DCEdition
            'dc.build' = $BuildNumber
            'dc.language' = $OSLanguage
            'lab.scriptsRenamed' = $renamed
            'lab.installScvmm' = $LabConfig.InstallSCVMM
            'os.windowsInstallationType' = $WindowsInstallationType
        }
        $events = @()

        # First for parent disks
        foreach($key in $vhdStatusInfo.Keys) {
            $status = $vhdStatusInfo[$key]
            $buildDuration = 0
            if(-not $status.AlreadyExists) {
                $buildDuration = ($status.BuildEndDate - $status.BuildStartDate).TotalSeconds
            }
            $key = $key.ToLower()

            $properties["vhd.$($key).exists"] = [int]$status.AlreadyExists
            $properties["vhd.$($key).name"] = $status.Name
            if($buildDuration -gt 0) {
                $metrics["vhd.$($key).duration"] = $buildDuration
            }

            if($status.AlreadyExists) {
               continue # verbose events are interesting only when creating a new vhds
            }

            $vhdMetrics = @{
                'vhd.duration' = $buildDuration
            }
            $vhdProperties = @{
                'vhd.name' = $status.Name
                'vhd.kind' = $status.Kind
            }
            if($status.Kind -ne "Tools") {
                $vhdProperties['vhd.os.build'] = $BuildNumber

                if($LabConfig.TelemetryLevel -eq "Full") {
                    $vhdProperties['vhd.os.language'] = $OSLanguage
                }
            }
            $events += Initialize-TelemetryEvent -Event "CreateParentDisks.Vhd" -Metrics $vhdMetrics -Properties $vhdProperties -NickName $LabConfig.TelemetryNickName
        }

        # and one overall
        $events += Initialize-TelemetryEvent -Event "CreateParentDisks.End" -Metrics $metrics -Properties $properties -NickName $LabConfig.TelemetryNickName

        Send-TelemetryEvents -Events $events | Out-Null
    }

Stop-Transcript

If (!$LabConfig.AutoClosePSWindows) {
    WriteSuccess "Job Done. Press enter to continue..."
    Read-Host | Out-Null
}

#endregion

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhvmbb5ObDclN/
# pR6U1H49IGfCx4xrvo2yJnL619bed6CCDXYwggX0MIID3KADAgECAhMzAAADrzBA
# DkyjTQVBAAAAAAOvMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwOTAwWhcNMjQxMTE0MTkwOTAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOS8s1ra6f0YGtg0OhEaQa/t3Q+q1MEHhWJhqQVuO5amYXQpy8MDPNoJYk+FWA
# hePP5LxwcSge5aen+f5Q6WNPd6EDxGzotvVpNi5ve0H97S3F7C/axDfKxyNh21MG
# 0W8Sb0vxi/vorcLHOL9i+t2D6yvvDzLlEefUCbQV/zGCBjXGlYJcUj6RAzXyeNAN
# xSpKXAGd7Fh+ocGHPPphcD9LQTOJgG7Y7aYztHqBLJiQQ4eAgZNU4ac6+8LnEGAL
# go1ydC5BJEuJQjYKbNTy959HrKSu7LO3Ws0w8jw6pYdC1IMpdTkk2puTgY2PDNzB
# tLM4evG7FYer3WX+8t1UMYNTAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQURxxxNPIEPGSO8kqz+bgCAQWGXsEw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMTgyNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAISxFt/zR2frTFPB45Yd
# mhZpB2nNJoOoi+qlgcTlnO4QwlYN1w/vYwbDy/oFJolD5r6FMJd0RGcgEM8q9TgQ
# 2OC7gQEmhweVJ7yuKJlQBH7P7Pg5RiqgV3cSonJ+OM4kFHbP3gPLiyzssSQdRuPY
# 1mIWoGg9i7Y4ZC8ST7WhpSyc0pns2XsUe1XsIjaUcGu7zd7gg97eCUiLRdVklPmp
# XobH9CEAWakRUGNICYN2AgjhRTC4j3KJfqMkU04R6Toyh4/Toswm1uoDcGr5laYn
# TfcX3u5WnJqJLhuPe8Uj9kGAOcyo0O1mNwDa+LhFEzB6CB32+wfJMumfr6degvLT
# e8x55urQLeTjimBQgS49BSUkhFN7ois3cZyNpnrMca5AZaC7pLI72vuqSsSlLalG
# OcZmPHZGYJqZ0BacN274OZ80Q8B11iNokns9Od348bMb5Z4fihxaBWebl8kWEi2O
# PvQImOAeq3nt7UWJBzJYLAGEpfasaA3ZQgIcEXdD+uwo6ymMzDY6UamFOfYqYWXk
# ntxDGu7ngD2ugKUuccYKJJRiiz+LAUcj90BVcSHRLQop9N8zoALr/1sJuwPrVAtx
# HNEgSW+AKBqIxYWM4Ev32l6agSUAezLMbq5f3d8x9qzT031jMDT+sUAoCw0M5wVt
# CUQcqINPuYjbS1WgJyZIiEkBMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGg0wghoJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILJeaSAmRFsBWN1YVfkOd904
# Z1SW3IoIKWQrypfeWoxnMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAV/Lw6UEM0HJvokmbe/ZOwYHSL0vFWDDI+7l+Mjz1TGZlCh6xJk1mWBYS
# itEFlnpERUCl/q3NNnmZbTcvORs4SWlcKSGR7/8NTdyuNezXY1s5BI7/ylmVhYu4
# TLRrC7JlYB/KpUsmOg1DIU7H087RBxC3Gij/x0WhKLYt97y56rsCbVhjoOqfqj8L
# cZVNQespo4yG2NRyYwb/o0RcBRBFoXamS+TTpvJQq3K4LdoxvDm0CA/Tmh3LnOLq
# 2+WTvRfKFnLIU7xLG1yNsawBWpWCkOcYkau0M8CiW0toD9AbcdJ9pJOS47IFZxMJ
# gLn66ZQXHMZYctpdhJIqzWN5BaLe96GCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCB6m3CUr3xEzw47x3pfOlWdF/3nNdqWMI9Y0fSf+gFy3QIGZkZHC3lQ
# GBMyMDI0MDYyMTEzMjMwMy44MjZaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046RjAwMi0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAfI+MtdkrHCRlAABAAAB8jANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEyMDYxODQ1
# NThaFw0yNTAzMDUxODQ1NThaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046RjAwMi0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC85fPLFwppYgxwYxkSEeYvQBtnYJTtKKj2FKxzHx0f
# gV6XgIIrmCWmpKl9IOzvOfJ/k6iP0RnoRo5F89Ad29edzGdlWbCj1Qyx5HUHNY8y
# u9ElJOmdgeuNvTK4RW4wu9iB5/z2SeCuYqyX/v8z6Ppv29h1ttNWsSc/KPOeuhzS
# AXqkA265BSFT5kykxvzB0LxoxS6oWoXWK6wx172NRJRYcINfXDhURvUfD70jioE9
# 2rW/OgjcOKxZkfQxLlwaFSrSnGs7XhMrp9TsUgmwsycTEOBdGVmf1HCD7WOaz5EE
# cQyIS2BpRYYwsPMbB63uHiJ158qNh1SJXuoL5wGDu/bZUzN+BzcLj96ixC7wJGQM
# BixWH9d++V8bl10RYdXDZlljRAvS6iFwNzrahu4DrYb7b8M7vvwhEL0xCOvb7WFM
# sstscXfkdE5g+NSacphgFfcoftQ5qPD2PNVmrG38DmHDoYhgj9uqPLP7vnoXf7j6
# +LW8Von158D0Wrmk7CumucQTiHRyepEaVDnnA2GkiJoeh/r3fShL6CHgPoTB7oYU
# /d6JOncRioDYqqRfV2wlpKVO8b+VYHL8hn11JRFx6p69mL8BRtSZ6dG/GFEVE+fV
# mgxYfICUrpghyQlETJPITEBS15IsaUuW0GvXlLSofGf2t5DAoDkuKCbC+3VdPmlY
# VQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFJVbhwAm6tAxBM5cH8Bg0+Y64oZ5MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQA9S6eO4HsfB00XpOgPabcN3QZeyipgilcQ
# SDZ8g6VCv9FVHzdSq9XpAsljZSKNWSClhJEz5Oo3Um/taPnobF+8CkAdkcLQhLdk
# Shfr91kzy9vDPrOmlCA2FQ9jVhFaat2QM33z1p+GCP5tuvirFaUWzUWVDFOpo/O5
# zDpzoPYtTr0cFg3uXaRLT54UQ3Y4uPYXqn6wunZtUQRMiJMzxpUlvdfWGUtCvnW3
# eDBikDkix1XE98VcYIz2+5fdcvrHVeUarGXy4LRtwzmwpsCtUh7tR6whCrVYkb6F
# udBdWM7TVvji7pGgfjesgnASaD/ChLux66PGwaIaF+xLzk0bNxsAj0uhd6QdWr6T
# T39m/SNZ1/UXU7kzEod0vAY3mIn8X5A4I+9/e1nBNpURJ6YiDKQd5YVgxsuZCWv4
# Qwb0mXhHIe9CubfSqZjvDawf2I229N3LstDJUSr1vGFB8iQ5W8ZLM5PwT8vtsKEB
# wHEYmwsuWmsxkimIF5BQbSzg9wz1O6jdWTxGG0OUt1cXWOMJUJzyEH4WSKZHOx53
# qcAvD9h0U6jEF2fuBjtJ/QDrWbb4urvAfrvqNn9lH7gVPplqNPDIvQ8DkZ3lvbQs
# Yqlz617e76ga7SY0w71+QP165CPdzUY36et2Sm4pvspEK8hllq3IYcyX0v897+X9
# YeecM1Pb1jCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNQ
# MIICOAIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkYwMDItMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBr
# i943cFLH2TfQEfB05SLICg74CKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA6h+P/zAiGA8yMDI0MDYyMTA1Mzcw
# M1oYDzIwMjQwNjIyMDUzNzAzWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDqH4//
# AgEAMAoCAQACAgc+AgH/MAcCAQACAhP4MAoCBQDqIOF/AgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAHB2xCxhmy/OBo3cH/4ETncL6tmaFYovGd8/BpHSMKlL
# MPAVmj+ody0adXO4aZc5jN9EtWFPR4RjgRFjrqmEs94P1gy1S6plNUS0lTb1njHF
# NppMkNJnO3UV/j3H7BM3ZI5ghpZwVtdInUkrOKguH7Wylt5uqHeThyR7lfxbdAqZ
# Tzv2vd1d/af5ZJ7+veIxhkU1e0CvTXXDo22oRodHPz/wV+goEeX2ozkau4/WeMhD
# APyLkDFujXi4Eb8QbyNbv8lB6TadUG3F+ilqsSVTyRVEPySSD77W4CCSG0CVxP8b
# MON8UT6Ywt8Pok8eXmanUxMNLTJpvRFR4Oud8qHoyNQxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAfI+MtdkrHCRlAABAAAB
# 8jANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCBZg430DoyBB4s4kX3giGggQYiNHC5JVqOVEeuKaW9o
# izCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPjaPh0uMVJc04+Y4Ru5BUUb
# HE4suZ6nRHSUu0XXSkNEMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAHyPjLXZKxwkZQAAQAAAfIwIgQgp/S8eC/TU+cAcq+mPzfvTGq6
# AuXQBOXdt046P31Qy50wDQYJKoZIhvcNAQELBQAEggIAXlpQqOzRGnF8bvKN9ar0
# HYd99n9mk2P5bzU3v0sctdY39fq4mO9RPG2OjfK00g4jXbPZywTH/t/3LcfdvWY+
# Q29/fachJgi6ZTMRzIdz8C1HD754Eh3y/VELutxbePu1DbPnll/PDC/FlnAWwfxk
# VTCb0e8vauaRm05qD5XBT2LOnCZ5zHs4YI42RpZIMNbN7MVQlr+kbjfFFOgQat2B
# QPcnDxf0bfR4W333wcIaUkGxYcC9JORtxda0rLqU1YMf6g5y0gQ+q/PTlKHaq+mV
# QjY0YB6WsIIGipLZk5T2sbSuPC2u1XbnLtvteHP8AXji0uLNz6ui33CEPKVFcdF0
# VnkEeXhRR8Q07+PwKb+y+B6+/RGjHkhc+y/JhWBTghQ1XN54sx6q+mpaVrhQuq70
# RNjRsb/20Y0QabNFAB3dy4FVCR7jdn/XzbWtUbjS0DyiuOFugq2+E2n3leVqhmMq
# bFN2hYKze0+iyfN4Dh285u9gE540AnFgC5VyTdHsMsSlkXB6W6A7aAP2PHhtRP78
# zoZsPAmPqMTVJjcpF2cLLGcJ8VdZCkNUz6sAUY7kaWiJvX0L6gwTo1Z9FeEnwUcl
# lSUvES1xOsxneEHJv2ilAwcl6djKVhuDP8GZpeTErcx0uy2RMFDD1NY9nQmTaATW
# 0++Nhano/fTFum9AUK8uWzk=
# SIG # End signature block
