#basic config for Windows Server 2022, that creates VMs for S2D Hyperconverged scenario https://github.com/Microsoft/MSLab/tree/master/Scenarios/S2D%20Hyperconverged

$LabConfig=@{AllowedVLANs="1-10,711-719" ; DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'MSLab-' ; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}
# Windows Server 2022
1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "$S2D$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2022Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}
# Or Azure Stack HCI 23H2 (non-domain joined) https://github.com/DellGEOS/AzureStackHOLs/tree/main/lab-guides/01a-DeployAzureStackHCICluster-CloudBasedDeployment
#1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName = "ASNode$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI23H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 2TB ; MemoryStartupBytes= 20GB; VMProcessorCount=16 ; vTPM=$true ; Unattend="NoDjoin" ; NestedVirt=$true }}
# Or Windows Server 2025 https://github.com/DellGEOS/AzureStackHOLs/tree/main/lab-guides/03-TestingWindowsServerInsider
#1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName="S2D$_" ; Configuration='S2D' ; ParentVHD='WinSrvInsiderCore_26063.vhdx' ; HDDNumber=4 ; HDDSize=2TB ; MemoryStartupBytes=1GB; VMProcessorCount=4 ; vTPM=$true}}


#region Same as above, but with more explanation
    <#
    $LabConfig=@{
        DomainAdminName="LabAdmin";                  # Used during 2_CreateParentDisks (no affect if changed after this step)
        AdminPassword="LS1setup!";                   # Used during 2_CreateParentDisks. If changed after, it will break the functionality of 3_Deploy.ps1
        Prefix = "MSLab-";                           # (Optional) All VMs and vSwitch are created with this prefix, so you can identify the lab. If not specified, Lab folder name is used
        SwitchName = "LabSwitch";                    # (Optional) Name of vSwitch
        SwitchNICs = "";                             # (Optional) Adds these NICs to vSwitch (without connecting hostOS). (example "NIC1","NIC2")
        SecureBoot=$true;                            # (Optional) Useful when testing unsigned builds (Useful for MS developers for daily builds)
        DCEdition="4";                               # 4 for DataCenter or 3 for DataCenterCore
        InstallSCVMM="No";                           # (Optional) Yes/Prereqs/SQL/ADK/No
        AdditionalNetworksInDC=$false;               # (Optional) If Additional networks should be added also to DC
        DomainNetbiosName="Corp";                    # (Optional) If set, custom domain NetBios name will be used. if not specified, Default "corp" will be used
        DomainName="Corp.contoso.com";               # (Optional) If set, custom DomainName will be used. If not specified, Default "Corp.contoso.com" will be used
        DefaultOUName="Workshop";                    # (Optional) If set, custom OU for all machines and account will be used. If not specified, default "Workshop" is created
        AllowedVLANs="1-10";                         # (Optional) Sets the list of VLANs that can be used on Management vNICs. If not specified, default "1-10" is set.
        Internet=$false;                             # (Optional) If $true, it will add external vSwitch and configure NAT in DC to provide internet (Logic explained below)
        UseHostDnsAsForwarder=$false;                # (Optional) If $true, local DNS servers will be used as DNS forwarders in DC
        CustomDnsForwarders=@("8.8.8.8","1.1.1.1");  # (Optional) If configured, script will use those servers as DNS fordwarders in DC (Defaults to 8.8.8.8 and 1.1.1.1)
        PullServerDC=$true;                          # (Optional) If $false, then DSC Pull Server will not be configured on DC
        ServerISOFolder="";                          # (Optional) If configured, script will use ISO located in this folder for Windows Server hydration (if more ISOs are present, then out-grid view is called)
        ServerMSUsFolder="";                         # (Optional) If configured, script will inject all MSU files found into server OS
        EnableGuestServiceInterface=$false;          # (Optional) If True, then Guest Services integration component will be enabled on all VMs.
        DCVMProcessorCount=2;                        # (Optional) 2 is default. If specified more/less, processorcount will be modified.
        DHCPscope="10.0.0.0";                        # (Optional) 10.0.0.0 is configured if nothing is specified. Scope has to end with .0 (like 10.10.10.0). It's always /24
        DCVMVersion="9.0";                           # (Optional) Latest is used if nothing is specified. Make sure you use values like "8.0","8.3","9.0"
        TelemetryLevel="";                           # (Optional) If configured, script will stop prompting you for telemetry. Values are "None","Basic","Full"
        TelemetryNickname="";                        # (Optional) If configured, telemetry will be sent with NickName to correlate data to specified NickName. So when leaderboards will be published, MSLab users will be able to see their own stats
        AutoStartAfterDeploy=$false;                 # (Optional) If $false, no VM will be started; if $true or 'All' all lab VMs will be started after Deploy script; if 'DeployedOnly' only newly created VMs will be started.
        InternetVLAN="";                             # (Optional) If set, it will apply VLAN on Interent adapter connected to DC
        Linux=$false;                                # (Optional) If set to $true, required prerequisities for building Linux images with Packer will be configured.
        LinuxAdminName="linuxadmin";                 # (Optional) If set, local user account with that name will be created in Linux image. If not, DomainAdminName will be used as a local account.
        SshKeyPath="$($env:USERPROFILE)\.ssh\id_rsa" # (Optional) If set, specified SSH key will be used to build and access Linux images.
        AutoClosePSWindows=$false;                   # (Optional) If set, the PowerShell console windows will automatically close once the script has completed successfully. Best suited for use in automated deployments.
        AutoCleanUp=$false;                          # (Optional) If set, after creating initial parent disks, files that are no longer necessary will be cleaned up. Best suited for use in automated deployments.
        AdditionalNetworksConfig=@();                # Just empty array for config below
        VMs=@();                                     # Just empty array for config below
    }

    # Specifying LabVMs
    1..4 | ForEach-Object {
        $VMNames="S2D";                                # Here you can bulk edit name of 4 VMs created. In this case will be s2d1,s2d2,s2d3,s2d4 created
        $LABConfig.VMs += @{
            VMName = "$VMNames$_" ;
            Configuration = 'S2D' ;                    # Simple/S2D/Shared/Replica
            ParentVHD = 'Win2022Core_G2.vhdx';         # VHD Name from .\ParentDisks folder
            SSDNumber = 0;                             # Number of "SSDs" (its just simulation of SSD-like sized HDD, just bunch of smaller disks)
            SSDSize=800GB ;                            # Size of "SSDs"
            HDDNumber = 12;                            # Number of "HDDs"
            HDDSize= 4TB ;                             # Size of "HDDs"
            MemoryStartupBytes= 512MB;                 # Startup memory size
        }
    }

    #optional: (only if AdditionalNetworks are configured in $LabConfig.VMs) this is just an example. In this configuration its not needed.
    $LABConfig.AdditionalNetworksConfig += @{
        NetName = 'Storage1';                        # Network Name
        NetAddress='172.16.1.';                      # Network Addresses prefix. (starts with 1), therefore first VM with Additional network config will have IP 172.16.1.1
        NetVLAN='1';                                 # VLAN tagging
        Subnet='255.255.255.0'                       # Subnet Mask
    }
    $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage2'; NetAddress='172.16.2.'; NetVLAN='2'; Subnet='255.255.255.0'}
    $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage3'; NetAddress='172.16.3.'; NetVLAN='3'; Subnet='255.255.255.0'}

    #>
#endregion

#region $Labconfig
    <#
    DomainAdminName (Mandatory)
        Additional Domain Admin.

    Password (Mandatory)
        Specifies password for your lab. This password is used for domain admin, vmm account, sqlservice account and additional DomainAdmin... Define before running 2_CreateParentImages

    Prefix (Optional)
        Prefix for your lab. Each VM and switch will have this prefix.
        If not specified, labfolder name will be used

    SwitchName (Optional)
        If not specified, LabSwitch will be used as switch name

    Secureboot (Optional)
        $True/$False
        This enables or disables secure boot. In Microsoft we can test unsigned test builds with Secureboot off.

    DCEdition (Mandatory)
        'ServerDataCenter'/'ServerDataCenterCore'
        If you dont like GUI and you have management VM, you can select Core edition.

    InstallSCVMM * (Optional)
        'Yes'         - installs ADK, SQL and VMM
        'ADK'         - installs just ADK
        'SQL'         - installs just SQL
        'Prereqs'     - installs ADK and SQL
        'No'          - No, or anything else, nothing is installed.

            *requires install files in toolsVHD\SCVMM\, or it will fail. You can download all tools here:
                SQL: http://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2016
                SCVMM: http://www.microsoft.com/en-us/evalcenter/evaluate-system-center-technical-preview
                ADK: https://msdn.microsoft.com/en-us/windows/hardware/dn913721.aspx (you need to run setup and download the content. 2Meg file is not enough)

    AdditionalNetworksInDC (optional)
        If $True, networks specified in $LABConfig.AdditionalNetworksConfig will be added.

    MGMTNICsInDC (Optional)
        If nothing specified, then just 1 NIC is added in DC.
        Can be 1-8

    DomainNetbiosName (Optional)
        Domain NetBios Name. If nothing is specified, default "Corp" will be used

    DomainName (Optional)
        Domain Name. If nothing is specified, default "Corp.contoso.com" will be used

    DefaultOUName (Optional)
        Default Organization Unit Name for all computers and accounts. If nothing is specified, default "Workshop" will be used

    AllowedVLANs (Optional)
        Allowed VLANs configured on all management adapters. Accepts "1-10" or "1,2,3,4,5,6,7,8,9,10"

    Internet (Optional)
        If $True, it will configure vSwitch based on following Logic (designed to not ask you anything most of the times):
            If no vSwitch exists:
                If only one connected adapter exists, then it will create vSwitch from it.
                If more connected adapters exists, it will ask for only one
            If vSwitch named "$($labconfig.Prefix)$($labconfig.Switchname)-External" exists, it will be used (in case lab already exists)
            If only one vSwitch exists, then it will be used
            If more vSwitches exists, you will be prompted for what to use.
        It will add vNIC to DC and configure NAT with some Open DNS servers in DNS forwarder

    UseHostDnsAsForwarder (Optional)
        If $true, local DNS servers will be used as DNS forwarders in DC when Internet is enabled.
        By default local host's DNS servers will be used as forwarders.

    CustomDnsForwarders (Optional)
        If configured, DNS servers listed will be appended to DNS forwaders list on DC's DNS server.
        If not defined at all, commonly known DNS servers will be used as a fallback:
             - Google DNS: 8.8.8.8
             - Cloudfare: 1.1.1.1

    DHCPscope (Optional)
        If configured, a custom DHCP scope will be used. Will always use a '/24'.
        Specify input like '10.1.0.0' or '192.168.0.0'
        If not defined at all, DHCP scope 10.0.0.0 will be used.

    PullServerDC (optional)
        If $False, Pull Server will not be setup.

    ServerISOFolder
        Example: ServerISOFolder="d:\ISO\Server2016"
        Script will try to find ISO in this folder and subfolders. If more ISOs are present, then out-grid view is called and you will be promted to select only one

    ServerMSUsFolder
        Example: ServerMSUsFolder="d:\Updates\Server2016"
        If ServerISOFolder is specified, then updates are being grabbed from ServerMSUsFolder.
        If ServerMSUsFolder is not specified, or empty, you are not asked for providing MSU files and no MSUs are applied.

    DCVMProcessorCount (optional)
        Example: DCVMProcessorCount=4
        Number of CPUs in DC.
        If not specified, 2 vCPUs will be set. If specified more/less, processorcount will be modified. If more vCPUs specified than available in host, the maximum possible number will be configured.

    EnableGuestServiceInterface (optional)
        Example: EnableGuestServiceInterface=$true
        If True, then Guest Services integration component will be enabled on all VMs. This allows simple file copy from host to guests.

    DCVMVersion
        Example: DCVMVersion="8.0" (optional)
        If set, version for DC will be used. It is useful if you want to keep DC older to be able to use it on previous versions of OS.

    TelemetryLevel (optional)
        Example: TelemetryLevel="Full"
        If set, scripts will not prompt for telemetry. Can be "None","Basic","Full"
        For more info see https://aka.ms/mslab/telemetry

    TelemetryNickname (optional)
        Example: TelemetryNickname="Jaromirk"
        If configured, telemetry will be sent with NickName to correlate data to specified NickName. So when leaderboards will be published, MSLab users will be able to see their own stats

    Linux (optional)
        Example: Linux=$true
        If set to $true, additional prerequisities (SSH Client, SSH Key, Packer, Packer templates) required for building Linux images will be downloaded and configured.

    LinuxAdminName (optional)
        Example: LinuxAdminName="linuxadmin"
        If set, local user account with that name will be created in Linux image. If not, DomainAdminName will be used as a local account.

    SshKeyPath (optional)
        Example: SshKeyPath="$($env:USERPROFILE)\.ssh\id_rsa"
        If configured, existing SSH key will be used for building and connecting to Linux images. If not, 0_Prereq.ps1 will generate a new SSH key pair and store it locally in LAB folder.

    AutoStartAfterDeploy (optional)
        Example: AutoClosePSWindows=$true
        If set to true, the PowerShell console windows will automatically close once the script has completed successfully. Best suited for use in automated deployments.

    AutoCleanup (optional)
        Example: AutoCleanUp=$true
        If set to true, after creating initial parent disks, files that are no longer necessary will be cleaned up. Best suited for use in automated deployments.

    #>
#endregion

#region $LabConfig.VMs
    <#
    Example
        Single:
        $LABConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True }
        Multiple:
        1..2 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }

    VMName (Mandatory)
        Can be whatever. This name will be used as name to djoin VM.

    Configuration (Mandatory)
        'Simple' - No local storage. Just VM
        'S2D' - locally attached SSDS and HDDs. For Storage Spaces Direct. You can specify 0 for SSDnumber or HDD number if you want only one tier.
        'Shared' - Shared VHDS attached to all nodes. Simulates traditional approach with shared space/shared storage. Requires Shared VHD->Requires Clustering Components
        'Replica' - 2 Shared disks, first for Data, second for Log. Simulates traditional storage. Requires Shared VHD->Requires Clustering Components

    VMSet (Mandatory for Shared and Replica configuration)
        This is unique name for your set of VMs. You need to specify it for Spaces and Replica scenario, so script will connect shared disks to the same VMSet.

    ParentVHD (Mandatory)
        'Win2016Core_G2.vhdx'     - Windows Server 2016 Core
        'Win2016NanoHV_G2.vhdx'    - Windows Server 2016 Nano with these packages: DSC, Failover Cluster, Guest, Storage, SCVMM
        'Win2016NanoHV_G2.vhdx'   - Windows Server 2016 Nano with these packages: DSC, Failover Cluster, Guest, Storage, SCVMM, Compute, SCVMM Compute
        'Win10_G2.vhdx'        - Windows 10 if you selected to hydrate it with create client parent.

    AdditionalNetworks (Optional)
        $True - Additional networks (configured in AdditonalNetworkConfig) are added

    AdditionalNetworkAdapters (Optional) - Hashtable or array if multiple network adapters should be connected to this virtual machine
        @{
            VirtualSwitchName  (Mandatory) - Name of the Hyper-V Switch to witch the adapter will be connected
            Mac                (Optional)  - Static MAC address of the interface otherwise default will be generated
            VlanId             (Optional)  - VLAN ID for this adapter
            IpConfiguration    (Optional)  - DHCP or hastable with specific IP configuration
            @{
                IpAddress      (Mandatory) - Static IP Address that would be injected to the OS
                Subnet         (Mandatory)
            }
        }

    DSCMode (Optional)
        If 'Pull', VMs will be configured to Pull config from DC.

    Config
        You can specify random Config names to identify configuration that should be pulled from pull server

    NestedVirt (Optional)
        If $True, nested virt is enabled
        Enables -ExposeVirtualizationExtensions $true

    MemoryStartupBytes (Mandatory)
        Example: 512MB
        Startup memory bytes

    MemoryMinimumBytes (Optional)
        Example: 1GB
        Minimum memory bytes, must be less or equal to MemoryStartupBytes
        If not set, default is used.

    StaticMemory (Optional)
        if $True, then static memory is configured

    AddToolsVHD (Optional)
        If $True, then ToolsVHD will be added

    Unattend
        Example: Unattend="DjoinCred"
        Possible values: "DjoinBlob", "DjoinCred", "NoDjoin", "None"
        Default "DjoinBlob"
        "DjoinBlob" uses blob, can be consumed only by Windows Server 2016+
        "DjoinCred" uses credentials. Can be used in 2008+
        "NoDjoin" inserts just local admin. For win10 use also AdditionalLocalAdmin
        "None" does not inject any unattend.

    LinuxDomainJoin
        Example: LinuxDomainJoin="No"
        Possible values: "No", "SSSD"
        Default: SSSD
          "No" VM will be just renamed, but not joined to Active Directory
          "SSSD" VM will be joined to domain online using SSSD tool

    SkipDjoin (Optional,Deprecated)
        If $True, VM will not be djoined. Default unattend used.
        Note: you might want to use AdditionalLocalAdmin variable with Windows 10 as local administrator account is by default disabled there.

    Win2012Djoin (Optional,Deprecated)
        If $True, older way to domain join will be used (Username and Password in Answer File instead of blob) as Djoin Blob works only in Win 2016

    vTPM (Optional)
        if $true, vTPM will be enabled for virtual machine. Gen2 only.

    MGMTNICs (Optional)
        Number of management NIC.
        Default is 2, maximum 8.

    DisableWCF (Optional)
        If $True, then Disable Windows Consumer Features registry is added= no consumer apps in start menu.

    AdditionalLocalAdmin (Optional, only applies if Unattend="NoDjoin")
        Example AdditionalLocalAdmin='Ned'
        Works only with SkipDjoin as you usually don't need additional local account
        When you skipDjoin on Windows10 and local administrator is disabled. Then AdditionalLocalAdmin is useful

    VMProcessorCount (Optional)
        Example VMProcessorCount=8
        Number of Processors in VM. If specified more than available in host, maximum possible number will be used.
        If "Max" is specified, maximum number of VCPUs will be used (determined from host where mslab is running)

    Generation (Optional)
        Example Generation=1
        If not specified, then it's 2. If 1, then its 1. Easy.

    EnableWinRM (Optional)
        Example EnableWinRM=$True
        If $true, then synchronous command winrm quickconfig -force -q will be run
        Only useful for 2008 and Win10

    CustomPowerShellCommands (Optional)
        Example (single command) CustomPowerShellCommands="New-Item -Name Temp -Path c:\ -ItemType Directory"
        Example (multiple commands) CustomPowerShellCommands="New-Item -Name Temp -Path c:\ -ItemType Directory","New-Item -Name Temp1 -Path c:\ -ItemType Directory"

    #DisableTimeIC (Optional)
        Example DisableTimeIC=$true
        if $true, time Hyper-V Time Synchronization Integration Service (VMICTimeProvider) will be disabled
    #>
#endregion

#region $LabConfig.AdditionalNetworksConfig
    <#
    Example: $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage1'; NetAddress='172.16.1.'; NetVLAN='1'; Subnet='255.255.255.0'}

    NetName
        Name of network adapter (visible from host)

    NetAddress
        Network prefix of IP address thats injected into the VM. IP Starts with 1.

    NetVLAN
        Will tag VLAN. If 0, vlan tagging will be skipped.

    Subnet
        Subnet of network.
    #>
#endregion

#region $LabConfig.VMs Examples
    <#
    Just some VMs
        $LabConfig.VMs = @(
            @{ VMName = 'Simple1'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB },
            @{ VMName = 'Simple2'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB },
            @{ VMName = 'Simple3'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB },
            @{ VMName = 'Simple4'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }
        )

    or you can use this to deploy 100 simple VMs with name NanoServer1, NanoServer2...
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }

    or you can use this to deploy 100 server VMs with 1 Client OS with name Windows10
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
        $LabConfig.VMs += @{ VMName = 'Windows10' ; Configuration = 'Simple'  ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 512MB ; AddToolsVHD=$True ; DisableWCF=$True}

    or you can use this to deploy 100 nanoservers and 100 Windows 10 machines named Windows10_..
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
        1..100 | ForEach-Object {"Windows10_$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'          ; MemoryStartupBytes= 512MB ;   AddToolsVHD=$True ; DisableWCF=$True } }

    or Several different VMs
        * you need to provide your GPT VHD for win 2012 (like created with convertwindowsimage script)
        $LabConfig.VMs += @{ VMName = 'Win10'            ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; EnableWinRM=$True }
        $LabConfig.VMs += @{ VMName = 'Win10_OOBE'       ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; Unattend="None" }
        $LabConfig.VMs += @{ VMName = 'Win10_NotInDomain'; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; Unattend="NoDjoin" ; AdditionalLocalAdmin="Ned" }
        $LabConfig.VMs += @{ VMName = 'Win2016'          ; Configuration = 'Simple'   ; ParentVHD = 'Win2016_G2.vhdx'          ; MemoryStartupBytes= 512MB ; Unattend="NoDjoin" }
        $LabConfig.VMs += @{ VMName = 'Win2016_Core'     ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'      ; MemoryStartupBytes= 512MB }
        $LabConfig.VMs += @{ VMName = 'Win2016_Nano'     ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB }
        $LabConfig.VMs += @{ VMName = 'Win2012R2'        ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2_G2.vhdx'        ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" }
        $LabConfig.VMs += @{ VMName = 'Win2012R2_Core'   ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" }
        $LabConfig.VMs += @{ VMName = 'Win2008R2_Core'   ; Configuration = 'Simple'   ; ParentVHD = 'Win2008R2.vhdx'           ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" ; Generation = 1}

    Example with sets of different DSC Configs
        1..2 | ForEach-Object {"Nano$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB ; DSCMode='Pull'; DSCConfig=@('LAPS_Nano_Install','LAPSConfig1')} }
        3..4 | ForEach-Object {"Nano$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB ; DSCMode='Pull'; DSCConfig=@('LAPS_Nano_Install','LAPSConfig2')} }
        1..6 | ForEach-Object {"DSC$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig=@('Config1','Config2')} }
        7..12| ForEach-Object {"DSC$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig='Config3'} }

    Hyperconverged S2D with nano and nested virtualization (see https://msdn.microsoft.com/en-us/virtualization/hyperv_on_windows/user_guide/nesting for more info)
        1..4 | ForEach-Object {"S2D$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True} }

    HyperConverged Storage Spaces Direct with Nano Server
        1..4 | ForEach-Object {"S2D$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

    Disaggregated Storage Spaces Direct with Nano Server
        1..4 | ForEach-Object {"Compute$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
        1..4 | ForEach-Object {"SOFS$_"}     | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 12; SSDSize=800GB ; HDDNumber = 0 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

    "traditional" stretch cluster (like with traditional SAN)
        1..2 | ForEach-Object {"Replica$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }
        3..4 | ForEach-Object {"Replica$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet2' ; AdditionalNetworks = $True} }

    HyperConverged Storage Spaces with Shared Storage
        1..4 | ForEach-Object {"Compute$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
        1..4 | ForEach-Object {"SOFS$_"}     | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1'} }

    ShieldedVMs lab
        $LABConfig.VMs += @{ VMName = 'HGS' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; Unattend="NoDjoin" }
        1..2 | ForEach-Object { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; MemoryStartupBytes= 2GB ; NestedVirt=$True ; vTPM=$True  } }

    Windows Server 2012R2 Hyper-V (8x4TB CSV + 1 1G Witness)
        1..8 | ForEach-Object {"Node$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx'   ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'HyperV2012R2Lab' ;Unattend="DjoinCred" } }

    Windows Server 2012R2 Storage Spaces
        1..2 | ForEach-Object {"2012r2Spaces$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx'     ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= '2012R2SpacesLab';Unattend="DjoinCred" } }

    #>
#endregion

# SIG # Begin signature block
# MIInzgYJKoZIhvcNAQcCoIInvzCCJ7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDSAaDlshxHYvQF
# +o0Ekk03yZBS0E34UMK2EFwz2Fq0iqCCDYUwggYDMIID66ADAgECAhMzAAADri01
# UchTj1UdAAAAAAOuMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwODU5WhcNMjQxMTE0MTkwODU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQD0IPymNjfDEKg+YyE6SjDvJwKW1+pieqTjAY0CnOHZ1Nj5irGjNZPMlQ4HfxXG
# yAVCZcEWE4x2sZgam872R1s0+TAelOtbqFmoW4suJHAYoTHhkznNVKpscm5fZ899
# QnReZv5WtWwbD8HAFXbPPStW2JKCqPcZ54Y6wbuWV9bKtKPImqbkMcTejTgEAj82
# 6GQc6/Th66Koka8cUIvz59e/IP04DGrh9wkq2jIFvQ8EDegw1B4KyJTIs76+hmpV
# M5SwBZjRs3liOQrierkNVo11WuujB3kBf2CbPoP9MlOyyezqkMIbTRj4OHeKlamd
# WaSFhwHLJRIQpfc8sLwOSIBBAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhx/vdKmXhwc4WiWXbsf0I53h8T8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMTgzNjAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AGrJYDUS7s8o0yNprGXRXuAnRcHKxSjFmW4wclcUTYsQZkhnbMwthWM6cAYb/h2W
# 5GNKtlmj/y/CThe3y/o0EH2h+jwfU/9eJ0fK1ZO/2WD0xi777qU+a7l8KjMPdwjY
# 0tk9bYEGEZfYPRHy1AGPQVuZlG4i5ymJDsMrcIcqV8pxzsw/yk/O4y/nlOjHz4oV
# APU0br5t9tgD8E08GSDi3I6H57Ftod9w26h0MlQiOr10Xqhr5iPLS7SlQwj8HW37
# ybqsmjQpKhmWul6xiXSNGGm36GarHy4Q1egYlxhlUnk3ZKSr3QtWIo1GGL03hT57
# xzjL25fKiZQX/q+II8nuG5M0Qmjvl6Egltr4hZ3e3FQRzRHfLoNPq3ELpxbWdH8t
# Nuj0j/x9Crnfwbki8n57mJKI5JVWRWTSLmbTcDDLkTZlJLg9V1BIJwXGY3i2kR9i
# 5HsADL8YlW0gMWVSlKB1eiSlK6LmFi0rVH16dde+j5T/EaQtFz6qngN7d1lvO7uk
# 6rtX+MLKG4LDRsQgBTi6sIYiKntMjoYFHMPvI/OMUip5ljtLitVbkFGfagSqmbxK
# 7rJMhC8wiTzHanBg1Rrbff1niBbnFbbV4UDmYumjs1FIpFCazk6AADXxoKCo5TsO
# zSHqr9gHgGYQC2hMyX9MGLIpowYCURx3L7kUiGbOiMwaMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAOuLTVRyFOPVR0AAAAA
# A64wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDhX
# Qu+Bw26Eay05R8Q+XiEjjye0h5Ewc8q6LfD2TbO4MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAGnC847amzEcLJJtCkMNdlgpH+8xF2SqjdvXM
# 2pag9u962alIbOHhBXiMzHh+aWuTgfoHykK85oAU2U1UxuOrX8ke0npTHig6rb91
# X64uWAXkKbV2iIPTO7BEeANTVgU1TvzyjIhF3nirO2BX3BvJQDJdSwa6/isO3nXs
# t/WKESt9DqafN0rqlzVQKfeab1GB3Gu0irhSceTTt4lEZUmdYulTvr8rhRa3+GI+
# oERaktKRXkK8dhHxCkovWJWdN57OKu5oE/KN/LtfPz4ocYq+903YK36LrPYNRGkx
# wHtx39YHKGMCcMm3kfqIKFg83aFyIMbLt7LFMH/iQTS8pvhEBaGCFykwghclBgor
# BgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCBbUIOkrfEv+PryU7QSi1pz0VrKbgZ6xHlr
# 1ZIsfIgFAgIGZnLTo9a+GBMyMDI0MDYyMTEzMjMwNC43NDJaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAHlj2rA
# 8z20C6MAAQAAAeUwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjMxMDEyMTkwNzM1WhcNMjUwMTEwMTkwNzM1WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKl7
# 4Drau2O6LLrJO3HyTvO9aXai//eNyP5MLWZrmUGNOJMPwMI08V9zBfRPNcucreIY
# SyJHjkMIUGmuh0rPV5/2+UCLGrN1P77n9fq/mdzXMN1FzqaPHdKElKneJQ8R6cP4
# dru2Gymmt1rrGcNe800CcD6d/Ndoommkd196VqOtjZFA1XWu+GsFBeWHiez/Pllq
# cM/eWntkQMs0lK0zmCfH+Bu7i1h+FDRR8F7WzUr/7M3jhVdPpAfq2zYCA8ZVLNgE
# izY+vFmgx+zDuuU/GChDK7klDcCw+/gVoEuSOl5clQsydWQjJJX7Z2yV+1KC6G1J
# VqpP3dpKPAP/4udNqpR5HIeb8Ta1JfjRUzSv3qSje5y9RYT/AjWNYQ7gsezuDWM/
# 8cZ11kco1JvUyOQ8x/JDkMFqSRwj1v+mc6LKKlj//dWCG/Hw9ppdlWJX6psDesQu
# QR7FV7eCqV/lfajoLpPNx/9zF1dv8yXBdzmWJPeCie2XaQnrAKDqlG3zXux9tNQm
# z2L96TdxnIO2OGmYxBAAZAWoKbmtYI+Ciz4CYyO0Fm5Z3T40a5d7KJuftF6CTocc
# c/Up/jpFfQitLfjd71cS+cLCeoQ+q0n0IALvV+acbENouSOrjv/QtY4FIjHlI5zd
# JzJnGskVJ5ozhji0YRscv1WwJFAuyyCMQvLdmPddAgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQU3/+fh7tNczEifEXlCQgFOXgMh6owHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBADP6whOFjD1ad8GkEJ9oLBuvfjndMyGQ9R4HgBKSlPt3pa0XVLcimrJlDnKG
# gFBiWwI6XOgw82hdolDiMDBLLWRMTJHWVeUY1gU4XB8OOIxBc9/Q83zb1c0RWEup
# gC48I+b+2x2VNgGJUsQIyPR2PiXQhT5PyerMgag9OSodQjFwpNdGirna2rpV23EU
# wFeO5+3oSX4JeCNZvgyUOzKpyMvqVaubo+Glf/psfW5tIcMjZVt0elswfq0qJNQg
# oYipbaTvv7xmixUJGTbixYifTwAivPcKNdeisZmtts7OHbAM795ZvKLSEqXiRUjD
# YZyeHyAysMEALbIhdXgHEh60KoZyzlBXz3VxEirE7nhucNwM2tViOlwI7EkeU5hu
# dctnXCG55JuMw/wb7c71RKimZA/KXlWpmBvkJkB0BZES8OCGDd+zY/T9BnTp8si3
# 6Tql84VfpYe9iHmy7PqqxqMF2Cn4q2a0mEMnpBruDGE/gR9c8SVJ2ntkARy5Sflu
# uJ/MB61yRvT1mUx3lyppO22ePjBjnwoEvVxbDjT1jhdMNdevOuDeJGzRLK9HNmTD
# C+TdZQlj+VMgIm8ZeEIRNF0oaviF+QZcUZLWzWbYq6yDok8EZKFiRR5otBoGLvaY
# FpxBZUE8mnLKuDlYobjrxh7lnwrxV/fMy0F9fSo2JxFmtLgtMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA942iGuYFrsE4wzWD
# d85EpM6RiwqggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOof9O0wIhgPMjAyNDA2MjEyMDQ3NDFaGA8yMDI0MDYy
# MjIwNDc0MVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA6h/07QIBADAHAgEAAgIR
# RTAHAgEAAgISnzAKAgUA6iFGbQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# ACKMwEyDv1WXg2NrjgW7ha3lzAX/xkmyAfyBc8Mh+rlq4OMx8k2V1/k1sVfPLrMC
# UDrBJh0DN0NX+2jT40CmdUF3DTpzNzBphECwk0AqeHsGgZsUr2llNOXTdvGs9q6l
# LccrRWNy8atj2dpYBN46KS1sQnT/jHePOAQO6Ob+fwSSMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHlj2rA8z20C6MAAQAA
# AeUwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQg3FOT/DblZd7pGIiyYxOc0/pTt5Dzx9UGeheppnAx
# LO4wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAVqdP//qjxGFhe2YboEXeb
# 8I/pAof01CwhbxUH9U697TCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAAB5Y9qwPM9tAujAAEAAAHlMCIEICqEVqgF24rlc3Jaz/X/WUrS
# PwwbDHm5kY8uxoRrVkyDMA0GCSqGSIb3DQEBCwUABIICABDvN24KbMexhDIvUy4B
# qgTDRjBmXfjQSh1EJilJSFQZo+crmWCz+y/VpHE6jUxQYYoP4oulouvwYHvF5oD0
# tWI5FkC6cJzdhRw2Kki0UWjnYNq3BzDDoFpLZyW7Ezs9a2mgoUSnjqR1t8bw1sM0
# 2ohSwZSvCOibGgjvFW2v+0CUjaWhCJ3pWX/wU6uxd30WDnJjUwC+z40ug1Guy+r+
# 6xGW3zHKX+RSceCgzDX2NPFFXdqV+FT83Uxs/SpKxfafyzUeeWyRsEDawmN1anda
# Bq3QgbqwJmcR9EJG6d4LPVbNSh5ZNsPZPYz4pTGkWdicnVDa8bFqZFs03F13H6pN
# dl+Oui3O3JJi0yLdMhpjuyFZCvJ9yV9Rivuoi5MFU8SvGw5fj1HhL1iaxCqDlurR
# 2HDDBLyfskV/Ry58Rx154A8xsZnFaFSJFdIsaNwOa5ooJdFTGDeUQ7yaYygrrRMV
# XZCfwuOM4s1l64aILA4++PXepAi1w2Mfd+TzHqkjiqlMZUaNna3kWhgMajRlIybg
# gUK8mqMoAeh92v2y0x+nXk7T01Mix62YN/seHcz8YEarYp1sA6Oc2fN/G6zNB45g
# 2xdoeiTxRb32676ON+LY/akSXEOBNb+q4GOQkYKFG2h+r7Hkz/vf+jqmcPbwb5iz
# r1IhEDbkKSqaljN0MGMKyCM2
# SIG # End signature block
