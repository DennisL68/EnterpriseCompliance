<#
.SYNOPSIS
    A file to be included in scripts that needs to alter or use Windows BCD-information.

.DESCRIPTION
    This include file covers using the BCD (Boot Configuration Data) WMI provider to manipulate BCD stores
    from PowerShell.

.LINK
    https://www.codeproject.com/Articles/833655/Modify-Windows-BCD-using-Powershell

.EXAMPLE
    . ("$PSScriptRoot\PowerShellBcd.ps1")

    $mem = Get-StaticBcdStore | Open-Store "" | 
       Open-Object "{b2721d73-1db4-4c62-bf78-c548a880142d}"

    $dev = $mem |
        Get-Element -Type ([BcdLibraryElementTypes]::Device_ApplicationDevice) |
            Get-Device

    $dev.Properties_

    This example gets the Windows Memory Tester and retrieves the device data. This method is handy for evaluating
    properties for setting various device elements from code.

.EXAMPLE
    . ("$PSScriptRoot\PowershellBcd.ps1")

    Get-StaticBcdStore | Create-Store -File "$env:TEMP\BCD-TEMP" | Out-Null
    $bcdFile = "S:\boot\BCD"

    if (Test-Path $bcdFile) {
        Remove-Item -Path $bcdFile | Out-Null
    }

    $sDrive = Get-DosDevice "S:" # Windows OS (will be C after reboot)
    $cDrive = Get-DosDevice "W:"

    $BcdStore = Get-StaticBcdStore | Create-Store -File $bcdFile
    $BcdStore | Import-Store "$env:TEMP\BCD-TEMP" | Out-Null
    
    The output from bcdedit for a live system store is used to generate a new BCD store in code. The resulting BCD
    store is created on a drive that has been cleaned, reformatted, and reimaged in a deployment scenario.

.NOTE
    This include file was published by awilson9010 at CodeProject.com 1 Nov 2020.

#>


try {
    $check = ($deviceMethods -eq [Kernel32.NativeMethods])
}
catch {
    $deviceMethods = Add-Type -MemberDefinition @'
[DllImport("Kernel32.dll", 
EntryPoint = "QueryDosDeviceA", CharSet = CharSet.Ansi, SetLastError=true)]
public static extern int QueryDosDevice
(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@ -Name NativeMethods -Namespace Kernel32 -PassThru
}

function Get-DosDevice {
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        $DriveLetter
    )

    $sb = New-Object System.Text.StringBuilder(30)
    $ret = $deviceMethods::QueryDosDevice($DriveLetter, $sb, 30)

    if ($ret -gt 0) {
        $sb.ToString()
    }
}

function Has-Role {
    Param(
        [Security.Principal.WindowsBuiltInRole]$Role = 
          [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity

    return $principal.IsInRole($Role)
}


function Get-StaticBcdStore {
    $SWbemLocator = New-Object -ComObject WbemScripting.SWbemLocator
    $wmi = $SWbemLocator.ConnectServer(".","root\wmi")
    $wmi.Get("BcdStore")
}

function Set-InheritedObjects {
    Param(
        [Parameter(Position=0)]
        $Value,
        
        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Set-ObjectListElement -Type ([BcdLibraryElementTypes]::ObjectList_InheritedObjects) $Value
}

function Set-ApplicationPath {
    Param(
        [Parameter(Position=0)][string]
        $Value,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Set-StringElement ([BcdLibraryElementTypes]::String_ApplicationPath) $Value
}

function Set-Description {
    Param(
        [Parameter(Position=0)][string]
        $Value,
        
        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Set-StringElement ([BcdLibraryElementTypes]::String_Description) $Value
}

function Set-PreferredLocale {
    Param(
        [Parameter(Position=0)][string]
        $Value,
        
        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Set-StringElement ([BcdLibraryElementTypes]::String_PreferredLocale) $Value
}

##########################
###     COM Helper     ###
##########################

function New-InParameter {
    Param(
        [Parameter(Position=0)]
        $Method,
        
        [Parameter(ValueFromPipeLine=$true)]
        $Object
    )

    $Object.Methods_.Item($Method).InParameters.SpawnInstance_()
}

function Get-PropertyValue {
    Param(
        [Parameter(Position=0)]
        $Property,
        
        [Parameter(ValueFromPipeLine=$true)]
        $Object
    )

    $Object.Properties_.Item($Property).Value
}

function Set-PropertyValue {
    Param(
        [Parameter(Position=0)]
        $Property,
        [Parameter(Position=1)]
        $Value,

        [Parameter(ValueFromPipeLine=$true)]
        $Object
    )

    $Object.Properties_.Item($Property).Value=$Value
}

# 20201101 Work Around Posted for exception: Unable to cast object of type 'System.UInt32' to type 'System.String'
function Invoke-Method {
    Param(
        [Parameter(Position=0)]
        $Method,

        [Parameter(Position=1)]
        $ParameterNames,
        
        [Parameter(Position=2)]
        $ParameterValues,

        [Parameter(ValueFromPipeLine=$true)]
        $Object
    )

    if ($ParameterNames -eq $null -or $ParameterValues -eq $null) {
        # If the method has required parameters: "The remote procedure call failed."
        $Object.ExecMethod_($Method)
    }
    else {
        $in = $Object.Methods_.Item($Method).InParameters.SpawnInstance_()
        if ($ParameterNames.GetType() -eq [System.String]) {
            $prop = $in.Properties_.Item($ParameterNames)
            $prop.GetType().InvokeMember("Value", 
            [System.Reflection.BindingFlags]::SetProperty,$null,$prop,@($ParameterValues))
        }
        else {
            for ($i = 0; $i -lt $ParameterNames.LongLength; $i++) {
                if ($ParameterValues[$i] -ne $null) {
                    $prop = $in.Properties_.Item($ParameterNames[$i])
                    if ($ParameterValues[$i] -is [array]) {
                        $prop.GetType().InvokeMember("Value", 
                        [System.Reflection.BindingFlags]::SetProperty,
                        $null,$prop,@(,$ParameterValues[$i]))
                    } else {
                        $prop.GetType().InvokeMember("Value", 
                        [System.Reflection.BindingFlags]::SetProperty,
                        $null,$prop,@($ParameterValues[$i]))
                    }
                }
            }
        }

        $Object.ExecMethod_($Method, $in)
    }
}

function Release-ComObject {
    Param(
        [Parameter(Position=0, ValueFromPipeLine=$true)]
        $ComObject
    )

    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObject)
}

###########################
###     Known GUIDs     ###
###########################

# BCD-Template (Windows 7 Pro)
$bootmgr        = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
$resumeloadersettings = "{1afa9c49-16ab-4a5c-901b-212802da9460}"
$memdiag        = "{b2721d73-1db4-4c62-bf78-c548a880142d}"
$ntldr          = "{466f5a88-0af2-4f76-9038-095b170dc21c}"
$dbgsettings    = "{4636856e-540f-4170-a130-a84776f4c654}"
$emssettings    = "{0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}"
$bootloadersettings = "{6efb52bf-1766-41db-a6b3-0ee5eff72bd7}"
$hypervisorsettings = "{7ff607e0-4395-11db-b0de-0800200c9a66}"
$globalsettings     = "{7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}"
$badmemory      = "{5189b25c-5558-4bf2-bca4-289b11bd29e2}"

# BCD.doc - 2006
$fwbootmgr  = "{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}"
$resumeapp  = "{147aa509-0358-4473-b83b-d950dda00615}"

$ramdiskopt = "{AE5534E0-A924-466C-B836-758539A3EE3A}"


############################
###     Object Types     ###
############################

if (!(([System.Management.Automation.PSTypeName]"BcdBootMgrElementTypes").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdBootMgrElementTypes : uint
    {
        ObjectList_DisplayOrder = 0x24000001,
        ObjectList_BootSequence = 0x24000002,
        Object_DefaultObject = 0x23000003,
        Integer_Timeout = 0x25000004,
        Boolean_AttemptResume = 0x26000005,
        Object_ResumeObject = 0x23000006,
        ObjectList_ToolsDisplayOrder = 0x24000010,
        Boolean_DisplayBootMenu = 0x26000020,
        Boolean_NoErrorDisplay = 0x26000021,
        Device_BcdDevice = 0x21000022,
        String_BcdFilePath = 0x22000023,
        Boolean_ProcessCustomActionsFirst = 0x26000028,
        IntegerList_CustomActionsList = 0x27000030,
        Boolean_PersistBootSequence = 0x26000031
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdDeviceObjectElementTypes").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdDeviceObjectElementTypes : uint
    {
        Integer_RamdiskImageOffset = 0x35000001,
        Integer_TftpClientPort = 0x35000002,
        Device_SdiDevice = 0x31000003,
        String_SdiPath = 0x32000004,
        Integer_RamdiskImageLength = 0x35000005,
        Boolean_RamdiskExportAsCd = 0x36000006,
        Integer_RamdiskTftpBlockSize = 0x36000007,
        Integer_RamdiskTftpWindowSize = 0x36000008,
        Boolean_RamdiskMulticastEnabled = 0x36000009,
        Boolean_RamdiskMulticastTftpFallback = 0x3600000A,
        Boolean_RamdiskTftpVarWindow = 0x3600000B
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdLibrary_DebuggerType").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdLibrary_DebuggerType
    {
        DebuggerSerial = 0,
        Debugger1394 = 1,
        DebuggerUsb = 2,
        DebuggerNet = 3
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdLibrary_SafeBoot").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdLibrary_SafeBoot
    {
        SafemodeMinimal = 0,
        SafemodeNetwork = 1,
        SafemodeDsRepair = 2
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdLibraryElementTypes").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdLibraryElementTypes : uint
    {
        Device_ApplicationDevice = 0x11000001,
        String_ApplicationPath = 0x12000002,
        String_Description = 0x12000004,
        String_PreferredLocale = 0x12000005,
        ObjectList_InheritedObjects = 0x14000006,
        Integer_TruncatePhysicalMemory = 0x15000007,
        ObjectList_RecoverySequence = 0x14000008,
        Boolean_AutoRecoveryEnabled = 0x16000009,
        IntegerList_BadMemoryList = 0x1700000a,
        Boolean_AllowBadMemoryAccess = 0x1600000b,
        Integer_FirstMegabytePolicy = 0x1500000c,
        Integer_RelocatePhysicalMemory = 0x1500000D,
        Integer_AvoidLowPhysicalMemory = 0x1500000E,
        Boolean_DebuggerEnabled = 0x16000010,
        Integer_DebuggerType = 0x15000011,
        Integer_SerialDebuggerPortAddress = 0x15000012,
        Integer_SerialDebuggerPort = 0x15000013,
        Integer_SerialDebuggerBaudRate = 0x15000014,
        Integer_1394DebuggerChannel = 0x15000015,
        String_UsbDebuggerTargetName = 0x12000016,
        Boolean_DebuggerIgnoreUsermodeExceptions = 0x16000017,
        Integer_DebuggerStartPolicy = 0x15000018,
        String_DebuggerBusParameters = 0x12000019,
        Integer_DebuggerNetHostIP = 0x1500001A,
        Integer_DebuggerNetPort = 0x1500001B,
        Boolean_DebuggerNetDhcp = 0x1600001C,
        String_DebuggerNetKey = 0x1200001D,
        Boolean_EmsEnabled = 0x16000020,
        Integer_EmsPort = 0x15000022,
        Integer_EmsBaudRate = 0x15000023,
        String_LoadOptionsString = 0x12000030,
        Boolean_DisplayAdvancedOptions = 0x16000040,
        Boolean_DisplayOptionsEdit = 0x16000041,
        Device_BsdLogDevice = 0x11000043,
        String_BsdLogPath = 0x12000044,
        Boolean_GraphicsModeDisabled = 0x16000046,
        Integer_ConfigAccessPolicy = 0x15000047,
        Boolean_DisableIntegrityChecks = 0x16000048,
        Boolean_AllowPrereleaseSignatures = 0x16000049,
        String_FontPath = 0x1200004A,
        Integer_SiPolicy = 0x1500004B,
        Integer_FveBandId = 0x1500004C,
        Boolean_ConsoleExtendedInput = 0x16000050,
        Integer_GraphicsResolution = 0x15000052,
        Boolean_RestartOnFailure = 0x16000053,
        Boolean_GraphicsForceHighestMode = 0x16000054,
        Boolean_IsolatedExecutionContext = 0x16000060,
        Boolean_BootUxDisable = 0x1600006C,
        Boolean_BootShutdownDisabled = 0x16000074,
        IntegerList_AllowedInMemorySettings = 0x17000077,
        Boolean_ForceFipsCrypto = 0x16000079
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdMemDiagElementTypes").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdMemDiagElementTypes : uint
    {
        Integer_PassCount = 0x25000001,
        Integer_FailureCount = 0x25000003
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdOSLoader_NxPolicy").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdOSLoader_NxPolicy
    {
        NxPolicyOptIn = 0,
        NxPolicyOptOut = 1,
        NxPolicyAlwaysOff = 2,
        NxPolicyAlwaysOn = 3
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdOSLoader_PAEPolicy").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdOSLoader_PAEPolicy
    {
        PaePolicyDefault = 0,
        PaePolicyForceEnable = 1,
        PaePolicyForceDisable = 2
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdOSLoaderElementTypes").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdOSLoaderElementTypes : uint
    {
        Device_OSDevice = 0x21000001,
        String_SystemRoot = 0x22000002,
        Object_AssociatedResumeObject = 0x23000003,
        Boolean_DetectKernelAndHal = 0x26000010,
        String_KernelPath = 0x22000011,
        String_HalPath = 0x22000012,
        String_DbgTransportPath = 0x22000013,
        Integer_NxPolicy = 0x25000020,
        Integer_PAEPolicy = 0x25000021,
        Boolean_WinPEMode = 0x26000022,
        Boolean_DisableCrashAutoReboot = 0x26000024,
        Boolean_UseLastGoodSettings = 0x26000025,
        Boolean_AllowPrereleaseSignatures = 0x26000027,
        Boolean_NoLowMemory = 0x26000030,
        Integer_RemoveMemory = 0x25000031,
        Integer_IncreaseUserVa = 0x25000032,
        Boolean_UseVgaDriver = 0x26000040,
        Boolean_DisableBootDisplay = 0x26000041,
        Boolean_DisableVesaBios = 0x26000042,
        Boolean_DisableVgaMode = 0x26000043,
        Integer_ClusterModeAddressing = 0x25000050,
        Boolean_UsePhysicalDestination = 0x26000051,
        Integer_RestrictApicCluster = 0x25000052,
        Boolean_UseLegacyApicMode = 0x26000054,
        Integer_X2ApicPolicy = 0x25000055,
        Boolean_UseBootProcessorOnly = 0x26000060,
        Integer_NumberOfProcessors = 0x25000061,
        Boolean_ForceMaximumProcessors = 0x26000062,
        Boolean_ProcessorConfigurationFlags = 0x25000063,
        Boolean_MaximizeGroupsCreated = 0x26000064,
        Boolean_ForceGroupAwareness = 0x26000065,
        Integer_GroupSize = 0x25000066,
        Integer_UseFirmwarePciSettings = 0x26000070,
        Integer_MsiPolicy = 0x25000071,
        Integer_SafeBoot = 0x25000080,
        Boolean_SafeBootAlternateShell = 0x26000081,
        Boolean_BootLogInitialization = 0x26000090,
        Boolean_VerboseObjectLoadMode = 0x26000091,
        Boolean_KernelDebuggerEnabled = 0x260000a0,
        Boolean_DebuggerHalBreakpoint = 0x260000a1,
        Boolean_UsePlatformClock = 0x260000A2,
        Boolean_ForceLegacyPlatform = 0x260000A3,
        Integer_TscSyncPolicy = 0x250000A6,
        Boolean_EmsEnabled = 0x260000b0,
        Integer_DriverLoadFailurePolicy = 0x250000c1,
        Integer_BootMenuPolicy = 0x250000C2,
        Boolean_AdvancedOptionsOneTime = 0x260000C3,
        Integer_BootStatusPolicy = 0x250000E0,
        Boolean_DisableElamDrivers = 0x260000E1,
        Integer_HypervisorLaunchType = 0x250000F0,
        Boolean_HypervisorDebuggerEnabled = 0x260000F2,
        Integer_HypervisorDebuggerType = 0x250000F3,
        Integer_HypervisorDebuggerPortNumber = 0x250000F4,
        Integer_HypervisorDebuggerBaudrate = 0x250000F5,
        Integer_HypervisorDebugger1394Channel = 0x250000F6,
        Integer_BootUxPolicy = 0x250000F7,
        String_HypervisorDebuggerBusParams = 0x220000F9,
        Integer_HypervisorNumProc = 0x250000FA,
        Integer_HypervisorRootProcPerNode = 0x250000FB,
        Boolean_HypervisorUseLargeVTlb = 0x260000FC,
        Integer_HypervisorDebuggerNetHostIp = 0x250000FD,
        Integer_HypervisorDebuggerNetHostPort = 0x250000FE,
        Integer_TpmBootEntropyPolicy = 0x25000100,
        String_HypervisorDebuggerNetKey = 0x22000110,
        Boolean_HypervisorDebuggerNetDhcp = 0x26000114,
        Integer_HypervisorIommuPolicy = 0x25000115,
        Integer_XSaveDisable = 0x2500012b
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"BcdResumeElementTypes").Type)) {
    Add-Type -TypeDefinition @'
    public enum BcdResumeElementTypes : uint
    {
        Reserved1 = 0x21000001,
        Reserved2 = 0x22000002,
        Boolean_UseCustomSettings = 0x26000003,
        Device_AssociatedOsDevice = 0x21000005,
        Boolean_DebugOptionEnabled = 0x26000006,
        Integer_BootMenuPolicy = 0x25000008
    }
'@
}

if (!(([System.Management.Automation.PSTypeName]"ApplicationObjectTypes").Type)) {
    Add-Type -TypeDefinition @'
    public enum ApplicationObjectTypes : uint
    {
        fwbootmgr = 0x10100001,
        bootmgr = 0x10100002,
        osloader = 0x10200003,
        resume = 0x10200004,
        memdiag = 0x10200005,
        ntldr = 0x10300006,
        bootsector = 0x10400008,
        startup = 0x10400009
    }
'@
}

#########################
###     BcdObject     ###
#########################


function Enumerate-ElementTypes {
    Param (
        [Parameter(Position=0, ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "EnumerateElementTypes" | Get-PropertyValue "Types"
}

function Enumerate-Elements {
    Param (
        [Parameter(Position=0, ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "EnumerateElements" | Get-PropertyValue "Elements"
}

function Get-Element {
        Param (
            [Parameter(Position=0)][uint32]
            $Type,

            [Parameter(ValueFromPipeLine=$true)]
            $BcdObject
    )

    $BcdObject | Invoke-Method "GetElement" "Type" $Type | Get-PropertyValue "Element"
}

function Get-ElementWithFlags {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][int]
        $Flags,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "GetElementWithFlags" "Id","Flags" $Id,$Flags | Get-PropertyValue "Element"
}

function Set-DeviceElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][int]
        $DeviceType,

        [Parameter(Position=2)][string]
        $AdditionalOptions,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $parameterNames = "Type","DeviceType","AdditionalOptions"
    $parameterValues = $Type,$DeviceType,$AdditionalOptions
    $BcdObject | Invoke-Method "SetDeviceElement" $parameterNames $parameterValues | Get-PropertyValue "ReturnValue"
}

function Set-PartitionDeviceElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][int]
        $DeviceType,

        [Parameter(Position=2)][string]
        $AdditionalOptions,

        [Parameter(Position=3)][string]
        $Path,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $parameterNames = "Type","DeviceType","AdditionalOptions","Path"
    $parameterValues = $Type,$DeviceType,$AdditionalOptions,$Path
    $BcdObject | Invoke-Method "SetPartitionDeviceElement" $parameterNames $parameterValues | Get-PropertyValue "ReturnValue"
}

function Set-PartitionDeviceElementWithFlags {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][int]
        $DeviceType,

        [Parameter(Position=2)][string]
        $AdditionalOptions,

        [Parameter(Position=3)][string]
        $Path,

        [Parameter(Position=4)][int]
        $Flags,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $parameterNames = "Type","DeviceType","AdditionalOptions","Path","Flags"
    $parameterValues = $Type,$DeviceType,$AdditionalOptions,$Path,$Flags
    $BcdObject | Invoke-Method "SetPartitionDeviceElementWithFlags" $parameterNames $parameterValues | Get-PropertyValue "ReturnValue"
}

function Set-FileDeviceElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][int]
        $DeviceType,

        [Parameter(Position=2)][string]
        $AdditionalOptions,

        [Parameter(Position=3)][string]
        $Path,

        [Parameter(Position=4)][uint32]
        $ParentDeviceType,

        [Parameter(Position=5)][string]
        $ParentAdditionalOptions,

        [Parameter(Position=6)][string]
        $ParentPath,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $parameterNames = "Type","DeviceType",
    "AdditionalOptions","Path","ParentDeviceType",
    "ParentAdditionalOptions","ParentPath"
    $parameterValues = $Type,$DeviceType,$AdditionalOptions,$Path,
    $ParentDeviceType,$ParentAdditionalOptions,$ParentPath
    $BcdObject | Invoke-Method "SetFileDeviceElement" $parameterNames $parameterValues | Get-PropertyValue "ReturnValue"
}

function Set-QualifiedPartitionDeviceElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][int]
        $PartitionStyle,

        [Parameter(Position=2)][string]
        $DiskSignature,

        [Parameter(Position=3)][string]
        $PartitionIdentifier,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $parameterNames = "Type","PartitionStyle",
    "DiskSignature","PartitionIdentifier"
    $parameterValues = $Type,$PartitionStyle,$DiskSignature,$PartitionIdentifier
    $BcdObject | Invoke-Method "SetQualifiedPartitionDeviceElement" $parameterNames $parameterValues | Get-PropertyValue "ReturnValue"
}

function Set-VhdDeviceElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][string]
        $Path,

        [Parameter(Position=2)][uint32]
        $ParentDeviceType,

        [Parameter(Position=3)][string]
        $ParentAdditionalOptions,

        [Parameter(Position=4)][string]
        $ParentPath,

        [Parameter(Position=5)][uint32]
        $CustomLocate,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $parameterNames = "Type","Path","ParentDeviceType",
    "ParentAdditionalOptions","ParentPath","CustomLocate"
    $parameterValues = $Type,$Path,$ParentDeviceType,
                       $ParentAdditionalOptions,$ParentPath,$CustomLocate
    $BcdObject | Invoke-Method "SetVhdDeviceElement" $parameterNames $parameterValues | Get-PropertyValue "ReturnValue"
}

function Set-StringElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][string]
        $String,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "SetStringElement" "Type","String" $Type,$String | Get-PropertyValue "ReturnValue"
}

function Set-ObjectElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][string]
        $Id,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "SetObjectElement" "Type","Id" $Type,$Id | Get-PropertyValue "ReturnValue"
}

function Set-ObjectListElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)]
        $Ids,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "SetObjectListElement" "Type","Ids" $Type,$Ids | Get-PropertyValue "ReturnValue"
}

function Set-IntegerElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)]
        $Integer,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "SetIntegerElement" "Type",
    "Integer" $Type,$Integer | Get-PropertyValue "ReturnValue"
}
    
function Set-IntegerListElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)]
        $Integers,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "SetIntegerListElement" "Type",
    "Integers" $Type,$Integers | Get-PropertyValue "ReturnValue"
}

function Set-BooleanElement {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][bool]
        $Boolean, 

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "SetBooleanElement" "Type",
    "Boolean" $Type,$Boolean | Get-PropertyValue "ReturnValue"
}

function Delete-Element {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Invoke-Method "DeleteElement" "Type" $Type | Get-PropertyValue "ReturnValue"
}


########################
###     BcdStore     ###
########################


 function Get-FilePath {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Get-PropertyValue "FilePath"
 }

function Open-Store {
    Param (
        [Parameter(Position=0)][string]
        $File="", 

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "OpenStore" "File" $File | Get-PropertyValue "Store"
}

function Import-Store {
    Param (
        [Parameter(Position=0)][string]
        $File,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    ####! This will overwrite the current system store--use with caution! ####
    $BcdStore | Invoke-Method "ImportStore" "File" $File | Get-PropertyValue "ReturnValue"
}

function Import-StoreWithFlags {
    Param (
        [Parameter(Position=0)][string]
        $File,

        [Parameter(Position=1)][int]
        $Flags=0,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "ImportStoreWithFlags" "File","Flags" $File,$Flags | Get-PropertyValue "ReturnValue"
}

function Export-Store {
    Param (
        [Parameter(Position=0)][string]$File, 
        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]$BcdStore
    )

    $BcdStore | Invoke-Method "ExportStore" "File" $File | Get-PropertyValue "ReturnValue"
}

function Create-Store {
    Param (
        [Parameter(Position=0)][string]
        $File,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "CreateStore" "File" $File | Get-PropertyValue "Store"
}

function Delete-SystemStore {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "DeleteSystemStore" | Get-PropertyValue "ReturnValue"
}

function Get-SystemDisk {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "GetSystemDisk" | Get-PropertyValue "Disk"
}

function Get-SystemPartition {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method 
    "GetSystemPartition" | Get-PropertyValue "Partition"
}

function Set-SystemStoreDevice {
    Param (
        [Parameter(Position=0)]
        $Partition,

        [Parameter(Mandatory=$true, Position=2, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method 
    "SetSystemStoreDevice" | Get-PropertyValue "ReturnValue"
}

function Enumerate-Objects {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "EnumerateObjects" "Type" $Type | Get-PropertyValue "Objects"
}

function Open-Object {
    Param (
        [Parameter(Position=0)][string]
        $Id,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "OpenObject" "Id" $Id | Get-PropertyValue "Object"
}

function Create-Object {
    Param (
        [Parameter(Position=0)][uint32]
        $Type,

        [Parameter(Position=1)][string]
        $Id,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "CreateObject" "Id","Type" $Id,$Type | Get-PropertyValue "Object"
}

function Delete-Object {
    Param (
        [Parameter(Position=0)][string]
        $Id,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "DeleteObject" "Id" $Id | Get-PropertyValue "ReturnValue"
}

function Copy-Object {
    Param (
        [Parameter(Position=0)][string]
        $SourceStoreFile,

        [Parameter(Position=1)][string]
        $SourceId,

        [Parameter(Position=2)][int]
        $Flags,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "CopyObject" "SourceStoreFile",
    "SourceId","Flags" 
    $SourceStoreFile,$SourceId,$Flags | Get-PropertyValue "Object"
}

function Copy-Objects {
    Param (
        [Parameter(Position=0)][string]
        $SourceStoreFile, 

        [Parameter(Position=1)][uint32]
        $Type,

        [Parameter(Position=2)][int]
        $Flags,

        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        $BcdStore
    )

    $BcdStore | Invoke-Method "CopyObjects" "SourceStoreFile",
    "Type","Flags" 
    $SourceStoreFile,$Type,$Flags | Get-PropertyValue "ReturnValue"
}


#################################
###     Other Bcd Objects     ###
#################################

function Get-StoreFilePath {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdObject
        )

    $BcdObject | Get-PropertyValue "StoreFilePath"
}

function Get-Id {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Get-PropertyValue "Id"
}

function Get-Type {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Get-PropertyValue "Type"
}

function Get-Path {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Get-PropertyValue "Path"
}

function Get-ElementProperty {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Get-PropertyValue "Element"
}

function Get-Parent {
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdObject
    )

    $BcdObject | Get-PropertyValue "Parent"
}

function Get-ObjectId {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdElement
    )

    $BcdElement | Get-PropertyValue "ObjectId"
}

function Get-Data {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdDeviceUnknownData
    )

    $BcdDeviceUnknownData | Get-PropertyValue "Data"
}

function Get-Device {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdDeviceElement
    )

    $BcdDeviceElement | Get-PropertyValue "Device"
}

function Get-DeviceType {
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdDeviceData
    )

    $BcdDeviceData | Get-PropertyValue "DeviceType"
}

function Get-AdditionalOptions {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdDeviceData
    )

    $BcdDeviceData | Get-PropertyValue "AdditionalOptions"
}

function Get-PartitionStyle {
    Param (
        [Parameter(Mandatory=$true, Position=0,ValueFromPipeLine=$true)]
        $BcdDeviceQualifiedPartitionData
    )

    $BcdDeviceQualifiedPartitionData | Get-PropertyValue "PartitionStyle"
}

function Get-DiskSignature {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdDeviceQualifiedPartitionData
    )

    $BcdDeviceQualifiedPartitionData | Get-PropertyValue "DiskSignature"
}

function Get-PartitionIdentifier {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdDeviceQualifiedPartitionData
    )

    $BcdDeviceQualifiedPartitionData | Get-PropertyValue "PartitionIdentifier"
}

function Get-String {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdStringElement
    )

    Get-PropertyValue "String" -Object $BcdStringElement
}

function Get-Ids {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdObjectListElement
    )

    Get-PropertyValue "Ids" -Object $BcdObjectListElement
}

function Get-Integer {
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdIntegerElement
    )

    Get-PropertyValue "Integer" -Object $BcdIntegerElement
}

function Get-Integers {
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdIntegerListElement
    )

    Get-PropertyValue "Integers" -Object $BcdIntegerListElement
}

function Get-Boolean {
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdBooleanElement
    )

    Get-PropertyValue "Boolean" -Object $BcdBooleanElement
}

function Get-ActualType {
    Param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeLine=$true)]
        $BcdUnknownElement
    )

    Get-PropertyValue "ActualType" -Object $BcdUnknownElement
}
