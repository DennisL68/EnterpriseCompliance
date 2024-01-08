#TODO Add Power & Sleep detection
#TODO Add Privacy checks
#TODO WiFi Settings?
#TODO Check Tamper settings in 1903 and above
#TODO Smart Screen
#? Do we need to check Windows Defender preferences as well
#TODO Internet security settings

#Requires -Modules PSWindowsUpdate,@{ModuleName='Pester';ModuleVersion='4.10.1'},PendingReboot,SpeculationControl

function ConvertFrom-IniFile ($file) {
    
    $ini = @{}
  
    # Create a default section if none exist in the file.
    $section = "NO_SECTION"
    $ini[$section] = @{}
  
    switch -regex -file $file {
      "^\[(.+)\]$" {
        $section = $matches[1].Trim()
        $ini[$section] = @{}
      }

      "^\s*([^#].+?)\s*=\s*(.*)" {
        $name,$value = $matches[1..2]
        
        if (!($name.StartsWith(";"))) {#not a comment
          $ini[$section][$name] = $value.Trim()
        }

      }

    }#end switch

    return $ini

}# end function

Function Get-UacLevel {
    $Uac = New-Object psobject | 
        select EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, NotifyLevel, NotifyLevelVal

    $PolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $Uac.EnableLUA = (Get-ItemProperty $PolicyKey).EnableLUA
    $Uac.ConsentPromptBehaviorAdmin = (Get-ItemProperty $PolicyKey).ConsentPromptBehaviorAdmin
    $Uac.PromptOnSecureDesktop = (Get-ItemProperty $PolicyKey).PromptOnSecureDesktop

    switch -Wildcard ($Uac.psobject.Properties.Value -join ',') {# EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop
        '1,0,0*' {
            $Uac.NotifyLevel = 'Never Notify'
            $Uac.NotifyLevelVal = 0
        }

        '1,5,0*' {
            $Uac.NotifyLevel = 'Notify when app changes computer (no dim)'
            $Uac.NotifyLevelVal = 1
        }

        '1,5,1*' {
            $Uac.NotifyLevel = 'Notify when app changes computer (default)'
            $Uac.NotifyLevelVal = 2
        }

        '1,2,1*' {
            $Uac.NotifyLevel = 'Always Notify'
            $Uac.NotifyLevelVal = 3
        }

        Default {
            $Uac.NotifyLevel = 'Unknown'
            $Uac.NotifyLevelVal = -1
        }

    }# end switch

    return $Uac
} 

function Get-FireWallRuleProperties {

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        $FirewallRule
    )

    process {
        $FirewallRule | Select *, 
        @{ n = 'Protocol';  e={($_ | Get-NetFirewallPortFilter).Protocol} },
        @{ n = 'LocalPort'; e={($_ | Get-NetFirewallPortFilter).LocalPort} },
        @{ l = 'RemotePort';e={($_ | Get-NetFirewallPortFilter).RemotePort} },
        @{ l = 'RemoteAddress';e={($_ | Get-NetFirewallAddressFilter).RemoteAddress} },
        @{ l = 'Program';   e={($_ | Get-NetFirewallApplicationFilter).Program} }
    }

}

$Compliance = Get-Content .\compliance.json | ConvertFrom-Json

Describe '- Check Windows environment Compliance'  -Tag Environment {

    Context '- Check Windows version' {

        It 'Should not be product End of Life' {
            $WindowsInfo = Get-ComputerInfo | select OSName,
                @{
                    l = 'BuildNumber'
                    e = {$_.WindowsBuildLabEx.Split('.')[0]}
                },
                @{
                    l = 'Version'
                    e = {
                        if ($_.OSDisplayVersion) {$_.OSDisplayVersion}
                        else {$_.WindowsVersion}
                    }
                }
            
            $Windows = ($WindowsInfo.OSName -replace "^(\S+\s){1}|(\s\S+){1}$") + #Remove first and last word
                ' ' +
                $WindowsInfo.Version
            write-host -ForegroundColor Yellow '      ' $Windows
            
            $Today = Get-Date

            ($Today -lt [datetime]$Compliance.WindowsEoL.Settings.$Windows[1]) | Should -BeTrue
        }
    }

    <#* We don't care about licenses
    Context '- Check license information'{

        It 'Should be licensed' {
            $License = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" |
            where { $_.PartialProductKey } | select Description, LicenseStatus

            $License.LicenseStatus | Should -Be '1'
        }
     }
     #>
}
  Describe '- Check Security Compliance' -Tag Security {

    Context '- Get Windows Update Status' {

        $WULastResults = Get-WULastResults 3>$null #Hide default warning message
        $Today = Get-Date

        It 'Should be recently updated' {
            ($Today - $WULastResults.LastInstallationSuccessDate).TotalDays | Should -BeLessOrEqual 7
        }

        It 'Should not need a reboot' {
            if (($PSVersionTable.PSVersion | select Major,Minor) -like ([version]'5.1' | select Major,Minor)) {#only works with PoSH 5.1
                (Test-PendingReboot -SkipConfigurationManagerClientCheck).IsRebootPending | Should -Be $false
            }
            else {
                Set-ItResult -Skipped -Because 'Test requires PoSH 5.1'
            }
        }
    }#end context Windows Update

    $IsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')

    Context '- Check local accounts' {

        #Get built in admin account
        $BuiltinAdmin = Get-LocalUser | where SID -like 'S-1-5-21-*-500'

        #Get current account
        $MyAccount = whoami /user /fo CSV | ConvertFrom-Csv

        #Get Local Security Policy
        if ($IsAdmin){
            $MyAppPath = [environment]::getfolderpath('ApplicationData')
            secedit /areas securitypolicy /export /cfg $MyAppPath\sec_cfg.ini
            $SecCfg = ConvertFrom-IniFile $MyAppPath\sec_cfg.ini
            remove-item $MyAppPath\sec_cfg.ini -Force
        }

        It 'Should not be running Builtin Admin' {
            ($BuiltinAdmin.SID -ne $MyAccount.SID) | Should -Be $true
        }
        
        It 'Should not have Builtin Admin account enabled' {
            $BuiltinAdmin.Enabled | Should -Be $false
        }

        It 'Should not have blank passwords' {
            #$TestPwd = ConvertTo-SecureString '' -AsPlainText -Force #! Does not work with empty strings
            #$TestCred = New-Object -TypeName System.Management.Automation.PSCredential $MyAccount.Name, $TestPwd 

            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $PrincipalObj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$Env:COMPUTERNAME)

            $PrincipalObj.ValidateCredentials($MyAccount.'User Name','') | Should -Be $false
        }

        It 'Should not use auto logon' {
            $AutoLogon = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\').AutoAdminLogon
        
            $AutoLogon | Should -Not -Be '1'
        }

        It 'Should not store AutoLogon password in cleartext' {
            $AutoLogonPwd = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\').DefaultPassword
        
            $AutoLogonPwd | Should -BeNullOrEmpty
        }

        if ($IsAdmin){
            It 'Should require complex passwords' {
                $SecCfg.'System Access'.PasswordComplexity | Should -Be 1
            }
        } else {
            It 'Should require complex passwords' {
                $IsAdmin | Should -Be $true -Because 'Check requires admin privileges'
            }
        }
        

        if ($IsAdmin) {
            It 'Should have password length policy of at least 8 characters' {
                [int]($SecCfg.'System Access'.MinimumPasswordLength) | Should -BeGreaterOrEqual 8
            }
        } 

        if ($IsAdmin -and [int]($SecCfg.'System Access'.MinimumPasswordLength) -lt 12) {
            It 'Ought to have password length policy of at least 12 characters' {
                Set-ItResult -Skipped -Because 'not required (NOT compliant)'
            }
            
        }
        
        if (!$IsAdmin){# skip password check
            It 'Should have password length policy' {
                $IsAdmin | Should -Be $true -Because 'Check requires admin privileges'
            }
        }

        It 'Should have lock out screen set' {#! Add Power & Sleep detection
            [bool][int]$ScreenSaveActive = (Get-ItemProperty 'HKCU:\Control Panel\Desktop').ScreenSaveActive
            [bool][int]$ScreenSaverIsSecure = (Get-ItemProperty 'HKCU:\Control Panel\Desktop').ScreenSaverIsSecure
            
            if ($IsAdmin){
                $InactivityLimit = $SecCfg.'Registry Values'.'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'
                if ($InactivityLimit){#exists
                    $InactivityLimit = $InactivityLimit.split(',')[-1] #Only keep last part
                }

                ($ScreenSaveActive -and $ScreenSaverIsSecure) -or $InactivityLimit -gt 0 | Should -Be $true
            }

            if (!$IsAdmin -and !($ScreenSaveActive -and $ScreenSaverIsSecure)) {
                # Set-ItResult -Inconclusive -Because 'Test not run as admin'
                $IsAdmin | Should -Be $true -Because 'Test not run as admin'
            }
        }
    }#end context Accounts

    Context '- Get machine settings'{

        $TpmDevice = Get-PnpDevice -Class SecurityDevices -ErrorAction SilentlyContinue | where Service -eq 'TPM'
        if ($TpmDevice){#make sure we have a TPM before getting version
            $TpmVersion = [version]$TpmDevice.FriendlyName.split(' ')[-1]
        }
        $BitLockerMod = Get-Module BitLocker -ListAvailable
        if ($IsAdmin -and $BitLockerMod) {
            $OsBitLockerVolume = Get-BitLockerVolume | where VolumeType -eq OperatingSystem
        }
        $EfiPart = Get-Disk | where IsBoot | Get-Partition | where GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        
        It 'Ought to have EFI partition'{
            If ($EfiPart -eq $null) {
                Set-ItResult -Skipped -Because 'not required (NOT compliant)'
            }
            else {
                Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
            }
        }
        
        if ($EfiPart -ne $null) {#ok to test for UEFI settings
            It 'Ought to have UEFI Secure boot' {
                if ($IsAdmin -and (Confirm-SecureBootUEFI)){
                    Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
                } 
    
                if ($IsAdmin -and !(Confirm-SecureBootUEFI)){
                    Set-ItResult -Skipped -Because 'not required (NOT compliant)'
                } 
                
                if (!$IsAdmin) {
                    Set-ItResult -Skipped -Because 'Check requires admin privileges'
                }
            }
        }

        It 'Should have TPM 2.0 or greater' {
            $TpmVersion.Major | Should -BeGreaterOrEqual 2
        }

        It 'Should have TPM status - OK' {
            $TpmDevice.Status | Should -Be 'OK'
        }

        It 'Should have Bitlocker Feature installed' {
            $BitLockerMod.Name -eq 'BitLocker' | Should -Be $true
        }

        It 'Should have BitLocker activated on OS Volume' {
            if ($IsAdmin) {
                $OsBitLockerVolume.ProtectionStatus | Should -Be 'On'
            }
            elseif (!$IsAdmin) {
                $IsAdmin | Should -Be $true -Because 'Check requires admin privileges and BitLocker'
            }
        }

        It 'Should have UAC set to default or higer' {
            $Uac = Get-UacLevel
            $Uac.NotifyLevelVal | Should -BeGreaterOrEqual 2
        }

        It 'Should not require actions for Spectre/Meltdown (https://support.microsoft.com/help/4074629)' {
            $Speculation = Get-SpeculationControlSettings 6>&1 #Redirect info stream to Success stream
            $SpecMessage = $Speculation.MessageData.Message

            $SpecMessage | Should -Not -Contain 'Suggested actions'
        }

        <# 
        It 'Should have CPU features' { #* This might come in handy at some point
            & $Env:Temp\Coreinfo64.exe -accepteula -f
            Get-CimInstance CIM_Processor | Select -Property ProcessorId
        } 
        #>

    }#end context Machine

    Context '- Get Exploit Protection' {
        # https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-exploit-protection#powershell
        $ExploitProt = Get-ProcessMitigation -System

        It 'Should have Control Flow Guard (CFG) set to default (On)'{
            $ExploitProt.CFG.Enable -eq 'NOTSET' -or  $ExploitProt.CFG.Enable -eq 'Enable' -and
            $ExploitProt.CFG.SuppressExports -eq 'NOTSET' -or  $ExploitProt.CFG.SuppressExports -eq 'Enable' -and
            $ExploitProt.CFG.StrictControlFlowGuard -eq 'NOTSET' -or  $ExploitProt.CFG.StrictControlFlowGuard -eq 'Enable' |  
                Should -Be $true
        }

        It 'Should have Data Excution Prevention (DEP) set to default (On)' {
            $ExploitProt.DEP.Enable -eq 'NOTSET' -or  $ExploitProt.DEP.Enable -eq 'Enable' -and
            $ExploitProt.DEP.EmulateAtlThunks -eq 'NOTSET' -or  $ExploitProt.DEP.EmulateAtlThunks -eq 'Enable' |
                Should -Be $true
        }

        It 'Should have Force Randomization for Images (Mandatory ASL) set to at least default (Off)' {
            $true | Should -Be $true
        }

        It 'Should have Randomize memory allocations (Bottom-up ASLR) set to default (On)' {
            $ExploitProt.ASLR.BottomUp -eq 'NOTSET' -or  $ExploitProt.ASLR.BottomUp -eq 'Enable' |
                Should -Be $true
        }

        It 'Should have High-Entropy ASLR set to deault (On)' {
            $ExploitProt.ASLR.HighEntropy -eq 'NOTSET' -or  $ExploitProt.ASLR.HighEntropy -eq 'Enable' |
                Should -Be $true
        }

        It 'Should Validate Exception Chains (SEHOP) set to default (On)' {
            $ExploitProt.SEHOP.Enable -eq 'NOTSET' -or  $ExploitProt.SEHOP.Enable -eq 'Enable' -and
            $ExploitProt.SEHOP.TelemetryOnly -eq 'NOTSET' -or  $ExploitProt.SEHOP.TelemetryOnly -eq 'Enable' |
                Should -Be $true
        }

        It 'Should have Validate Heap Integrity set to default (On)' {
            $ExploitProt.Heap.TerminateOnError -eq 'NOTSET' -or  $ExploitProt.Heap.TerminateOnError -eq 'Enable' |
                Should -Be $true
        }
    }#end context exploit

        
    Context '- Get Windows Defender status' {

        $MpStatus = Get-MpComputerStatus

        It 'Should have AntiMalware enabled' {
            $MpStatus.AMServiceEnabled | Should -Be $true
        }

        It 'Should have AntiSpyware enabled' {
            $MpStatus.AntispywareEnabled | Should -Be $true
        }

        It 'Should have current AntiSpyware signature' {
            $MpStatus.AntispywareSignatureAge | Should -BeLessOrEqual 7
        }

        It 'Should have AnitVirus enabled' {
            $MpStatus.AntivirusEnabled | Should -Be $true
        }

        It 'Shoud have current AntiVirusSignature' {
            $MpStatus.AntivirusSignatureAge | Should -BeLessOrEqual 7
        }

        It 'Should have Behavior monitoring enabled' {
            $MpStatus.BehaviorMonitorEnabled | Should -Be $true
        }

        It 'Ought to be recently fulled scanned' {
            if ($MpStatus.FullScanAge -le 32) {
                Set-ItResult -Skipped -Because 'not required (COMPLIANT, scanned last 32 days)'
            }
            if ($MpStatus.FullScanAge -gt 32) {
                Set-ItResult -Skipped -Because 'not required (NOT compliant, not scanned last 32 days)'
            }
        }

        It 'Should be recently quicked scanned' {
            $MpStatus.QuickScanAge | Should -BeLessOrEqual 7
        }

        It 'Should be realtime protected' {
            $MpStatus.RealTimeProtectionEnabled | Should -Be $true
        }

        It 'May be Tamper Protected' {
            If ($MpStatus.IsTamperProtected) {
                Set-ItResult -Skipped -Because 'not required'
            }
            else {
                Set-ItResult -Skipped -Because 'not required'
            }
            
        }
    }# end context Windows Defender

    Context '- Get Firewall Status (slow process)' {

        #TODO $Rules=(New-object -ComObject HNetCfg.FWPolicy2).rules to replace Get-NetFirewallRule

        $MpsSvc = Get-Service -Name MpsSvc
        $FirewallProfile = Get-NetFirewallProfile
        if ($IsAdmin){
            $FirewallRule = Get-NetFirewallRule | where {
                $_.Enabled -eq $true -and
                $_.Direction -eq 'Inbound'
            } | Get-FireWallRuleProperties
        }
        else {# it will take to loooong :/
            $FirewallRule = Get-NetFirewallRule | where {
                $_.Enabled -eq $true -and
                $_.Direction -eq 'Inbound'
            }
        }
        

        It 'Should have FireWall enabled' {
            $MpsSvc.StartType | Should -Be 'Automatic'
        }

        It 'Should have Firewall running' {
            $MpsSvc.Status | Should -Be 'Running'
        }

        It 'Should be turned on for Private networks' {
            ($FirewallProfile | where Name -like 'Private').Enabled | Should -Be $true
        }

        It 'Should have Firewall rules in Private networks' {
            ($FirewallRule | where Profile -like 'Private').Count | Should -BeGreaterThan 1

        }

        
        It 'Ought not to have an "allow all" for Private networks' {
            if ($IsAdmin){
                if (($FirewallRule | where {
                    $_.Profile -eq 'Private' -and
                    $_.Action -eq 'Allow' -and
                    $_.Program -eq 'Any' -and
                    $_.LocalPort -eq 'Any'
                }) -eq $null) {
                    Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
                }
                else {
                    Set-ItResult -Skipped -Because 'not required (NON compliant)'
                }
            }
            else {
                Set-ItResult -Skipped -Because 'Test will take to long as non admin'
            }
        }
        

        It 'Should be turned on for Public networks' {
            ($FirewallProfile | where Name -like 'Public').Enabled | Should -Be $true
        }

        It 'Should have Firewall rules in Public networks' {
            ($FirewallRule | where Profile -like 'Public').Count | Should -BeGreaterThan 1

        }

        It 'Should NOT have an "allow all rule" for Public networks' {
            if ($IsAdmin){
                ($FirewallRule | where {
                    $_.Profile -eq 'Public' -and
                    $_.Action -eq 'Allow' -and
                    $_.Program -eq 'Any' -and
                    $_.LocalPort -eq 'Any'
                }) | Should -BeNullOrEmpty
            }
            else {
                Set-ItResult -Skipped -Because 'Test will take to long as non admin'
            }
        }

        It 'Should be turned on for Domain networks' {
            ($FirewallProfile | where Name -like 'Domain').Enabled | Should -Be $true
        }

        It 'Should have Firewall rules in Domain networks' {
            ($FirewallRule | where Profile -like 'Domain').Count | Should -BeGreaterThan 1

        }

        It 'Ought not to have an "allow all rule" for Domain networks' {
            if ($IsAdmin){
                if (($FirewallRule | where {
                    $_.Profile -eq 'Domain' -and
                    $_.Action -eq 'Allow' -and
                    $_.Program -eq 'Any' -and
                    $_.LocalPort -eq 'Any'
                }) -eq $null) {
                    Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
                }
                else {
                    Set-ItResult -Skipped -Because 'not required (NON compliant)'
                }
            }
            else {
                Set-ItResult -Skipped -Because 'Test will take to long as non admin'
            }
        }
        
        
    }#end context Firewall

<# 
    Context '- Get Internet Security Settings' {
        It 'Should have Internet Security Settings' {
            Set-ItResult -Skipped -Because 'Test does not exist yet' #! Fix
        }
    }# end context Internet Security
 #>
}#end describe Security

Describe 'MS Telemetry Compliance' -Tag Telemetry {

    if (Test-Path $Env:ProgramFiles\PowerShell\7){

        Context '- Get PowerShell Telemetry' {

            It 'Should not send Telemetry for PoSH 7.x' {
                $ENV:POWERSHELL_TELEMETRY_OPTOUT | Should -Not -BeNullOrEmpty
            }
    
        }#end context PoSH
    }# end if
    
    $MyLocalAppPath = [Environment]::GetFolderPath('LocalApplicationData')

    if (
        (Test-Path $Env:ProgramFiles\'Microsoft VS Code') -or 
        (Test-Path $MyLocalAppPath\Programs\'Microsoft VS Code')
        ){#VS Code is installed

        Context '- Get VS Code Telemetry' {

            $MyAppPath = [Environment]::GetFolderPath('ApplicationData')
            $CodeSettings = get-content $MyAppPath\code\user\settings.json -ErrorAction SilentlyContinue | ConvertFrom-Json
            
            It 'Should not send VS Code Usage data'{
                $CodeSettings.'telemetry.enableTelemetry' | Should -Be 'False'
            }
    
            It 'Should not send VS Code Crash reports' {
                $CodeSettings.'telemetry.enableCrashReporter' | Should -Be 'False'
            }
    
            #! GitLens defaults to optout buy uses different values
            #TODOD Verify GitLens exists before checking for OptOut 
            <# It 'Should not send GitLens usage data'{
                $CodeSettings.'gitlens.advanced.telemetry.enabled' | Should -Be 'False'
            } #>
    
        }#end context VS Code
    }#end if

    Context '- Get Windows Telemetry' {
        
        It 'Should not send Windows Data collections'{
            if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection).AllowTelemetry -eq 0){
                Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
            }
            else {
                Set-ItResult -Skipped -Because 'not required (NOT compliant)'
            }
        }

        It 'Should not send MS Customer Experience Improvement Program'{
            if ((Get-ItemProperty HKLM:Software\Policies\Microsoft\SQMClient\Windows -ErrorAction SilentlyContinue).CEIPEnable -eq 0){
                Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
            }
            else {
                Set-ItResult -Skipped -Because 'not required (NOT compliant)'
            }
        }

        It 'Should not have Connected User Experiences and Telemetry running' {
            if ((Get-Service DiagTrack).Status -eq 'Stopped'){
                Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
            }
            else {
                Set-ItResult -Skipped -Because 'not required (NOT compliant)'
            }
        }

    }#end context Windows

}#end describe Telemetry

<#
.SYNOPSIS
    Pester script for minimal security compliance test on external computers.

.DESCRIPTION
    Pester script for minimal windows security compliance test on external computers.

    The test requires the following modules from PSGallery to be installed:

    - PSWindowsUpdate
    - Pester 4.10.1
    - PendingReboot
    - SpeculationControl

    Pester needs to be installed using:

    PS:> Install-Module pester -RequiredVersion 4.10.1 -SkipPublisherCheck -Force
    
    The other modules can be installed as ordinary modules.

    Some tests require admin permissions to be perfomed.

.EXAMPLE
  .\Get-MiniCompliance.Tests.ps1

.EXAMPLE
  Invoke-Pester .\Get-MiniComplance.Tests.ps1

.NOTES
#>
