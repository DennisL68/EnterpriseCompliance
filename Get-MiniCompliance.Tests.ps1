#TODO Add Power & Sleep detection
#TODO Add Privacy checks
#TODO WiFi Settings?
#TODO Check Tamper settings in 1903 and above
#TODO Smart Screen
#? Do we need to check Windows Defender preferences as well
#TODO Internet security settings

#Requires -Modules PSWindowsUpdate,@{ModuleName='Pester';ModuleVersion='4.10.1'},PendingReboot,SpeculationControl

#region functions
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

function Get-UacLevel {
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

function Get-FireWallRuleProperty {

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

#endregion functions

$Compliance = Get-Content .\compliance.json | ConvertFrom-Json

if (Test-Path ~\compliance.json) {
    $Compliance = Get-Content ~\compliance.json | ConvertFrom-Json
}

$ComplianceTypes =  $Compliance |
    Get-Member -MemberType Property,NoteProperty |
        select -ExpandProperty Name

foreach ($ComplianceType in $ComplianceTypes) {# State what compliance is not defined to be checked
    if ([string]::IsNullOrEmpty($Compliance.$ComplianceType.Active)) {

        It "Test of $ComplianceType" {
            Set-ItResult -Skipped -Because 'Test param Active not defined in JSON config'
        }
    }
}

Describe '- Check Windows environment Compliance'  -Tag Environment {

    if ($Compliance.WindowsEoL.Active) {
        Context '- Check Windows version' {

            It ('Should not be product End of Life' + ' (Ext)' * $Compliance.WindowsEoL.Settings.Extended) {

                    $WindowsInfo = Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion" | select @{
                            l = 'OsName'
                            e = {$_.GetValue("ProductName")}
                    },
                    @{
                        l = 'BuildNumber'
                        e = {$_.GetValue("CurrentBuildNumber")}
                    },
                    @{
                        l = 'Version'
                        e = {
                            if ($_.GetValue("ReleaseId")) {$_.GetValue("ReleaseID")}
                            if ($_.GetValue("DisplayVersion")) {$_.GetValue("DisplayVersion")}
                            if (! ($_.GetValue("ReleaseId") -or $_.GetValue("DisplayVersion")) ) {$_.GetValue("CurrentVersion")}
                        }
                    }

                    $Windows = ($WindowsInfo.OSName -replace "(\s\S+){1}$") + #Remove last word
                        ' ' +
                        $WindowsInfo.Version
                    write-host -ForegroundColor Yellow '      ' $Windows

                    $Today = Get-Date

                    if ($Compliance.WindowsEoL.Settings.Extended) {
                        $EndDate = [datetime]($Compliance.WindowsEoL.EndDates.$Windows[1..3] | Measure-Object -Maximum).Maximum
                    } else {
                        $EndDate = [datetime]$Compliance.WindowsEoL.EndDates.$Windows[1]
                    }

                    $Today -lt $EndDate | Should -BeTrue
            }

        }
    }


    if ($Compliance.WindowsLicense.Active) {
        Context '- Check license information'{

            It 'Should be licensed' {
                $License = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL" |
                where Name -like 'Windows*' | select Description, LicenseStatus

                $License.LicenseStatus | Should -Be '1'
            }
        }
    }
}

Describe '- Check Security Compliance' -Tag Security {

    if ($Compliance.WindowsUpdate.Active) {
        Context '- Get Windows Update Status' {

            $WULastResults = Get-WULastResults 3>$null #Hide default warning message
            $Today = Get-Date

            It "Should be updated during the last $($Compliance.WindowsUpdate.Settings.LastInstallMaxAge) days" {
                [int]($Today - $WULastResults.LastInstallationSuccessDate).TotalDays |
                    Should -BeLessOrEqual $Compliance.WindowsUpdate.Settings.LastInstallMaxAge
            }

            It 'Should not have a pending reboot' {
                if (($PSVersionTable.PSVersion | select Major,Minor) -like ([version]'5.1' | select Major,Minor)) {#only works with PoSH 5.1
                    (Test-PendingReboot -SkipConfigurationManagerClientCheck).IsRebootPending |
                        Should -Be $Compliance.WindowsUpdate.Settings.HavePendingReboot
                }
                else {
                    Set-ItResult -Skipped -Because 'Test requires PoSH 5.1'
                }
            }
        }#end context Windows Update
    }

    if ($Compliance.UserAccount.Active) {
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

            It ('Should check running as Builtin Admin') {
                ($BuiltinAdmin.SID -ne $MyAccount.SID) |
                    Should -Be $Compliance.UserAccount.Settings.IsNotBuiltInAdmin
            }

            It ('Should check Builtin Admin account being enabled') {
                -not $BuiltinAdmin.Enabled |
                    Should -Be $Compliance.UserAccount.Settings.BuiltInAdminDisabled
            }

            It ('Should check using blank passwords') {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $PrincipalObj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$Env:COMPUTERNAME)

                -not $PrincipalObj.ValidateCredentials($MyAccount.'User Name','') |
                    Should -Be $Compliance.UserAccount.Settings.NotUsingBlankPassword
            }

            It ('Should check using Auto Logon') {
                $AutoLogon = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\').AutoAdminLogon

                -not $AutoLogon -eq 1 |
                    Should -Be $Compliance.UserAccount.Settings.AutoLogonDisabled
            }

            It ('Should check storing AutoLogon password') {
                $AutoLogonPwd = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\').DefaultPassword

                [string]::IsNullOrEmpty($AutoLogonPwd) |
                    Should -Be $Compliance.UserAccount.Settings.AutoLogonDisabled
            }

            if ($IsAdmin){
                It ('Should check complex password requirement') {
                    $SecCfg.'System Access'.PasswordComplexity -eq 1 |
                        Should -Be $Compliance.UserAccount.Settings.RequireComplexPassword
                }
            } else {
                It 'Should check complex password requirement' {
                    $IsAdmin | Should -Be $true -Because 'Check requires admin privileges'
                }
            }


            if ($IsAdmin) {
                It "Should check password length policy setting" {
                    [int]($SecCfg.'System Access'.MinimumPasswordLength) |
                        Should -BeGreaterOrEqual $Compliance.UserAccount.Settings.MinimumPasswordLength
                    # Should -BeGreaterOrEqual 8
                }
            }

            if (!$IsAdmin){# skip password check
                It 'Should check password length policy setting' {
                    $IsAdmin | Should -Be $true -Because 'Check requires admin privileges'
                }
            }

            It ('Should check lock out screen setting') {#! Add Power & Sleep detection
                [bool][int]$ScreenSaveActive = (Get-ItemProperty 'HKCU:\Control Panel\Desktop').ScreenSaveActive
                [bool][int]$ScreenSaverIsSecure = (Get-ItemProperty 'HKCU:\Control Panel\Desktop').ScreenSaverIsSecure

                if ($IsAdmin){
                    $InactivityLimit = $SecCfg.'Registry Values'.'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'
                    if ($InactivityLimit){#exists
                        $InactivityLimit = $InactivityLimit.split(',')[-1] #Only keep last part
                    }

                    ($ScreenSaveActive -and $ScreenSaverIsSecure) -or
                    $InactivityLimit -gt 0 |
                        Should -Be $Compliance.UserAccount.Settings.LockOutScreenOn
                }

                if (!$IsAdmin -and !($ScreenSaveActive -and $ScreenSaverIsSecure)) {
                    $IsAdmin | Should -Be $true -Because 'Check requires admin privileges'
                }
            }
        }#end context Accounts
    }

    if ($Compliance.Machine.Active) {
        Context '- Get machine settings'{

            $TpmDevice = Get-PnpDevice -Class SecurityDevices -ErrorAction SilentlyContinue | where Service -eq 'TPM'
            if ($TpmDevice){#make sure we have a TPM before getting version
                $TpmVersion = [version]$TpmDevice.FriendlyName.split(' ')[-1]
            }

            $BitLockerMod = Get-Module BitLocker -ListAvailable

            if ($IsAdmin -and $BitLockerMod) {
                $OsBitLockerVolume = Get-BitLockerVolume | where VolumeType -eq OperatingSystem
            }

            It ('Should check for an EFI partition') {
                if ($IsAdmin) {
                    #$EfiPart = Get-Disk | where IsBoot | Get-Partition | where GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
                    #! Get-Disk doesn't work with Dynamic disks

                    $EfiPart = bcdedit /enum BOOTMGR | select -Index 5 | where {$_ -like '*.efi'}
                    ![string]::IsNullOrEmpty($EfiPart) | Should -Be $Compliance.Machine.Settings.EFIPartitionActive
                }
                if (!$IsAdmin) {
                    Set-ItResult -Skipped -Because 'Check requires admin privileges'
                }
            }

            It ('Should check for UEFI firmware Secure Boot') {
                If ($IsAdmin) {
                    Confirm-SecureBootUEFI | Should -Be $Compliance.Machine.Settings.UEFISecureBoot
                }
                if (!$IsAdmin) {
                    Set-ItResult -Skipped -Because 'Check requires admin privileges'
                }
            }

            It 'Should check for TPM' {
                $TpmDevice.Present | Should -Be $Compliance.Machine.Settings.HasTPM
            }

            It 'Should check TPM version' {
                if ($TpmDevice.Present) {
                    $TpmVersion -ge [version]$Compliance.Machine.Settings.LowestTPMVersion | Should -BeTrue
                }
                if (!$TpmDevice.Present) {
                    Set-ItResult -Skipped -Because 'Check requires TPM device'
                }
            }

            It 'Should check TPM status' {
                if ($TpmDevice.Present) {
                    $TpmDevice.Status -eq 'OK' | Should -Be $Compliance.Machine.Settings.TPMStatusIsOk
                }
                if (!$TpmDevice.Present) {
                    Set-ItResult -Skipped -Because 'Check requires TPM device'
                }
            }

            It 'Should check Bitlocker Feature installation status' {
                $BitLockerMod.Name -eq 'BitLocker' | Should -Be $Compliance.Machine.Settings.BitLockerInstalled
            }

            It 'Should check BitLocker activatation for OS Volume' {
                if ($IsAdmin) {
                    $OsBitLockerVolume.ProtectionStatus -eq 'On' -and
                    $OsBitLockerVolume.KeyProtector.KeyProtectorType -contains 'TPM' |
                        Should -Be $Compliance.Machine.Settings.BitLockerOnOSVolume
                }
                if (!$IsAdmin) {
                    $BootDrive = (Get-CimInstance Win32_Volume | where BootVolume).DriveLetter
                    $OsBitLockerProtection = (New-Object -ComObject Shell.Application).NameSpace($BootDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
                    @(1, 3, 5) -contains $OsBitLockerProtection | Should -Be $Compliance.Machine.Settings.BitLockerOnOSVolume
                }
            }

            It 'Should check BitLocker activatation for Data Volume' {
                Set-ItResult -Skipped -Because 'Test not implemented yet'
                # | Should -Be $Compliance.Machine.Settings.BitLockerOnDataVolumes
            }

            It 'Should check BitLocker PIN' {
                if (
                    $IsAdmin -and
                    $OsBitLockerVolume.ProtectionStatus -eq 'On'
                ) {
                    $OsBitLockerVolume.KeyProtector.KeyProtectorType -contains 'TpmPin' |
                        Should -Be $Compliance.Machine.Settings.BitLockerPinEnabled
                }
            }

            It 'Should check UAC level' {
                $Uac = Get-UacLevel
                $Uac.NotifyLevelVal | Should -BeGreaterOrEqual $Compliance.Machine.Settings.LowestUACLevel
            }

            It 'Should check actions for Spectre/Meltdown (https://support.microsoft.com/help/4074629)' {
                $Speculation = Get-SpeculationControlSettings 6>&1 #Redirect info stream to Success stream
                $SpecMessage = $Speculation.MessageData.Message

                -not $SpecMessage -Contains 'Suggested actions' | Should -Be $Compliance.Machine.Settings.SpectreMeltdownIsHandled
            }

            <#
            It 'Should have CPU features' { #* This might come in handy at some point
                & $Env:Temp\Coreinfo64.exe -accepteula -f
                Get-CimInstance CIM_Processor | Select -Property ProcessorId
            }
            #>

        }#end context Machine
    }

    if ($Compliance.ExploitProtection.Active) {
        Context '- Get Exploit Protection' {

            $ExploitProt = Get-ProcessMitigation -System

            It 'Should check Control Flow Guard (CFG)'{
                $ExploitProt.CFG.Enable -eq 'NOTSET' -or  $ExploitProt.CFG.Enable -eq 'Enable' -and
                $ExploitProt.CFG.SuppressExports -eq 'NOTSET' -or  $ExploitProt.CFG.SuppressExports -eq 'Enable' -and
                $ExploitProt.CFG.StrictControlFlowGuard -eq 'NOTSET' -or  $ExploitProt.CFG.StrictControlFlowGuard -eq 'Enable' |
                    Should -Be $true
            }

            It 'Should check Data Excution Prevention (DEP)' {
                $ExploitProt.DEP.Enable -eq 'NOTSET' -or  $ExploitProt.DEP.Enable -eq 'Enable' -and
                $ExploitProt.DEP.EmulateAtlThunks -eq 'NOTSET' -or  $ExploitProt.DEP.EmulateAtlThunks -eq 'Enable' |
                    Should -Be $true
            }

            It 'Should check Force Randomization for Images (Mandatory ASLR)' {
                $ExploitProt.ASLR.ForceRelocateImages -eq 'NOTSET' -or
                $ExploitProt.ASLR.ForceRelocateImages -eq 'ON' -or
                $ExploitProt.ASLR.ForceRelocateImages -eq 'OFF' |
                    Should -Be $true
            }

            It 'Should check Randomize memory allocations (Bottom-up ASLR)' {
                $ExploitProt.ASLR.BottomUp -eq 'NOTSET' -or  $ExploitProt.ASLR.BottomUp -eq 'Enable' |
                    Should -Be $true
            }

            It 'Should check High-Entropy ASLR' {
                $ExploitProt.ASLR.HighEntropy -eq 'NOTSET' -or  $ExploitProt.ASLR.HighEntropy -eq 'Enable' |
                    Should -Be $true
            }

            It 'Should check Exception Chains (SEHOP)' {
                $ExploitProt.SEHOP.Enable -eq 'NOTSET' -or  $ExploitProt.SEHOP.Enable -eq 'Enable' -and
                $ExploitProt.SEHOP.TelemetryOnly -eq 'NOTSET' -or  $ExploitProt.SEHOP.TelemetryOnly -eq 'Enable' |
                    Should -Be $true
            }

            It 'Should check Validate Heap Integrity' {
                $ExploitProt.Heap.TerminateOnError -eq 'NOTSET' -or  $ExploitProt.Heap.TerminateOnError -eq 'Enable' |
                    Should -Be $true
            }
        }#end context exploit
    }

    if ($Compliance.WinddowsDefender.Active) {
        Context '- Get Windows Defender status' {

            $MpStatus = Get-MpComputerStatus

            It 'Should check AntiMalware enabled' {
                $MpStatus.AMServiceEnabled | Should -Be $true
            }

            It 'Should check AntiSpyware enabled' {
                $MpStatus.AntispywareEnabled | Should -Be $true
            }

            It 'Should check current AntiSpyware signature' {
                $MpStatus.AntispywareSignatureAge | Should -BeLessOrEqual 7
            }

            It 'Should check AnitVirus enabled' {
                $MpStatus.AntivirusEnabled | Should -Be $true
            }

            It 'Shoud check current AntiVirusSignature' {
                $MpStatus.AntivirusSignatureAge | Should -BeLessOrEqual 7
            }

            It 'Should check Behavior monitoring enabled' {
                $MpStatus.BehaviorMonitorEnabled | Should -Be $true
            }

            It 'Should check fully scanned timeframe' {
                if ($MpStatus.FullScanAge -le 32) {
                    Set-ItResult -Skipped -Because 'not required (COMPLIANT, scanned last 32 days)'
                }
                if ($MpStatus.FullScanAge -gt 32) {
                    Set-ItResult -Skipped -Because 'not required (NOT compliant, not scanned last 32 days)'
                }
            }

            It 'Should check quicked scanned timeframe' {
                $MpStatus.QuickScanAge | Should -BeLessOrEqual 7
            }

            It 'Should check Realtime Protecteion' {
                $MpStatus.RealTimeProtectionEnabled | Should -Be $true
            }

            It 'Should check Tamper Protection' {
                If ($MpStatus.IsTamperProtected) {
                    Set-ItResult -Skipped -Because 'not required'
                }
                else {
                    Set-ItResult -Skipped -Because 'not required'
                }

            }
        }# end context Windows Defender
    }

    if ($Compliance.Firewall.Active) {
        Context '- Get Firewall Status (slow process)' {

            #TODO $Rules=(New-object -ComObject HNetCfg.FWPolicy2).rules to replace Get-NetFirewallRule

            $MpsSvc = Get-Service -Name MpsSvc
            $FirewallProfile = Get-NetFirewallProfile
            if ($IsAdmin){
                $FirewallRule = Get-NetFirewallRule | where {
                    $_.Enabled -eq $true -and
                    $_.Direction -eq 'Inbound'
                } | Get-FireWallRuleProperty
            }
            else {# it will take to loooong :/
                $FirewallRule = Get-NetFirewallRule | where {
                    $_.Enabled -eq $true -and
                    $_.Direction -eq 'Inbound'
                }
            }


            It 'Should check FireWall enabled status' {
                $MpsSvc.StartType | Should -Be 'Automatic'
            }

            It 'Should check Firewall running status' {
                $MpsSvc.Status | Should -Be 'Running'
            }

            It 'Should check Firewall status for Private networks' {
                ($FirewallProfile | where Name -like 'Private').Enabled | Should -Be $true
            }

            It 'Should check Firewall rules existence in Private networks' {
                ($FirewallRule | where Profile -like 'Private').Count | Should -BeGreaterThan 1

            }


            It 'Should check for "allow all" rules for Private networks' {
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


            It 'Should check Firewall status for Public networks' {
                ($FirewallProfile | where Name -like 'Public').Enabled | Should -Be $true
            }

            It 'Should check Firewall rules existence in Public networks' {
                ($FirewallRule | where Profile -like 'Public').Count | Should -BeGreaterThan 1

            }

            It 'Should check for "allow all" rules for Public networks' {
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

            It 'Should check Firewall status for Domain networks' {
                ($FirewallProfile | where Name -like 'Domain').Enabled | Should -Be $true
            }

            It 'Should check Firewall rules existence in Domain networks' {
                ($FirewallRule | where Profile -like 'Domain').Count | Should -BeGreaterThan 1

            }

            It 'Should check for "allow all rule" for Domain networks' {
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
    }

    if ($Compliance.InternetSecurity.Active) {}
<#
    Context '- Get Internet Security Settings' {
        It 'Should have Internet Security Settings' {
            Set-ItResult -Skipped -Because 'Test does not exist yet' #! Fix
        }
    }# end context Internet Security
 #>
}#end describe Security

Describe '- Check MS Telemetry Compliance' -Tag Telemetry {

    if ($Compliance.Telemetry.Active) {
        if (Test-Path $Env:ProgramFiles\PowerShell\7){

            Context '- Get PowerShell Telemetry' {

                It 'Should check for for PoSH 7.x Telemetry' {
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

                It 'Should check for VS Code Usage data'{
                    $CodeSettings.'telemetry.enableTelemetry' | Should -Be 'False'
                }

                It 'Should check for VS Code Crash reports' {
                    $CodeSettings.'telemetry.enableCrashReporter' | Should -Be 'False'
                }

                #! GitLens defaults to optout but uses different values
                #TODOD Verify GitLens exists before checking for OptOut
                <# It 'Should not send GitLens usage data'{
                    $CodeSettings.'gitlens.advanced.telemetry.enabled' | Should -Be 'False'
                } #>

            }#end context VS Code
        }#end if

        Context '- Get Windows Telemetry' {

            It 'Should check for Windows Data collections Telemetry'{
                if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection).AllowTelemetry -eq 0){
                    Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
                }
                else {
                    Set-ItResult -Skipped -Because 'not required (NOT compliant)'
                }
            }

            It 'Should check for MS Customer Experience Improvement Program Telemetry'{
                if ((Get-ItemProperty HKLM:Software\Policies\Microsoft\SQMClient\Windows -ErrorAction SilentlyContinue).CEIPEnable -eq 0){
                    Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
                }
                else {
                    Set-ItResult -Skipped -Because 'not required (NOT compliant)'
                }
            }

            It 'Should check for Connected User Experiences and Telemetry running' {
                if ((Get-Service DiagTrack).Status -eq 'Stopped'){
                    Set-ItResult -Skipped -Because 'not required (COMPLIANT)'
                }
                else {
                    Set-ItResult -Skipped -Because 'not required (NOT compliant)'
                }
            }

        }#end context Windows
    }

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

    Make sure to configure the compliance.json file before running the test and store it in ~.

.EXAMPLE
    .\Get-MiniCompliance.Tests.ps1

.EXAMPLE
    Invoke-Pester .\Get-MiniComplance.Tests.ps1

.NOTES
#>
