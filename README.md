# EnterpriseCompliance

## 1. Description

EnterpriseCompliance is a Pester v4 test that will show if your development rig is compliant with the 
corporation you are involved with.

Simply enter the values provided by the IT Security department in the settings file (feature not done yet) and run the test.

## 2. Requirements

The prerequisites for using the artifact of this repo is

* A Windows Computer
* PowerShell
* Pester 4.10.1
* Module PSWindowsUpdate
* Module PendingReboot 
* Module SpeculationControl

## 3. Limitations

The script can only test what the Pester script is handling. Feel free to add additional tests.

## 4. How do I use this repo?

* `Install-Module EnterpriseCompliance` (not released to PS Gallery yet)
* Install the prerequisites.
* Create the settingsjson file complaiance.json in your `~`-folder. (future version)
* `Invoke-Pester ...` as administrator.

## 5. References and links

* [Introduction to Pester][1]
* [Pester v4 Docs][1]

## 6. Contacts

Please contact the author for any questions or if you'd like to help out.

[1]:https://www.dbi-services.com/blog/an-introduction-to-pester-unit-testing-and-infrastructure-checks-in-powershell/
[2]:https://pester.dev/docs/v4/quick-start
