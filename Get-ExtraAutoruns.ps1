# Global variables
$TypeReg = "RegistryKey"
$TypeBin = "File"

Function Get-ScreenSaverRegKeys {
    <#
    .SYNOPSIS
        This function grabs the registry key at 
        HKCU\Control Panel\Desktop\SCRNSAVE.exe and displays it for the user.

    .DESCRIPTION
        This function checks to see the registry key
        HKCU\Control Panel\Desktop\SCRNSAVE.exe exists. If it does exist, it
        checks to see if it is signed. When the function returns, it returns
        a PersistenceFinderObject or null.

    .LINK
        https://attack.mitre.org/wiki/Technique/T1180

    .NOTES
        Author: Tom Daniels
        License: MPL v2.0
    #>

    $Path = "HKCU:\Control Panel\Desktop\SCRNSAVE.EXE" # The path to the screen saver registry key
    $MatrixNumber = "T1180" # The Mitre Attack Matrix ID
    return New-PersistenceFinderObject -PersistenceMethod "Screen Saver" -Type $TypeReg `
        -Path $Path -AttackMatrixNumber $MatrixNumber
}

Function Get-AccessibilityFeatures {
<#
    .SYNOPSIS
        Gets the information about the accessibility binaries and registry keys

    .DESCRIPTION
        If an attacker has either physical access to a machine or RDP access
        to a machine, putting a backdoor in the accessibility features
        would allow easy re-entry to a system, even if the machine is on
        the logon screen. This function will check if the following
        accessibility binaries share an MD5 hash with any binaries that
        could be used for persistence.

        Accessibility Binaries:
            sethc.exe         (Sticky-Keys)
            utilman.exe       (Accessibility Menu)
            osk.exe           (On-Screen Keyboard)
            Magnify.exe       (magnifier)
            Narrator.exe      (Narrator)
            DisplaySwitch.exe (Display Switcher)
            AtBroker.exe      (App Switcher)

        Persistence Binaries (MD5 hash of accessibility should NOT match these):
            explorer.exe              (Windows Explorer)
            taskschd.msc              (Task Scheduler)
            cmd.exe                   (Command Prompt)
            powershell.exe            (Powershell)
            powershell_ise.exe        (Powershell ISE)
            regedit.exe               (Registry Editor)
            Taskmgr.exe               (Task Manager)

        Additionally, adding a registry subkey for these accessibility features
        under the Image File Execution Options registry key could also give an
        attacker access to a system. By setting the value of the debugger subkey
        to a program such as cmd.exe, an attacker could execute that accessibility
        tool and launch the debugging program instead. For example, instead of
        launching Sticky-Keys, the attacker would launch cmd.exe. This function
        will check the Image File Execution Options key for any accessibility
        subkeys with a subsequent debugger subkey.

    .LINK
        https://attack.mitre.org/wiki/Technique/T1015

    .NOTES
        Author: Tom Daniels
        License: MPL v2.0
    #>

    # TODO: Add the registry keys method

    $MatrixNumber = "T1015"
    $PersistenceMethod = "Accessibility Features"
    $sys32 = "\system32\"
    $IFEOPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\"
    $AccessibilityObjects = @()

    # Accessibility programs
    $AccessibilityPrograms = "sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", `
        "Narrator.exe", "DisplaySwitch.exe", "AtBroker.exe"

    # For each program, test for the existance of a key in the registry.
    # If a key exists with the same name as the program, look for a debugger
    # subkey.
    ForEach ($Program in $AccessibilityPrograms){
        if(Test-Path $($IFEOPath + $Program)){
            try{
                # If the following succeeds, that means a debugger key exists
                $null = Get-ItemProperty -Path $($IFEOPath + $Program) -name "Debugger" -ErrorAction Stop
                $AccessibilityObjects += New-PersistenceFinderObject -PersistenceMethod $PersistenceMethod `
                    -Type $TypeReg -Path $($IFEOPath + $Program + "\Debugger") -AttackMatrixNumber $MatrixNumber
            }catch{
                continue  # Do nothing if there's no debugger subkey
            }
        }
    }

    # Accessibility program paths. All programs are in the sys32 dir
    $AccessibilityPaths = @()
    ForEach ($Program in $AccessibilityPrograms){
        $AccessibilityPaths += $($env:windir + $sys32 + $Program)
    }

    # Persistence Paths
    $PersistencePaths = $($env:windir + "\System32\WindowsPowerShell\v1.0\powershell.exe"),`
        $($env:windir + "\explorer.exe"), $($env:windir + "\system32\Taskmgr.exe"),`
        $($env:windir + "\system32\taskschd.msc"),`
        $($env:windir + "\System32\WindowsPowerShell\v1.0\powershell_ise.exe"),`
        $($env:windir + "\regedit.exe"), $($env:windir + "\system32\cmd.exe")

    # Calculate the hash for each persistence method
    $PersistenceHashes = @()
    For($i=0; $i -lt $PersistencePaths.Length; $i++){
        $PersistenceHashes += Get-FileHash -Path $PersistencePaths[$i] -Algorithm MD5
    }

    # For each accessibility method, check to see if it matches an admin
    # utility tool (see "Persistence Binaries" above in the function docs)
    ForEach ($Accessible in $AccessibilityPaths){
        $PersistenceObject = New-PersistenceFinderObject `
            -PersistenceMethod $PersistenceMethod -Type $TypeBin -Path `
            $Accessible -AttackMatrixNumber $MatrixNumber
        $PersistenceObject | Add-Member -MemberType NoteProperty -Name MatchesAdminUtil -Value "No"
        
        ForEach ($PersistenceHash in $PersistenceHashes){
            if($PersistenceObject.MD5 -eq $PersistenceHash.Hash){
                $PersistenceObject.MatchesAdminUtil = $PersistenceHash.Path
                break
            }
        }
        $AccessibilityObjects += $PersistenceObject
    }

    return $AccessibilityObjects
}

Function New-PersistenceFinderObject {
    <#
    .SYNOPSIS
        Makes a custom powershell object with the specified parameters.

    .DESCRIPTION
        This function creates an object that holds the path to a file or
        registry key. If it's a registry key, it will also hold the value
        of that registry key. It is assumed that the value of the registry
        key is a binary. It will also hold whether or not the binary is signed
        by whom it is signed. Finally, it holds the Mitre Attack Matrix ID of
        the persistence method.

    .PARAMETER PersistenceMethod
        This is the name of the persistence method. For example, if a piece of
        malware were to use a scheduled task as a persistence method, the value
        of this parameter should be "Scheduled Task".

    .PARAMETER Type
        This tells us whether the persistence method involves a registry key or a
        file. The values for this should always be either "RegistryKey" or "File".

    .PARAMETER Path
        The path to either the registry key or the binary.

    .PARAMETER AttackMatrixNumber
        The ID of the Mitre Attack Matrix technique associated with this attack

    .NOTES
        Author: Tom Daniels
        License: MPL v2.0
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PersistenceMethod,

        [Parameter(Mandatory=$True)]
        [string]$Type,

        [Parameter(Mandatory=$True)]
        [string]$Path,

        [Parameter(Mandatory=$True)]
        [string]$AttackMatrixNumber
    )

    # After the following code block, $ShortPath holds the path to the file or registry location
    # and $Value holds the name of the key or file. Example, if $Path = "C:\Windows\system32\calc.exe",
    # $Value will be "calc.exe" and $ShortPath will be "C:\Windows\system32\"
    $Value = $Path.Split("\")[-1]
    $ShortPath = $Path.Substring(0, $Path.LastIndexOf($Value))

    # If we're dealing with a registry key
    if($Type -eq $TypeReg){
        try{
            # Get the value of the registry key
            $Value = $(Get-ItemProperty -Path $ShortPath -name $Value -ErrorAction Stop).$Value

            # Verify the binary's signature and compute the hash values
            $SignatureResults = Get-AuthenticodeSignature -FilePath $Value
            $MD5 = $(Get-FileHash -Path $Value -Algorithm MD5).Hash
            $SHA1 = $(Get-FileHash -Path $Value -Algorithm SHA1).Hash
        }catch{
            # If the key doesn't exist, return $null
            return $null
        }
    }else{ # Case if we're dealing with a binary file
        try{
            $SignatureResults = Get-AuthenticodeSignature -FilePath $Path
            $MD5 = $(Get-FileHash -Path $Path -Algorithm MD5).Hash
            $SHA1 = $(Get-FileHash -Path $Path -Algorithm SHA1).Hash
        }catch{
            # If the file doesn't exist, return $null
            return $null
        }
    }

    # Create the object
    $object = New-Object -TypeName psobject
    $object | Add-Member -MemberType NoteProperty -Name Name -Value $PersistenceMethod
    $object | Add-Member -MemberType NoteProperty -Name Type -Value $Type
    $object | Add-Member -MemberType NoteProperty -Name Path -Value $Path
    $object | Add-Member -MemberType NoteProperty -Name Value -Value $Value
    $object | Add-Member -MemberType NoteProperty -Name MD5 -Value $MD5
    $object | Add-Member -MemberType NoteProperty -Name SHA1 -Value $SHA1
    $object | Add-Member -MemberType NoteProperty -Name ValidSignature -Value $SignatureResults.Status
    $object | Add-Member -MemberType NoteProperty -Name SignerCertificate -Value $SignatureResults.SignerCertificate
    $object | Add-Member -MemberType NoteProperty -Name MitreAttackMatrixNo -Value $AttackMatrixNumber
    return $object
}