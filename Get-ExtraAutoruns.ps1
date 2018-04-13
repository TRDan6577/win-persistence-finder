Function Get-ScreenSaverRegKeys {
    <#
    .SYNOPSIS
        This function grabs the registry key at 
        HKCU\Control Panel\Desktop\SCRNSAVE.exe and displays it for the user.

    .DESCRIPTION
        This function checks to see the registry key
        HKCU\Control Panel\Desktop\SCRNSAVE.exe exists. If it does exist, it
        checks to see if it is signed. When the function returns, it returns
        a PersistanceFinderObject or null.

    .LINK
        https://attack.mitre.org/wiki/Technique/T1180

    .NOTES
        Author: Tom Daniels
        License: MPL v2.0
    #>

    $Path = "HKCU:\Control Panel\Desktop\SCRNSAVE.EXE" # The path to the screen saver registry key
    $MatrixNumber = "T1180" # The Mitre Attack Matrix ID

    try {
        $KeyValue = $(Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -name 'SCRNSAVE.EXE' -ErrorAction Stop).'SCRNSAVE.EXE'
        $SignatureResults = Get-AuthenticodeSignature -FilePath $KeyValue
        $MD5 = $(Get-FileHash -Path $KeyValue -Algorithm MD5).Hash
        $SHA1 = $(Get-FileHash -Path $KeyValue -Algorithm SHA1).Hash
    
        return New-PersistanceFinderObject -PersistanceMethod 'Screen Saver' -Path `
        $Path -Value $KeyValue -MD5 $MD5 -SHA1 $SHA1 -ValidSignature `
        $SignatureResults.Status -SignerCertificate $SignatureResults.SignerCertificate `
        -AttackMatrixNumber $MatrixNumber
    }catch{  # If the key doesn't exist, return null
        return $null
    }
}

Function New-PersistanceFinderObject {
    <#
    .SYNOPSIS
        Makes a custom powershell object with the specified parameters.

    .DESCRIPTION
        This function creates an object that holds the path to a file or
        registry key. If it's a registry key, it will also hold the value
        of that registry key. It is assumed that the value of the registry
        key is a binary. It will also hold whether or not the binary is signed
        by whom it is signed. Finally, it holds the Mitre Attack Matrix ID of
        the persistance method.

    .PARAMETER PersistanceMethod
        This is the name of the persistance method. For example, if a piece of
        malware were to use a scheduled task as a persistance method, the value
        of this parameter should be "Scheduled Task".

    .PARAMETER Path
        The path to either the registry key or the binary.

    .PARAMETER Value
        If the path points to a registry key, this should be the value of that key.

    .PARAMETER MD5
        The MD5 hash value of the file

    .PARAMETER SHA1
        The SHA1 hash value of the file

    .PARAMETER ValidSignature
        Tells us if the binary in the path (or value) is signed.

    .PARAMETER SignerCertificate
        Contains the certificate of the entity that signed the binary

    .PARAMETER AttackMatrixNumber
        The ID of the Mitre Attack Matrix technique associated with this attack

    .NOTES
        Author: Tom Daniels
        License: MPL v2.0
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PersistanceMethod,

        [Parameter(Mandatory=$True)]
        [string]$Path,

        [Parameter(Mandatory=$True)]
        [string]$Value,

        [Parameter(Mandatory=$True)]
        [string]$MD5,

        [Parameter(Mandatory=$True)]
        [string]$SHA1,

        [Parameter(Mandatory=$False)]
        [string]$ValidSignature,

        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SignerCertificate,

        [Parameter(Mandatory=$True)]
        [string]$AttackMatrixNumber
    )

    $object = New-Object -TypeName psobject
    $object | Add-Member -MemberType NoteProperty -Name Name -Value $PersistanceMethod
    $object | Add-Member -MemberType NoteProperty -Name Path -Value $Path
    $object | Add-Member -MemberType NoteProperty -Name Value -Value $Value
    $object | Add-Member -MemberType NoteProperty -Name MD5 -Value $MD5
    $object | Add-Member -MemberType NoteProperty -Name SHA1 -Value $SHA1
    $object | Add-Member -MemberType NoteProperty -Name ValidSignature -Value $ValidSignature
    $object | Add-Member -MemberType NoteProperty -Name SignerCertificate -Value $SignerCertificate
    $object | Add-Member -MemberType NoteProperty -Name MitreAttackMatrixNo -Value $AttackMatrixNumber
    return $object
}
