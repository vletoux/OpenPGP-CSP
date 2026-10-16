param (
    [string]$outPath = "version.h"
)

$major = $minor = $patch = $build = 0
$isAzure = $env:TF_BUILD -eq "True" # detect Azure DevOps

# EID_FORCE_VERSION=a.b.c.d : version imposee au lieu de "git describe". Sert a
# soumettre EIDKernelPackage.sys sous le meme numero que le SSP deja signe par
# Microsoft (2.0.0.0) alors que le driver contient des commits posterieurs au tag.
if ($env:EID_FORCE_VERSION -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') {
    $major = $Matches[1]; $minor = $Matches[2]; $patch = $Matches[3]; $build = $Matches[4]
    $semVer = $env:EID_FORCE_VERSION
}
elseif ($env:EID_FORCE_VERSION) {
    throw "EID_FORCE_VERSION='$env:EID_FORCE_VERSION' : format attendu a.b.c.d"
}
else {
try {
    $describe = git describe --tags --always --long 2>$null
    
    if ($describe -match 'v?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?-(\d+)-g([a-f0-9]+)') {
        
        if ($Matches[4] -ne "") {
            $major = $Matches[1]
            $minor = $Matches[2]
            $patch = $Matches[3]
            $build = $Matches[5]
        } else {
            $major = $Matches[1]
            $minor = $Matches[2]
            $patch = $Matches[3]
            $build = $Matches[5]
        }
        
        $suffix = if ($isAzure) { "" } else { "-local" }
        $semVer = "$major.$minor.$patch.$build$suffix"
    } else {
        Write-Warning "Unknown tag format or no tag. Use 0.0.0."
        $semVer = "0.0.0-hash-$describe"
    }
} catch {
    Write-Error "Git not found in the PATH."
}
}

$newContent = @"
#ifndef VERSION_H
#define VERSION_H
#define VER_FILE_VERSION          $major,$minor,$patch,$build
#define VER_PRODUCT_VERSION       $major,$minor,$patch,$build
#define VER_FILE_VERSION_STR      "$major.$minor.$patch.$build\0"
#define VER_PRODUCT_VERSION_STR   "$semVer\0"
#endif // VERSION_H

"@

$mutexName = "Global\EIDVirtualVersionHeaderMutex"
$mutex = New-Object System.Threading.Mutex($false, $mutexName)

# Demande l'acc�s exclusif (attend que les autres projets l�chent le Mutex)
[void]$mutex.WaitOne()

$absoluteOutPath = [System.IO.Path]::GetFullPath($outPath)
$utf8Encoding = New-Object System.Text.UTF8Encoding($true)

try {
    # ZONE S�CURIS�E : Un seul projet � la fois ex�cute ce bloc
    if (-not (Test-Path $outPath)) {
        [System.IO.File]::WriteAllText($absoluteOutPath, $newContent, $utf8Encoding)
        Write-Host "Created file : $outPath (Version $semVer)" -ForegroundColor Cyan
    } else {
        $currentContent = [System.IO.File]::ReadAllText($absoluteOutPath)
        if ($currentContent -ne $newContent) {
            [System.IO.File]::WriteAllText($absoluteOutPath, $newContent, $utf8Encoding)
            Write-Host "Version file updated : $semVer" -ForegroundColor Green
        } else {
            Write-Host "Version file already up to date ($semVer)." -ForegroundColor Gray
        }
    }
}
finally {
    # Rel�che le verrou pour le projet suivant
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
