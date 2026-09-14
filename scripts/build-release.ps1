param(
    [string]$SigningDirectory = (Join-Path $env:USERPROFILE 'ConfigVPN-signing'),
    [string]$JavaHome = 'C:/Program Files/Android/Android Studio/jbr'
)
$ErrorActionPreference = 'Stop'
$env:JAVA_HOME = $JavaHome
$env:UPLOAD_KEYSTORE_PATH = Join-Path $SigningDirectory 'configvpn-release.p12'
$env:UPLOAD_KEY_ALIAS = 'configvpn-upload'
$secure = Get-Content -LiteralPath (Join-Path $SigningDirectory 'password.dpapi') | ConvertTo-SecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $env:UPLOAD_STORE_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    $env:UPLOAD_KEY_PASSWORD = $env:UPLOAD_STORE_PASSWORD
    Push-Location (Split-Path $PSScriptRoot -Parent)
    try {
        & ./gradlew.bat :app:assembleRelease :app:bundleRelease :app:lintRelease :app:testDebugUnitTest --no-daemon --console plain
        if ($LASTEXITCODE -ne 0) { throw "Release verification failed: $LASTEXITCODE" }
    } finally { Pop-Location }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    Remove-Item Env:UPLOAD_STORE_PASSWORD,Env:UPLOAD_KEY_PASSWORD -ErrorAction SilentlyContinue
}
