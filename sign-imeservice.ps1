
# sign-imeservice.ps1 — 给 ImeService.exe 重新签名并建立本机信任链
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File .\sign-imeservice.ps1
#   powershell -ExecutionPolicy Bypass -File .\sign-imeservice.ps1 -Exe "C:\path\ImeService.exe"

param(
    # 目标 exe；留空则自动选取安装目录下版本号最高的 ImeService.exe
    [string]$Exe
)

$ErrorActionPreference = "Stop"

# ==============================
# 配置
# ==============================

$CertSubject = "CN=Local Doubao IME Code Signing"
$CertValidityYears = 5
$CertFile = "$env:ProgramData\LocalDoubaoSigning.cer"

# 未指定 $Exe 时自动探测最新版本目录
if (-not $Exe) {
    $versRoot = "C:\Program Files\DoubaoIME\versions"
    if (-not (Test-Path $versRoot)) {
        Write-Host "找不到豆包安装目录：$versRoot" -ForegroundColor Red
        Write-Host "请用 -Exe 参数手动指定 ImeService.exe 路径。" -ForegroundColor Yellow
        exit 1
    }
    $latest = Get-ChildItem $versRoot -Directory |
        Sort-Object {
            $v = [regex]::Match($_.Name, '\d+(\.\d+)+').Value
            if ($v) { [version]$v } else { [version]'0.0.0' }
        } -Descending |
        Select-Object -First 1
    $Exe = Join-Path $latest.FullName "ImeService.exe"
    Write-Host "自动选择版本：$($latest.Name)" -ForegroundColor Green
}

# ==============================
# 1. 检查管理员权限
# ==============================

$IsAdmin = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "正在请求管理员权限..."

    $Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Exe `"$Exe`""
    Start-Process powershell.exe -Verb RunAs -ArgumentList $Arguments -Wait
    exit
}

try {
    Write-Host "`n[1/6] 检查目标文件..." -ForegroundColor Cyan

    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
        throw "找不到目标 EXE：$Exe"
    }

    # ==============================
    # 2. 查找 SignTool
    # ==============================

    Write-Host "`n[2/6] 查找 SignTool..." -ForegroundColor Cyan

    $SignTool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source

    if (-not $SignTool) {
        $KitPath = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"

        if (Test-Path $KitPath) {
            $SignTool = Get-ChildItem $KitPath `
                -Filter signtool.exe `
                -Recurse `
                -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.FullName -match '\\x64\\signtool\.exe$'
                } |
                Sort-Object FullName -Descending |
                Select-Object -First 1 -ExpandProperty FullName
        }
    }

    if (-not $SignTool) {
        throw "找不到 SignTool。请安装 Windows SDK。"
    }

    Write-Host "SignTool: $SignTool"

    # ==============================
    # 3. 创建或复用签名证书
    # ==============================

    Write-Host "`n[3/6] 创建或查找代码签名证书..." -ForegroundColor Cyan

    $Cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            $_.Subject -eq $CertSubject -and
            $_.HasPrivateKey -and
            $_.NotAfter -gt (Get-Date) -and
            ($_.EnhancedKeyUsageList.ObjectId.Value -contains "1.3.6.1.5.5.7.3.3")
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $Cert) {
        $Cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $CertSubject `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -KeyAlgorithm RSA `
            -KeyLength 3072 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears($CertValidityYears)

        Write-Host "已创建新证书。" -ForegroundColor Green
    }
    else {
        Write-Host "发现已有有效证书，直接复用。" -ForegroundColor Green
    }

    Write-Host "Thumbprint: $($Cert.Thumbprint)"

    # ==============================
    # 4. 检查并建立本机信任
    # ==============================

    Write-Host "`n[4/6] 检查本机根证书..." -ForegroundColor Cyan

    # 根据指纹精确查找根证书
    $RootCert = Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object {
            $_.Thumbprint -eq $Cert.Thumbprint
        } |
        Select-Object -First 1

    if ($RootCert) {
        Write-Host "根证书已存在，无需重复导入。" -ForegroundColor Green
    }
    else {
        Write-Host "未找到对应根证书，正在安装..." -ForegroundColor Yellow

        # 仅在需要安装时导出
        Export-Certificate `
            -Cert $Cert `
            -FilePath $CertFile `
            -Force | Out-Null

        # 导入本机受信任的根证书颁发机构
        Import-Certificate `
            -FilePath $CertFile `
            -CertStoreLocation "Cert:\LocalMachine\Root" |
            Out-Null

        # 再次验证
        $RootCert = Get-ChildItem Cert:\LocalMachine\Root |
            Where-Object {
                $_.Thumbprint -eq $Cert.Thumbprint
            } |
            Select-Object -First 1

        if (-not $RootCert) {
            throw "根证书导入失败，未找到对应指纹。"
        }

        Write-Host "根证书安装成功。" -ForegroundColor Green
    }

    Write-Host "本机信任已建立。"
    Write-Host "Root Thumbprint: $($RootCert.Thumbprint)"

    # ==============================
    # 5. 备份并签名
    # ==============================

    Write-Host "`n[5/6] 备份并签名..." -ForegroundColor Cyan

    $Backup = "$Exe.$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"

    Copy-Item -LiteralPath $Exe -Destination $Backup

    Write-Host "备份文件: $Backup"

    & $SignTool sign `
        /fd SHA256 `
        /sha1 $Cert.Thumbprint `
        /s My `
        /sm `
        /v `
        $Exe

    if ($LASTEXITCODE -ne 0) {
        throw "SignTool 签名失败，退出码：$LASTEXITCODE"
    }

    # ==============================
    # 6. 验证签名
    # ==============================

    Write-Host "`n[6/6] 验证签名..." -ForegroundColor Cyan

    & $SignTool verify /pa /v $Exe

    if ($LASTEXITCODE -ne 0) {
        throw "签名验证失败，退出码：$LASTEXITCODE"
    }

    $Result = Get-AuthenticodeSignature -FilePath $Exe

    if ($Result.Status -ne "Valid") {
        throw "PowerShell 签名验证失败：$($Result.Status)"
    }

    # 额外确认签名者指纹
    if ($Result.SignerCertificate.Thumbprint -ne $Cert.Thumbprint) {
        throw "签名者指纹与预期证书不一致。"
    }

    Write-Host "`n================================" -ForegroundColor Green
    Write-Host "签名及验证成功！" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green

    Write-Host "文件：$Exe"
    Write-Host "签名者：$($Result.SignerCertificate.Subject)"
    Write-Host "证书指纹：$($Result.SignerCertificate.Thumbprint)"
    Write-Host "备份：$Backup"
    Write-Host "证书：$CertFile"
}
catch {
    Write-Host "`n操作失败：" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
