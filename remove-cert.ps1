# remove-cert.ps1 — 卸载自签名证书（仅本机）

$Subject = "CN=Local Doubao IME Code Signing"

foreach ($Store in @("My", "Root")) {
    $Path = "Cert:\LocalMachine\$Store"

    $Certs = Get-ChildItem $Path |
        Where-Object { $_.Subject -eq $Subject }

    foreach ($Cert in $Certs) {
        Write-Host "删除 [$Store] $($Cert.Thumbprint)" -ForegroundColor Yellow
        Remove-Item -LiteralPath $Cert.PSPath -Force
    }
}

# 删除导出的 CER 文件
$CertFile = "$env:ProgramData\LocalDoubaoSigning.cer"

if (Test-Path $CertFile) {
    Remove-Item $CertFile -Force
    Write-Host "已删除 CER 文件"
}

# 验证
Write-Host "`n验证剩余证书..." -ForegroundColor Cyan

foreach ($Store in @("My", "Root")) {
    $Remaining = Get-ChildItem "Cert:\LocalMachine\$Store" |
        Where-Object { $_.Subject -eq $Subject }

    if ($Remaining) {
        Write-Host "[$Store] 仍有证书：" -ForegroundColor Red
        $Remaining | Format-Table Subject, Thumbprint
    }
    else {
        Write-Host "[$Store] 已清理干净。" -ForegroundColor Green
    }
}