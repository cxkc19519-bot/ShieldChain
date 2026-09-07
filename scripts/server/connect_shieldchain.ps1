param(
    [Parameter(Mandatory = $true)]
    [string]$ServerHost,

    [int]$Port = 1100,

    [string]$UserName = "jhk",

    [Parameter(Mandatory = $true)]
    [string]$IdentityFile,

    [int]$LocalPort = 8080
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    throw "未找到 ssh。请在 Windows 可选功能中安装 OpenSSH 客户端。"
}

$resolvedIdentity = (Resolve-Path -LiteralPath $IdentityFile).Path
if (-not (Test-Path -LiteralPath $resolvedIdentity -PathType Leaf)) {
    throw "SSH 私钥不存在：$IdentityFile"
}

$remoteCommand = "cd /home/user/jhk/project/ShieldChain && ./scripts/server/start_shieldchain.sh start; exec bash -l"
$sshArguments = @(
    "-i", $resolvedIdentity,
    "-p", $Port,
    "-o", "ExitOnForwardFailure=yes",
    "-L", "${LocalPort}:127.0.0.1:8080",
    "-t", "${UserName}@${ServerHost}",
    $remoteCommand
)

Write-Host "正在连接服务器并启动 ShieldChain……" -ForegroundColor Cyan
Write-Host "启动完成后访问：http://127.0.0.1:$LocalPort" -ForegroundColor Green
Write-Host "请保持此窗口打开；输入 exit 后 SSH 隧道会关闭。" -ForegroundColor Yellow

& ssh @sshArguments
if ($LASTEXITCODE -ne 0) {
    throw "SSH 连接或远程启动失败，退出码：$LASTEXITCODE"
}
