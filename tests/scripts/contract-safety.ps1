function Test-ScriptHasNoFileContentReads {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $Path).Path,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        return $false
    }

    $contentReadCommands = @(
        "Get-Content",
        "gc",
        "type",
        "cat",
        "Select-String",
        "sls"
    )
    $commands = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)
    foreach ($command in $commands) {
        if ($contentReadCommands -icontains $command.GetCommandName()) {
            return $false
        }

        if (
            $command.GetCommandName() -ieq "New-Object" -and
            $command.Extent.Text -match "(?i)(System\.)?IO\.StreamReader"
        ) {
            return $false
        }
    }

    $streamReaderTypes = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.TypeExpressionAst] -and
        $node.TypeName.FullName -match "(?i)^(System\.)?IO\.StreamReader$"
    }, $true)
    if ($streamReaderTypes.Count -gt 0) {
        return $false
    }

    $fileReadMethods = @(
        "ReadAllText",
        "ReadAllLines",
        "ReadAllBytes",
        "ReadLines",
        "OpenText",
        "OpenRead",
        "Open"
    )
    $memberCalls = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
    }, $true)
    foreach ($memberCall in $memberCalls) {
        $memberName = $memberCall.Member.Value
        if (
            $fileReadMethods -icontains $memberName -and
            $memberCall.Expression.Extent.Text -match "(?i)^\[(System\.)?IO\.File\]$"
        ) {
            return $false
        }
    }

    return $true
}
