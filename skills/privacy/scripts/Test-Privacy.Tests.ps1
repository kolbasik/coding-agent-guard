# Pester 4.10 (Pester 5 rejects `Should Be`), from the repo root: pwsh -NoProfile -Command "Invoke-Pester skills/privacy"
# Runs the engine on fake checks and the real checks on a TestDrive home with fake tools (zsh, brew, gh,
# sqlite3, the inventory, process detection), so no test reads or writes your real config. The functions
# come from the script's AST: its top level never runs.
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-Privacy.ps1'), [ref]$null, [ref]$null)
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($f.Extent.Text))
}

# A fresh, empty home under TestDrive.
function New-Home {
    $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $dir | Out-Null
    $dir
}

# Writes $Text to $HomeDir/$Relative, creating its folders; returns the full path.
function Write-HomeFile([string]$HomeDir, [string]$Relative, [string]$Text) {
    $path = Join-Path $HomeDir $Relative
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    Set-Content -LiteralPath $path $Text
    $path
}

# Fake tools: nothing installed, nothing listed. $Overrides replaces single tools.
function New-FakeTools([hashtable]$Overrides = @{}) {
    $tools = @{ LoginEnv = { @() }; Has = { $false }; Brew = { @() }; Gh = { @() }; Sqlite = { @() }; Defaults = { @() }; Inventory = { @() } }
    foreach ($k in $Overrides.Keys) { $tools[$k] = $Overrides[$k] }
    $tools
}

# The real check named $Name, built on $HomeDir.
function Get-Check([string]$HomeDir, [string]$Name, [hashtable]$Tools = (New-FakeTools), [string]$OptOuts = (Join-Path $HomeDir 'opt-outs.zsh'),
    [string]$KnownFile = (Join-Path $HomeDir 'known.txt')) {
    Get-PrivacyChecks -HomePath $HomeDir -OptOuts $OptOuts -KnownFile $KnownFile -Tools $Tools | Where-Object Name -eq $Name
}

# A fake check. Its Fix counts calls in Data.Fixes and clears the problems, unless -Stuck.
function Fake([string]$Name, [string[]]$Problems = @(), [switch]$NoFix, [switch]$Stuck) {
    $fix = if ($Stuck) { { param($c) $c.Data.Fixes++ } } elseif (-not $NoFix) { { param($c) $c.Data.Fixes++; $c.Data.Problems = @() } }
    New-Check $Name -Hint "fix $Name" -Data @{ Problems = $Problems; Fixes = 0 } -Test { param($c) $c.Data.Problems } -Fix $fix
}

function Run([object[]]$Checks, [string]$Action = 'status', [scriptblock]$IsRunning = { $false }) { Invoke-PrivacyCheck $Checks $Action $IsRunning 6> $null }

Describe 'Test-Privacy engine' {
    It 'StatusReportsViolationAndFails' {
        # Arrange
        $checks = @((Fake 'a'), (Fake 'b' @('k is 1, want 0')))

        # Act
        $result = Run $checks

        # Assert
        $result.Lines[1] | Should BeExactly 'VIOLATION  b: k is 1, want 0 (fix: fix b)'
        $result.ExitCode | Should Be 1
    }

    It 'StatusWithEverythingOkReturnsZero' {
        # Arrange
        $checks = @((Fake 'a'), (Fake 'b'))

        # Act
        $result = Run $checks

        # Assert
        $result.Lines -join '|' | Should BeExactly 'ok         a|ok         b'
        $result.ExitCode | Should Be 0
    }

    It 'ManualNeverFails' {
        # Arrange
        $manual = New-Check 'm' -Kind manual -Hint 'click X'

        # Act
        $result = Run @($manual)

        # Assert
        $result.Lines[0] | Should BeExactly 'manual     m: click X'
        $result.ExitCode | Should Be 0
    }

    It 'UnassessedToolIsReviewAndFails' {
        # Arrange
        $sweep = Get-Check (New-Home) 'Unknown-tool sweep' (New-FakeTools @{ Inventory = { 'jq', 'brand-new-tool' } })

        # Act
        $result = Run @($sweep)

        # Assert
        $result.Lines -join '|' | Should Match '^REVIEW     brand-new-tool: installed, not assessed'
        $result.Lines.Count | Should Be 1
        $result.ExitCode | Should Be 1
    }

    It 'UvPythonShimIsAssessed' {
        # Arrange
        $sweep = Get-Check (New-Home) 'Unknown-tool sweep' (New-FakeTools @{ Inventory = { 'python3.13' } })

        # Act
        $result = Run @($sweep)

        # Assert
        $result.ExitCode | Should Be 0
    }

    It 'EmptyInventoryIsNotReportedClean' {
        # Arrange
        $sweep = Get-Check (New-Home) 'Unknown-tool sweep'

        # Act
        $result = Run @($sweep)

        # Assert
        $result.Lines[0] | Should Match '^VIOLATION  Unknown-tool sweep: cannot read it: the inventory listed nothing'
    }

    It 'ToolInKnownFileIsAssessed' {
        # Arrange
        $homeDir = New-Home
        $knownFile = Write-HomeFile $homeDir 'known.txt' "# assessed by me`nbrand-new-*  # no network code"
        $sweep = Get-Check $homeDir 'Unknown-tool sweep' (New-FakeTools @{ Inventory = { 'jq', 'brand-new-tool' } }) -KnownFile $knownFile

        # Act
        $result = Run @($sweep)

        # Assert
        $result.Lines -join '|' | Should BeExactly 'ok         Unknown-tool sweep: every installed tool is assessed'
        $result.ExitCode | Should Be 0
    }

    It 'MissingKnownFileAddsNoNames' {
        # Arrange
        $homeDir = New-Home
        $knownFile = Join-Path $homeDir 'nowhere/known.txt'
        $sweep = Get-Check $homeDir 'Unknown-tool sweep' (New-FakeTools @{ Inventory = { 'jq', 'brand-new-tool' } }) -KnownFile $knownFile

        # Act
        $result = Run @($sweep)

        # Assert
        $result.Lines -join '|' | Should BeExactly "REVIEW     brand-new-tool: installed, not assessed (assess it, then add a check or add it to $knownFile)"
        $result.ExitCode | Should Be 1
    }

    It 'ManualCheckForAbsentAppIsNotApplicable' {
        # Arrange
        $manual = Get-Check (New-Home) 'Antigravity app'

        # Act
        $result = Run @($manual)

        # Assert
        $result.Lines[0] | Should BeExactly 'n/a        Antigravity app (not installed)'
    }

    It 'ManualCheckForInstalledAppIsManual' {
        # Arrange
        $homeDir = New-Home
        New-Item -ItemType Directory (Join-Path $homeDir 'Library/Application Support/Antigravity') | Out-Null
        $manual = Get-Check $homeDir 'Antigravity app'

        # Act
        $result = Run @($manual)

        # Assert
        $result.Lines[0] | Should Match '^manual     Antigravity app: '
        $result.ExitCode | Should Be 0
    }

    It 'StatusNeverFixes' {
        # Arrange
        $bad = Fake 'a' @('k is 1, want 0')

        # Act
        Run @($bad) | Out-Null

        # Assert
        $bad.Data.Fixes | Should Be 0
    }

    It 'ApplyFixesOnlyViolations' {
        # Arrange
        $good = Fake 'a'
        $bad = Fake 'b' @('k is 1, want 0')

        # Act
        $result = Run @($good, $bad) 'apply'

        # Assert
        $good.Data.Fixes | Should Be 0
        $bad.Data.Fixes | Should Be 1
        $result.Lines -join '|' | Should BeExactly 'ok         a|fixed      b'
        $result.ExitCode | Should Be 0
    }

    It 'ViolationWithoutAutomaticFixStaysViolation' {
        # Arrange
        $bad = Fake 'a' @('k is 1, want 0') -NoFix

        # Act
        $result = Run @($bad) 'apply'

        # Assert
        $result.Lines[0] | Should BeExactly 'VIOLATION  a: k is 1, want 0 (fix: fix a)'
        $result.ExitCode | Should Be 1
    }

    It 'FixThatDoesNotTakeStaysViolation' {
        # Arrange
        $stuck = Fake 'a' @('k is 1, want 0') -Stuck

        # Act
        $result = Run @($stuck) 'apply'

        # Assert
        $result.Lines[0] | Should Match '^VIOLATION  a: k is 1, want 0 \(still wrong after the fix'
        $result.ExitCode | Should Be 1
    }

    It 'TerminalBrowserSettingsAreCreatedOnceItIsInstalled' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir '.local/bin/terminal-browser' '' | Out-Null

        # Act
        Run @(Get-Check $homeDir 'terminal-browser') 'apply' | Out-Null

        # Assert
        (Get-Content "$homeDir/.config/terminal-browser/settings.json" -Raw | ConvertFrom-Json).'updates.check' | Should BeExactly 'off'
    }

    It 'TerminalBrowserFromHomebrewCountsAsInstalled' {
        # Arrange
        $homeDir = New-Home
        $tools = New-FakeTools @{ Has = { param($Name) $Name -eq 'terminal-browser' } }

        # Act
        Run @(Get-Check $homeDir 'terminal-browser' $tools) 'apply' | Out-Null

        # Assert
        (Get-Content "$homeDir/.config/terminal-browser/settings.json" -Raw | ConvertFrom-Json).'updates.check' | Should BeExactly 'off'
    }

    It 'ApplyBacksUpFileBeforeFixing' {
        # Arrange
        $homeDir = New-Home
        $original = '{"telemetry.usage":"on","telemetry.crashReports":"off","updates.check":"off","render.fps":30}'
        $file = Write-HomeFile $homeDir '.config/terminal-browser/settings.json' $original
        Write-HomeFile $homeDir '.local/bin/terminal-browser' '' | Out-Null

        # Act
        $result = Run @(Get-Check $homeDir 'terminal-browser') 'apply'

        # Assert
        $result.Lines[0] | Should BeExactly 'fixed      terminal-browser'
        $backups = @(Get-ChildItem (Split-Path $file) -Filter 'settings.json.bak-*')
        $backups.Count | Should Be 1
        $backups[0].Name | Should Match '^settings\.json\.bak-\d{8}-\d{4}$'
        (Get-Content $backups[0].FullName -Raw).Trim() | Should BeExactly $original
        $fixed = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable
        $fixed['telemetry.usage'] | Should BeExactly 'off'
        $fixed['render.fps'] | Should Be 30
    }

    It 'ApplySkipsGuiAppWhileItRuns' {
        # Arrange
        $homeDir = New-Home
        $file = Write-HomeFile $homeDir 'Library/Application Support/obsidian/obsidian.json' '{"updateDisabled":false}'

        # Act
        $result = Run @(Get-Check $homeDir 'Obsidian') 'apply' { param($App) $App -eq 'Obsidian' }

        # Assert
        $result.Lines[0] | Should Match 'updateDisabled is false, want true \(close Obsidian and re-run\)$'
        (Get-Content $file -Raw).Trim() | Should BeExactly '{"updateDisabled":false}'
        @(Get-ChildItem (Split-Path $file) -Filter '*.bak-*').Count | Should Be 0
    }

    It 'ApplyNeverCreatesConfigForAbsentApp' {
        # Arrange
        $homeDir = New-Home

        # Act
        $result = Run @(Get-Check $homeDir 'Zed') 'apply'

        # Assert
        $result.Lines[0] | Should BeExactly 'n/a        Zed (not installed)'
        Test-Path (Join-Path $homeDir '.config/zed') | Should Be $false
    }

    It 'UnreadableFileIsReportedAndNotRewritten' {
        # Arrange
        $homeDir = New-Home
        $file = Write-HomeFile $homeDir '.claude/settings.json' '{ "env": { broken'

        # Act
        $result = Run @(Get-Check $homeDir 'Claude Code') 'apply'

        # Assert
        $result.Lines[0] | Should Match '^VIOLATION  Claude Code: cannot read it: '
        (Get-Content $file -Raw).Trim() | Should BeExactly '{ "env": { broken'
    }
}

Describe 'Test-Privacy parsers' {
    It 'OptOutsExportsAreReadWithQuotesStripped' {
        # Arrange
        $lines = '# comment', 'export A=1', 'export B="x y"', "  export C='z'", 'D=not-exported', '# export E=1'

        # Act
        $map = Read-Exports $lines

        # Assert
        ($map.Keys | ForEach-Object { "$_=$($map[$_])" }) -join '|' | Should BeExactly 'A=1|B=x y|C=z'
    }

    It 'RealOptOutsHas22ExportsAndDoNotTrackIsOne' {
        # Arrange
        $lines = Get-Content (Join-Path $PSScriptRoot '../opt-outs.zsh')

        # Act
        $map = Read-Exports $lines

        # Assert
        $map.Count | Should Be 22
        $map['DO_NOT_TRACK'] | Should BeExactly '1'
    }

    It 'CodexRootKeyAboveFirstTableIsOk' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir '.codex/config.toml' "check_for_update_on_startup = false`n`n[analytics]`nenabled = false`n`n[feedback]`nenabled = false" | Out-Null
        $codex = Get-Check $homeDir 'Codex config.toml'

        # Act
        $problems = @(& $codex.Test $codex)

        # Assert
        $problems.Count | Should Be 0
    }

    It 'CodexRootKeyBelowFirstTableIsViolation' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir '.codex/config.toml' "[tui]`ncheck_for_update_on_startup = false`n`n[analytics]`nenabled = false`n`n[feedback]`nenabled = false" | Out-Null
        $codex = Get-Check $homeDir 'Codex config.toml'

        # Act
        $problems = @(& $codex.Test $codex)

        # Assert
        $problems -join '|' | Should BeExactly 'check_for_update_on_startup sits under [tui], where it is never read; want it above the first [table]'
    }

    It 'CodexFixMovesRootKeyAboveFirstTable' {
        # Arrange
        $homeDir = New-Home
        $file = Write-HomeFile $homeDir '.codex/config.toml' "[tui]`ncheck_for_update_on_startup = false`ntheme = `"x`"`n`n[analytics]`nenabled = true"

        # Act
        $result = Run @(Get-Check $homeDir 'Codex config.toml') 'apply'

        # Assert
        $result.Lines[0] | Should BeExactly 'fixed      Codex config.toml'
        $toml = @(Read-Toml (Get-Content $file))
        ($toml | ForEach-Object { "[$($_.Table)]$($_.Key)=$($_.Value)" }) -join '|' |
            Should BeExactly '[]check_for_update_on_startup=false|[tui]theme="x"|[analytics]enabled=false|[feedback]enabled=false'
    }

    It 'TomlFixAddsMissingTable' {
        # Arrange
        $homeDir = New-Home
        $file = Write-HomeFile $homeDir '.config/herdr/config.toml' "[ui]`ntheme = `"dark`""

        # Act
        Run @(Get-Check $homeDir 'herdr') 'apply' | Out-Null

        # Assert
        (Read-Toml (Get-Content $file) | Where-Object Table -eq 'update' | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '|' |
            Should BeExactly 'version_check=false|manifest_check=false'
    }

    It 'JsoncWithCommentsAndTrailingCommasIsRead' {
        # Arrange
        $homeDir = New-Home
        $jsonc = @'
// Zed settings
{
  /* block comment */
  "auto_update": false,
  "telemetry": { "diagnostics": false, "metrics": true, "anthropic_retention": false, },
  "edit_predictions": { "allow_data_collection": "no", "url": "https://example.invalid//x" },
  "agent": { "enable_feedback": false, }, // trailing
}
'@
        Write-HomeFile $homeDir '.config/zed/settings.json' $jsonc | Out-Null
        $zed = Get-Check $homeDir 'Zed'

        # Act
        $problems = @(& $zed.Test $zed)

        # Assert
        $problems -join '|' | Should BeExactly 'telemetry.metrics is true, want false'
    }

    It 'FlatDottedKeysAreReadAsOneKey' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/Application Support/Antigravity IDE/User/settings.json' `
            '{"telemetry.telemetryLevel":"off","telemetry.feedback.enabled":false,"update.mode":"manual","extensions.autoCheckUpdates":true}' | Out-Null
        $ide = Get-Check $homeDir 'Antigravity IDE'

        # Act
        $problems = @(& $ide.Test $ide)

        # Assert
        $problems -join '|' | Should BeExactly 'extensions.autoCheckUpdates is true, want false'
    }

    It 'DBeaverPrefsLastValueWins' {
        # Arrange
        $lines = 'ui.auto.update.check=true', 'ui.auto.update.check.time=1788434203989', 'ui.auto.update.check=false'

        # Act
        $value = Get-KeyValue $lines 'ui.auto.update.check'

        # Assert
        $value | Should BeExactly 'false'
    }

    It 'DBeaverPrefsLongerKeyIsNotTheCheckedKey' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/DBeaverData/workspace6/.metadata/.plugins/org.eclipse.core.runtime/.settings/org.jkiss.dbeaver.core.prefs' `
            "eclipse.preferences.version=1`nui.auto.update.check.time=1788434203989" | Out-Null
        $dbeaver = Get-Check $homeDir 'DBeaver update check'

        # Act
        $problems = @(& $dbeaver.Test $dbeaver)

        # Assert
        $problems -join '|' | Should BeExactly 'ui.auto.update.check is missing, want false'
    }

    It 'SweepListsOnlyUnknownTools' {
        # Arrange
        $raw = 'hashicorp/tap/terraform', 'Zed.app', 'zed', 'agy.1792342953106887000.old', 'headroom-ai v0.41.0', '- headroom', '@google/gemini-cli',
        'Acme Endpoint Agent', 'font-fira-code-nerd-font', 'new-thing', '@scope/new-pkg', 'New-Thing', ''
        $known = 'terraform', 'zed', 'agy', 'headroom*', '@google/gemini-cli', 'Acme Endpoint Agent', 'font-*'

        # Act
        $unknown = @(Get-UnknownTools $raw $known)

        # Assert
        $unknown -join '|' | Should BeExactly '@scope/new-pkg|new-thing'
    }

    It 'KnownFileCommentsAndBlankLinesAreSkipped' {
        # Arrange
        $lines = '# managed by IT, never touched', '', '   ', 'Acme Endpoint Agent  # MDM', '  tool-* ', '#commented-out'

        # Act
        $patterns = @(Read-KnownPatterns $lines)

        # Assert
        $patterns -join '|' | Should BeExactly 'Acme Endpoint Agent|tool-*'
    }
}

Describe 'Test-Privacy checks' {
    It 'AntigravityCliFileAsAgyRewritesItIsOk' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir '.gemini/antigravity-cli/settings.json' '{"colorScheme":"dark","showFeedbackSurvey":false}' | Out-Null
        $cli = Get-Check $homeDir 'Antigravity CLI'

        # Act
        $result = Run @($cli)

        # Assert
        $result.Lines[0] | Should BeExactly 'ok         Antigravity CLI'
    }

    It 'AntigravityCliApplyWritesNoEnableTelemetry' {
        # Arrange
        $homeDir = New-Home
        $file = Write-HomeFile $homeDir '.gemini/antigravity-cli/settings.json' '{"colorScheme":"dark"}'

        # Act
        Run @(Get-Check $homeDir 'Antigravity CLI') 'apply' | Out-Null

        # Assert
        (Read-JsonFile $file).Keys -join '|' | Should BeExactly 'colorScheme|showFeedbackSurvey'
    }

    It 'AntigravityCliTelemetryIsManualAccountSetting' {
        # Arrange
        $homeDir = New-Home
        New-Item -ItemType Directory (Join-Path $homeDir '.gemini/antigravity-cli') | Out-Null
        $telemetry = Get-Check $homeDir 'Antigravity CLI telemetry'

        # Act
        $result = Run @($telemetry)

        # Assert
        $result.Lines[0] | Should Match '^manual     Antigravity CLI telemetry: account-level.*/config'
        $result.ExitCode | Should Be 0
    }

    It 'MissingLoginOptOutIsViolation' {
        # Arrange
        $homeDir = New-Home
        $optOuts = Write-HomeFile $homeDir 'opt-outs.zsh' "export A=1`nexport B=x"
        $envCheck = Get-Check $homeDir 'Env opt-outs in the login shell' (New-FakeTools @{ LoginEnv = { 'A=1', 'b=x' } }) $optOuts

        # Act
        $problems = @(& $envCheck.Test $envCheck)

        # Assert
        $problems -join '|' | Should BeExactly 'B is missing, want x'
    }

    It 'EnvFixSourcesOptOutsFromZprofile' {
        # Arrange
        $homeDir = New-Home
        $optOuts = Write-HomeFile $homeDir 'opt-outs.zsh' "export A=1`nexport B=x"
        $zprofile = Write-HomeFile $homeDir '.zprofile' 'export EDITOR=hx'
        $login = { param($HomePath) if ((Get-Content -LiteralPath (Join-Path $HomePath '.zprofile') -Raw) -match 'opt-outs') { 'A=1', 'B=x' } else { 'A=1' } }
        $envCheck = Get-Check $homeDir 'Env opt-outs in the login shell' (New-FakeTools @{ LoginEnv = $login }) $optOuts

        # Act
        $result = Run @($envCheck) 'apply'

        # Assert
        $result.Lines[0] | Should BeExactly 'fixed      Env opt-outs in the login shell'
        (Get-Content $zprofile) -join '|' | Should BeExactly "export EDITOR=hx|source `"$optOuts`""
        @(Get-ChildItem $homeDir -Force -Filter '.zprofile.bak-*').Count | Should Be 1
    }

    It 'EnvFixLeavesZprofileThatAlreadySourcesOptOuts' {
        # Arrange
        $homeDir = New-Home
        $optOuts = Write-HomeFile $homeDir 'opt-outs.zsh' "export A=1`nexport B=x"
        $zprofile = Write-HomeFile $homeDir '.zprofile' 'source "/somewhere/else/opt-outs.zsh"'
        $envCheck = Get-Check $homeDir 'Env opt-outs in the login shell' (New-FakeTools @{ LoginEnv = { 'A=1' } }) $optOuts

        # Act
        $result = Run @($envCheck) 'apply'

        # Assert
        $result.Lines[0] | Should Match '^VIOLATION  Env opt-outs in the login shell: B is missing, want x \(still wrong after the fix'
        (Get-Content $zprofile) -join '|' | Should BeExactly 'source "/somewhere/else/opt-outs.zsh"'
    }

    It 'DebugLoggingInLoginEnvIsViolation' {
        # Arrange
        $tools = New-FakeTools @{ LoginEnv = { 'RUST_LOG=info,herdr=debug', 'OLLAMA_DEBUG=1', 'ANTHROPIC_LOG=info', 'HERDR_LOG=warn' } }
        $debug = Get-Check (New-Home) 'Debug logging off in the login shell' $tools

        # Act
        $problems = @(& $debug.Test $debug)

        # Assert
        $problems -join '|' | Should BeExactly 'RUST_LOG is info,herdr=debug|OLLAMA_DEBUG is 1'
    }

    It 'LoginShellRunsOnceForBothEnvChecks' {
        # Arrange
        $homeDir = New-Home
        $optOuts = Write-HomeFile $homeDir 'opt-outs.zsh' 'export A=1'
        $calls = @{ Count = 0 }
        $tools = New-FakeTools @{ LoginEnv = { $calls.Count++; 'A=1' }.GetNewClosure() }
        $checks = Get-PrivacyChecks -HomePath $homeDir -OptOuts $optOuts -KnownFile (Join-Path $homeDir 'known.txt') -Tools $tools | Where-Object Name -like '* in the login shell'

        # Act
        Run $checks | Out-Null

        # Assert
        $calls.Count | Should Be 1
    }

    It 'OllamaApplyBacksUpBeforeUpdate' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/Application Support/Ollama/db.sqlite' 'db' | Out-Null
        $state = @{ Row = '[{"survey":1,"auto_update_enabled":1,"expose":0}]'; Log = [Collections.Generic.List[string]]::new() }
        $sqlite = {
            param([string[]]$Arguments)
            $state.Log.Add(($Arguments[-1] -split ' ')[0])
            if ($Arguments[-1] -match "^\.backup '(.+)'$") { Set-Content -LiteralPath $Matches[1] 'copy' }
            elseif ($Arguments[-1] -like 'update *') { $state.Row = '[{"survey":0,"auto_update_enabled":0,"expose":0}]' }
            else { $state.Row }
        }.GetNewClosure()
        $ollama = Get-Check $homeDir 'Ollama' (New-FakeTools @{ Sqlite = $sqlite })

        # Act
        $result = Run @($ollama) 'apply'

        # Assert
        $result.Lines[0] | Should BeExactly 'fixed      Ollama'
        $state.Log -join '|' | Should BeExactly 'select|.backup|update|select'
    }

    It 'OllamaIsLeftAloneWhileItRuns' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/Application Support/Ollama/db.sqlite' 'db' | Out-Null
        $log = [Collections.Generic.List[string]]::new()
        $sqlite = { param([string[]]$Arguments) $log.Add(($Arguments[-1] -split ' ')[0]); '[{"survey":1,"auto_update_enabled":0,"expose":0}]' }.GetNewClosure()
        $ollama = Get-Check $homeDir 'Ollama' (New-FakeTools @{ Sqlite = $sqlite })

        # Act
        $result = Run @($ollama) 'apply' { param($App) $App -eq 'Ollama' }

        # Assert
        $result.Lines[0] | Should BeExactly 'VIOLATION  Ollama: survey is 1, want 0 (close Ollama and re-run)'
        $log -join '|' | Should BeExactly 'select'
    }

    It 'BrewAnalyticsOnIsFixedWithBrewAnalyticsOff' {
        # Arrange
        $state = @{ On = $true; Calls = [Collections.Generic.List[string]]::new() }
        $brew = {
            param([string[]]$Arguments)
            $state.Calls.Add($Arguments -join ' ')
            if ($Arguments[1] -eq 'off') { $state.On = $false }
            elseif ($state.On) { 'InfluxDB analytics are enabled.' } else { 'InfluxDB analytics are disabled.' }
        }.GetNewClosure()
        $check = Get-Check (New-Home) 'Homebrew analytics' (New-FakeTools @{ Has = { $true }; Brew = $brew })

        # Act
        $result = Run @($check) 'apply'

        # Assert
        $result.Lines[0] | Should BeExactly 'fixed      Homebrew analytics'
        $state.Calls -join '|' | Should BeExactly 'analytics state|analytics off|analytics state'
    }

    It 'GhWithoutTelemetryKeyIsViolation' {
        # Arrange
        $check = Get-Check (New-Home) 'gh telemetry' (New-FakeTools @{ Has = { $true }; Gh = { 'git_protocol=https', 'prompt=enabled' } })

        # Act
        $result = Run @($check)

        # Assert
        $result.Lines[0] | Should BeExactly 'VIOLATION  gh telemetry: telemetry is missing, want disabled (fix: gh config set telemetry disabled)'
    }

    It 'BrewAbsentIsNotApplicable' {
        # Arrange
        $check = Get-Check (New-Home) 'Homebrew analytics'

        # Act
        $result = Run @($check)

        # Assert
        $result.Lines[0] | Should BeExactly 'n/a        Homebrew analytics (not installed)'
        $result.ExitCode | Should Be 0
    }

    It 'EveryCheckedPathIsUnderHome' {
        # Arrange
        $homeDir = New-Home

        # Act
        $checks = Get-PrivacyChecks -HomePath $homeDir -OptOuts (Join-Path $homeDir 'opt-outs.zsh') -KnownFile (Join-Path $homeDir 'known.txt') -Tools (New-FakeTools)

        # Assert
        $paths = @($checks | ForEach-Object { $_.Files; $_.Data.File; $_.Data.Marker; $_.Data.Db; $_.Data.KnownFile } | Where-Object { $_ })
        $paths.Count | Should BeGreaterThan 15
        @($paths | Where-Object { -not $_.StartsWith($homeDir) }) -join '|' | Should BeExactly ''
    }

    It 'CheckNamesAreUnique' {
        # Arrange
        $homeDir = New-Home

        # Act
        $checks = Get-PrivacyChecks -HomePath $homeDir -OptOuts (Join-Path $homeDir 'opt-outs.zsh') -KnownFile (Join-Path $homeDir 'known.txt') -Tools (New-FakeTools)

        # Assert
        @($checks.Name | Group-Object | Where-Object Count -gt 1).Name -join '|' | Should BeExactly ''
    }

    It 'PluginCachePathBecomesMarketplaceCheckout' {
        # Arrange
        $homeDir = New-Home
        $stable = Write-HomeFile $homeDir '.claude/plugins/marketplaces/m/skills/privacy/opt-outs.zsh' 'export A=1'
        $cached = Write-HomeFile $homeDir '.claude/plugins/cache/m/p/1.2.3/skills/privacy/opt-outs.zsh' 'export A=1'

        # Act
        $path = Get-StablePath $cached

        # Assert
        $path | Should BeExactly $stable
    }

    It 'PluginCachePathStaysWithoutMarketplaceCopy' {
        # Arrange
        $homeDir = New-Home
        $cached = Write-HomeFile $homeDir '.claude/plugins/cache/m/p/1.2.3/skills/privacy/opt-outs.zsh' 'export A=1'

        # Act
        $path = Get-StablePath $cached

        # Assert
        $path | Should BeExactly $cached
    }

    It 'ParallelsAutoDownloadOnIsViolation' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/Preferences/com.parallels.Parallels Desktop.plist' '' | Out-Null
        $check = Get-Check $homeDir 'Parallels Desktop' (New-FakeTools @{ Defaults = { param($a) if ($a[2] -like '*Check for updates') { '2' } else { '1' } } })

        # Act
        $result = Run @($check)

        # Assert
        $result.Lines[0] | Should BeExactly 'VIOLATION  Parallels Desktop: Download updates automatically is 1, want 0 (fix: Preferences → General → Check for updates and Download updates automatically off)'
    }

    It 'ParallelsAutoDownloadOffIsOk' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/Preferences/com.parallels.Parallels Desktop.plist' '' | Out-Null
        $check = Get-Check $homeDir 'Parallels Desktop' (New-FakeTools @{ Defaults = { param($a) if ($a[2] -like '*Check for updates') { '2' } else { '0' } } })

        # Act
        $result = Run @($check)

        # Assert
        $result.Lines[0] | Should BeExactly 'ok         Parallels Desktop'
    }

    It 'ParallelsUpdateCheckOnIsViolation' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/Preferences/com.parallels.Parallels Desktop.plist' '' | Out-Null
        $check = Get-Check $homeDir 'Parallels Desktop' (New-FakeTools @{ Defaults = { param($a) if ($a[2] -like '*Check for updates') { '1' } else { '0' } } })

        # Act
        $result = Run @($check)

        # Assert
        $result.Lines[0] | Should Match 'Check for updates is 1, want 2'
    }

    It 'OrcaOptedInIsViolation' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/Application Support/orca/profiles/local-default/profile-state.db' '' | Out-Null
        $check = Get-Check $homeDir 'Orca' (New-FakeTools @{ Sqlite = { '1' } })

        # Act
        $result = Run @($check)

        # Assert
        $result.Lines[0] | Should BeExactly 'VIOLATION  Orca: telemetry.optedIn is true, want false (fix: Settings → Privacy → telemetry (PostHog) off)'
    }

    It 'OrcaUnreadableOptInIsViolation' {
        # Arrange
        $homeDir = New-Home
        Write-HomeFile $homeDir 'Library/Application Support/orca/profiles/local-default/profile-state.db' '' | Out-Null
        $check = Get-Check $homeDir 'Orca'

        # Act
        $result = Run @($check)

        # Assert
        $result.ExitCode | Should Be 1
    }
}
