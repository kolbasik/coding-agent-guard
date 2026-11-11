# Telemetry, surveys, needless update checks and debug logging on a Mac: one line per check.
# Owner: coding-agent-guard's privacy skill, whose SKILL.md says why each switch exists.
#
#   status  ok, VIOLATION <what> (fix: ...), n/a (not installed), manual (only the app's own settings
#           can change it) or REVIEW (installed, never assessed). Exits 1 when any line is VIOLATION or REVIEW.
#   apply   for each VIOLATION with an automatic fix: back the file up as <file>.bak-<yyyyMMdd-HHmm>,
#           fix it, check it again. A GUI app's config is left alone while the app runs, and no
#           config is created for an app that is not installed. A JSONC file loses its comments
#           on apply; its backup keeps them.
#
# Usage:  pwsh -NoProfile -File Test-Privacy.ps1 [-Action status|apply] [-HomePath <dir>] [-KnownFile <file>]
#         No -Action means status, so a bare run changes nothing. Every file a check reads or
#         writes is under -HomePath; the tests (Test-Privacy.Tests.ps1, beside this file) point it at a fixture.
#         -KnownFile lists your own assessed tools, one -like pattern per line, # starts a comment;
#         a missing file adds no names.
#Requires -Version 7
param([ValidateSet('status', 'apply')][string]$Action = 'status', [string]$HomePath = $HOME,
    [string]$KnownFile = (Join-Path $HomePath '.claude/coding-agent-guard/privacy-known.txt'))
$ErrorActionPreference = 'Stop'

# --- Parsers: text in, values out, no I/O. ---

# `export NAME=VALUE` lines (opt-outs.zsh) as NAME -> VALUE, quotes stripped.
function Read-Exports([string[]]$Lines) {
    $map = [ordered]@{}
    foreach ($l in $Lines) { if ($l -match '^\s*export\s+([A-Za-z_]\w*)=(.*?)\s*$') { $map[$Matches[1]] = $Matches[2].Trim('"', "'") } }
    $map
}

# `env` output as NAME -> VALUE. Ordinal: env names are case-sensitive (npm_config_update_notifier).
function Read-EnvLines([string[]]$Lines) {
    $map = [hashtable]::new([StringComparer]::Ordinal)
    foreach ($l in $Lines) { if ($l -match '^([A-Za-z_]\w*)=(.*)$') { $map[$Matches[1]] = $Matches[2] } }
    $map
}

# The value of `key = value` (Ghostty) or `key=value` (Java .prefs, DBeaver); the last line wins. $null when absent.
function Get-KeyValue([string[]]$Lines, [string]$Key) {
    $hit = @($Lines) -match "^\s*$([regex]::Escape($Key))\s*=" | Select-Object -Last 1
    if ($hit) { ($hit -split '=', 2)[1].Trim() }
}

function Set-KeyValue([string[]]$Lines, [string]$Key, [string]$Value, [string]$Separator) {
    $pattern = "^\s*$([regex]::Escape($Key))\s*="
    if (@($Lines) -match $pattern) { foreach ($l in $Lines) { if ($l -match $pattern) { "$Key$Separator$Value" } else { $l } } }
    else { @($Lines) + "$Key$Separator$Value" }
}

# Every `key = value` line of a TOML file as (Table, Key, Value); Table '' is the root, above the first [table].
# shortcut: reads [table] blocks only, not inline tables or dotted keys; upgrade if a checked file starts using them.
function Read-Toml([string[]]$Lines) {
    $table = ''
    foreach ($l in $Lines) {
        if ($l -match '^\s*\[\[?\s*([^\]]+?)\s*\]') { $table = $Matches[1] }
        elseif ($l -match '^\s*([\w-]+)\s*=\s*([^#]*?)\s*(#.*)?$') { [pscustomobject]@{ Table = $table; Key = $Matches[1]; Value = $Matches[2] } }
    }
}

# 'update.version_check' -> table 'update', key 'version_check'; a key without a dot is a root key.
function Split-TomlKey([string]$Name) { if ($Name -match '^(.*)\.([^.]+)$') { $Matches[1], $Matches[2] } else { '', $Name } }

# $Lines with $Key = $Value in [$Table] ('' = the root): replaced where it is, added at the end of
# the table, or added under a new [$Table] at the end of the file.
function Set-TomlValue([string[]]$Lines, [string]$Table, [string]$Key, [string]$Value) {
    $out = [Collections.Generic.List[string]]::new()
    $current = ''; $done = $false
    $isKey = "^\s*$([regex]::Escape($Key))\s*="
    foreach ($l in $Lines) {
        if ($l -match '^\s*\[\[?\s*([^\]]+?)\s*\]') {
            $next = $Matches[1]
            if (-not $done -and $current -eq $Table) { $out.Add("$Key = $Value"); $done = $true }
            $current = $next
        }
        elseif ($current -eq $Table -and $l -match $isKey) {
            if (-not $done) { $out.Add("$Key = $Value"); $done = $true }
            continue
        }
        $out.Add($l)
    }
    if (-not $done) {
        if ($current -ne $Table) { $out.Add(''); $out.Add("[$Table]") }
        $out.Add("$Key = $Value")
    }
    $out
}

# A JSON or JSONC file (comments, trailing commas: pwsh's parser takes both) as an ordered hashtable; empty when absent.
function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return [ordered]@{} }
    $text = Get-Content -LiteralPath $Path -Raw
    if (-not "$text".Trim()) { return [ordered]@{} }
    ConvertFrom-Json -InputObject $text -AsHashtable
}

# Key 'a/b' is b inside object a. A key with dots ('telemetry.feedback.enabled') is one flat key, as VS Code-style apps store it.
function Get-JsonValue($Object, [string]$Path) {
    foreach ($part in $Path -split '/') {
        if ($Object -isnot [Collections.IDictionary] -or -not $Object.Contains($part)) { return $null }
        $Object = $Object[$part]
    }
    , $Object
}

function Set-JsonValue([Collections.IDictionary]$Object, [string]$Path, $Value) {
    $parts = $Path -split '/'
    foreach ($part in $parts | Select-Object -SkipLast 1) {
        if ($Object[$part] -isnot [Collections.IDictionary]) { $Object[$part] = [ordered]@{} }
        $Object = $Object[$part]
    }
    $Object[$parts[-1]] = $Value
}

function Read-Lines([string]$Path) { if (Test-Path -LiteralPath $Path) { Get-Content -LiteralPath $Path } }

# One problem line when $Actual is not $Want; both are display text.
function Compare-Value([string]$Key, $Actual, [string]$Want) {
    if ($null -eq $Actual) { "$Key is missing, want $Want" } elseif ("$Actual" -cne $Want) { "$Key is $Actual, want $Want" }
}

# Raw names from brew, npm, uv, ~/.local/bin and /Applications as tool names.
function ConvertTo-ToolName([string]$Raw) {
    $n = $Raw.Trim()
    if (-not $n -or $n.StartsWith('-')) { return }                    # uv tool list prints each entry point as "- name"
    $n = $n -replace '\s+v\d[\w.+-]*$' -replace '\.app$' -replace '\.\d+\.old$'   # "headroom-ai v0.41.0", "Zed.app", agy's self-update leftover
    if (-not $n.StartsWith('@')) { $n = ($n -split '/')[-1] }        # "hashicorp/tap/terraform", but not "@scope/pkg"
    $n
}

# Installed names no -like pattern in $Known covers, sorted and without case duplicates.
function Get-UnknownTools([string[]]$Raw, [string[]]$Known) {
    $names = @($Raw | ForEach-Object { ConvertTo-ToolName $_ } | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($n in $names) { if (-not ($Known | Where-Object { $n -like $_ })) { $n } }
}

# The known file's -like patterns: # starts a comment, anywhere on the line; blank lines are skipped.
function Read-KnownPatterns([string[]]$Lines) {
    foreach ($l in $Lines) { $p = ($l -replace '#.*$').Trim(); if ($p) { $p } }
}

# --- Checks as data. Building the list runs nothing. ---

# Kind: check (Test returns problem lines, Fix is $null when only the user can fix it), manual (Hint is what to
# click, Test may add a note), clean (assessed, Hint is why) or sweep (Test returns unassessed tool names).
# Data.Marker, when set, is the path whose absence means the app is not installed.
function New-Check([string]$Name, [scriptblock]$Test, [scriptblock]$Fix, [string]$Hint = '-Action apply', [string]$App,
    [string[]]$Files = @(), [hashtable]$Data = @{}, [string]$Kind = 'check',
    [scriptblock]$Installed = { param($c) -not $c.Data.Marker -or (Test-Path -LiteralPath $c.Data.Marker) }) {
    [pscustomobject]@{ Name = $Name; Kind = $Kind; Test = $Test; Fix = $Fix; Hint = $Hint; App = $App; Files = $Files; Data = $Data; Installed = $Installed }
}

# -Command: the tool also counts as installed when that command is on PATH, since a Homebrew install lands outside the home.
function New-JsonCheck([string]$Name, [string]$File, [Collections.IDictionary]$Want, [string]$App, [string]$Marker = (Split-Path $File),
    [string]$Command, [hashtable]$Tools) {
    New-Check $Name -App $App -Files $File -Hint "-Action apply, or edit $File" -Data @{ File = $File; Want = $Want; Marker = $Marker; Command = $Command; Tools = $Tools } -Installed {
        param($c)
        -not $c.Data.Marker -or (Test-Path -LiteralPath $c.Data.Marker) -or ($c.Data.Command -and (& $c.Data.Tools.Has $c.Data.Command))
    } -Test {
        param($c)
        $json = Read-JsonFile $c.Data.File
        foreach ($k in $c.Data.Want.Keys) {
            $actual = Get-JsonValue $json $k
            Compare-Value ($k -replace '/', '.') $(if ($null -ne $actual) { ConvertTo-Json $actual -Compress }) (ConvertTo-Json $c.Data.Want[$k] -Compress)
        }
    } -Fix {
        param($c)
        $json = Read-JsonFile $c.Data.File
        foreach ($k in $c.Data.Want.Keys) { Set-JsonValue $json $k $c.Data.Want[$k] }
        New-Item -ItemType Directory -Force (Split-Path $c.Data.File) | Out-Null
        ConvertTo-Json -InputObject $json -Depth 100 | Set-Content -LiteralPath $c.Data.File
    }
}

function New-KeyValueCheck([string]$Name, [string]$File, [Collections.IDictionary]$Want, [string]$Separator, [string]$App) {
    New-Check $Name -App $App -Files $File -Hint "-Action apply, or edit $File" -Data @{ File = $File; Want = $Want; Separator = $Separator; Marker = (Split-Path $File) } -Test {
        param($c)
        $lines = Read-Lines $c.Data.File
        foreach ($k in $c.Data.Want.Keys) { Compare-Value $k (Get-KeyValue $lines $k) $c.Data.Want[$k] }
    } -Fix {
        param($c)
        $lines = Read-Lines $c.Data.File
        foreach ($k in $c.Data.Want.Keys) { $lines = @(Set-KeyValue $lines $k $c.Data.Want[$k] $c.Data.Separator) }
        Set-Content -LiteralPath $c.Data.File $lines
    }
}

# A root key (no dot) written under a [table] belongs to that table, so the app never reads it; the fix moves it.
function New-TomlCheck([string]$Name, [string]$File, [Collections.IDictionary]$Want) {
    New-Check $Name -Files $File -Hint "-Action apply, or edit $File" -Data @{ File = $File; Want = $Want; Marker = (Split-Path $File) } -Test {
        param($c)
        $toml = @(Read-Toml (Read-Lines $c.Data.File))
        foreach ($k in $c.Data.Want.Keys) {
            $table, $key = Split-TomlKey $k
            $hit = $toml | Where-Object { $_.Table -eq $table -and $_.Key -eq $key } | Select-Object -First 1
            $under = $toml | Where-Object { $_.Key -eq $key -and $_.Table } | Select-Object -First 1
            if (-not $hit -and -not $table -and $under) { "$key sits under [$($under.Table)], where it is never read; want it above the first [table]" }
            else { Compare-Value $k $hit.Value $c.Data.Want[$k] }
        }
    } -Fix {
        param($c)
        $lines = @(Read-Lines $c.Data.File)
        foreach ($k in $c.Data.Want.Keys) {
            $table, $key = Split-TomlKey $k
            if (-not $table) { $lines = @($lines | Where-Object { $_ -notmatch "^\s*$([regex]::Escape($key))\s*=" }) }
            $lines = @(Set-TomlValue $lines $table $key $c.Data.Want[$k])
        }
        Set-Content -LiteralPath $c.Data.File $lines
    }
}

# The login env, read once and shared by the env and debug checks; a fix clears it so the re-check reads it again.
function Get-LoginEnv($Check) {
    $shell = $Check.Data.Shell
    if ($null -eq $shell.Env) { $shell.Env = Read-EnvLines (& $shell.Tools.LoginEnv $shell.HomePath) }
    $shell.Env
}

# Every check, in the order the skill lists them. $Tools holds the scriptblocks that reach outside -HomePath
# (zsh, brew, gh, sqlite3, the installed-tool inventory), so the tests can fake them.
function Get-PrivacyChecks([Parameter(Mandatory)][string]$HomePath, [Parameter(Mandatory)][string]$OptOuts, [Parameter(Mandatory)][string]$KnownFile,
    [Parameter(Mandatory)][hashtable]$Tools) {
    $support = Join-Path $HomePath 'Library/Application Support'
    $zprofile = Join-Path $HomePath '.zprofile'
    $shell = @{ Tools = $Tools; HomePath = $HomePath; Env = $null }

    New-Check 'Env opt-outs in the login shell' -Files $zprofile -Data @{ Shell = $shell; OptOuts = $OptOuts; Zprofile = $zprofile } `
        -Hint "source `"$OptOuts`" from ~/.zprofile; if it is sourced already, a later line overrides it" -Test {
        param($c)
        $login = Get-LoginEnv $c
        $want = Read-Exports (Read-Lines $c.Data.OptOuts)
        foreach ($k in $want.Keys) { Compare-Value $k $login[$k] $want[$k] }
    } -Fix {
        param($c)
        if (-not (@(Read-Lines $c.Data.Zprofile) -match '^\s*(source|\.)\s.*opt-outs\.zsh')) {
            Add-Content -LiteralPath $c.Data.Zprofile "source `"$($c.Data.OptOuts)`""
        }
        $c.Data.Shell.Env = $null
    }
    New-Check 'Debug logging off in the login shell' -Data @{ Shell = $shell } -Hint 'remove it from the shell startup files' -Test {
        param($c)
        $login = Get-LoginEnv $c
        foreach ($k in 'RUST_LOG', 'HERDR_LOG', 'ANTHROPIC_LOG') { if ($login[$k] -match 'debug|trace') { "$k is $($login[$k])" } }
        if ($login['OLLAMA_DEBUG'] -and $login['OLLAMA_DEBUG'] -notmatch '^(0|false)$') { "OLLAMA_DEBUG is $($login['OLLAMA_DEBUG'])" }
    }

    New-JsonCheck 'Claude Code' (Join-Path $HomePath '.claude/settings.json') ([ordered]@{
            'env/DISABLE_TELEMETRY' = '1'; 'env/DISABLE_ERROR_REPORTING' = '1'; 'env/CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY' = '1' })
    New-TomlCheck 'Codex config.toml' (Join-Path $HomePath '.codex/config.toml') ([ordered]@{
            check_for_update_on_startup = 'false'; 'analytics.enabled' = 'false'; 'feedback.enabled' = 'false' })
    New-JsonCheck 'Codex app-server daemon' (Join-Path $HomePath '.codex/app-server-daemon/settings.json') ([ordered]@{ 'updater/autoUpdateEnabled' = $false })
    $gemini = Join-Path $HomePath '.gemini/settings.json'
    New-JsonCheck 'Gemini CLI' $gemini ([ordered]@{
            'privacy/usageStatisticsEnabled' = $false; 'general/enableAutoUpdate' = $false; 'general/enableAutoUpdateNotification' = $false }) -Marker $gemini
    $agyCli = Join-Path $HomePath '.gemini/antigravity-cli'
    New-JsonCheck 'Antigravity CLI' (Join-Path $agyCli 'settings.json') ([ordered]@{ showFeedbackSurvey = $false })
    # Its Enable Telemetry has no settings.json key (agy 1.5.3: the field is tagged json:"-"); agy reads it from the
    # account at each start and drops an enableTelemetry key from the file.
    New-Check 'Antigravity CLI telemetry' -Kind manual -Data @{ Marker = $agyCli } `
        -Hint 'account-level, unreadable here; keep /config → Enable Telemetry off in agy (saved with the Google account)'
    New-JsonCheck 'Antigravity IDE' (Join-Path $support 'Antigravity IDE/User/settings.json') ([ordered]@{
            'telemetry.telemetryLevel' = 'off'; 'telemetry.feedback.enabled' = $false; 'update.mode' = 'manual'; 'extensions.autoCheckUpdates' = $false }) `
        -App 'Antigravity IDE' -Marker (Join-Path $support 'Antigravity IDE')
    New-JsonCheck 'Zed' (Join-Path $HomePath '.config/zed/settings.json') ([ordered]@{
            'telemetry/diagnostics' = $false; 'telemetry/metrics' = $false; 'telemetry/anthropic_retention' = $false; auto_update = $false
            'edit_predictions/allow_data_collection' = 'no'; 'agent/enable_feedback' = $false }) -App 'Zed'
    New-TomlCheck 'herdr' (Join-Path $HomePath '.config/herdr/config.toml') ([ordered]@{ 'update.version_check' = 'false'; 'update.manifest_check' = 'false' })
    # The app checks releases.herdr.dev hourly and has no switch for it; only its daily usage report has one.
    New-JsonCheck 'Herdr app' (Join-Path $HomePath '.config/herdr-app/settings.json') ([ordered]@{ telemetry = $false }) -App 'Herdr'
    New-Check 'herdr-core' -Kind clean -Hint 'hc sends no telemetry; reaches releases.herdr.dev only on hc update, and serve opened no socket over 20 s'
    New-KeyValueCheck 'Ghostty' (Join-Path $support 'com.mitchellh.ghostty/config.ghostty') ([ordered]@{ 'auto-update' = 'off' }) ' = ' -App 'Ghostty'
    New-JsonCheck 'Obsidian' (Join-Path $support 'obsidian/obsidian.json') ([ordered]@{ updateDisabled = $true }) -App 'Obsidian'
    $dbeaver = Join-Path $HomePath 'Library/DBeaverData/workspace6/.metadata/.plugins/org.eclipse.core.runtime/.settings'
    New-KeyValueCheck 'DBeaver update check' (Join-Path $dbeaver 'org.jkiss.dbeaver.core.prefs') ([ordered]@{ 'ui.auto.update.check' = 'false' }) '=' -App 'DBeaver'
    New-KeyValueCheck 'DBeaver feature tracking' (Join-Path $dbeaver 'org.jkiss.dbeaver.ui.statistics.prefs') ([ordered]@{ 'feature.tracking.enabled' = 'false' }) '=' -App 'DBeaver'

    $ollama = Join-Path $support 'Ollama/db.sqlite'
    New-Check 'Ollama' -App 'Ollama' -Data @{ Marker = $ollama; Tools = $Tools } -Hint "-Action apply, or the Ollama app's settings" -Test {
        param($c)
        $json = (& $c.Data.Tools.Sqlite @('-readonly', '-json', $c.Data.Marker, 'select survey, auto_update_enabled, expose from settings')) -join "`n"
        if (-not $json.Trim()) { return 'no settings row could be read' }
        $row = @(ConvertFrom-Json -InputObject $json)[0]
        foreach ($k in 'survey', 'auto_update_enabled', 'expose') { Compare-Value $k $row.$k '0' }
    } -Fix {
        param($c)
        # sqlite3 .backup, not a file copy: a copy of a live database can be torn.
        $bak = Get-BackupPath $c.Data.Marker
        if (-not (Test-Path -LiteralPath $bak)) { & $c.Data.Tools.Sqlite @($c.Data.Marker, ".backup '$($bak -replace "'", "''")'") | Out-Null }
        if (-not (Test-Path -LiteralPath $bak)) { throw "no backup at $bak, nothing changed" }
        & $c.Data.Tools.Sqlite @($c.Data.Marker, 'update settings set survey = 0, auto_update_enabled = 0, expose = 0') | Out-Null
    }

    New-JsonCheck 'Podman Desktop' (Join-Path $HomePath '.local/share/containers/podman-desktop/configuration/settings.json') ([ordered]@{
            'telemetry.enabled' = $false; 'feedback.dialog' = $false; 'preferences.update.reminder' = 'never'; 'preferences.update.appUpdate' = $false
            'extensions.autoCheckUpdates' = $false; 'extensions.autoUpdate' = $false }) -App 'Podman Desktop' -Marker (Join-Path $HomePath '.local/share/containers/podman-desktop')
    # Installed means the binary, not the settings file: DO_NOT_TRACK covers its telemetry, but its update check is on
    # until settings.json says off, and that file only appears once a setting is changed.
    New-JsonCheck 'terminal-browser' (Join-Path $HomePath '.config/terminal-browser/settings.json') ([ordered]@{
            'telemetry.usage' = 'off'; 'telemetry.crashReports' = 'off'; 'updates.check' = 'off' }) -Marker (Join-Path $HomePath '.local/bin/terminal-browser') `
        -Command 'terminal-browser' -Tools $Tools
    New-JsonCheck 'SourceGit' (Join-Path $support 'SourceGit/preference.json') ([ordered]@{ Check4UpdatesOnStartup = $false }) -App 'SourceGit'

    New-Check 'Homebrew analytics' -Data @{ Tools = $Tools } -Hint 'brew analytics off' -Installed { param($c) & $c.Data.Tools.Has 'brew' } -Test {
        param($c)
        $state = (& $c.Data.Tools.Brew @('analytics', 'state')) -join ' '
        if ($state -notmatch 'analytics are disabled') { "brew analytics state says: $state" }
    } -Fix { param($c) & $c.Data.Tools.Brew @('analytics', 'off') | Out-Null }
    New-Check 'gh telemetry' -Data @{ Tools = $Tools } -Hint 'gh config set telemetry disabled' -Installed { param($c) & $c.Data.Tools.Has 'gh' } -Test {
        param($c)
        $line = @(& $c.Data.Tools.Gh @('config', 'list')) -match '^telemetry=' | Select-Object -First 1
        Compare-Value 'telemetry' $(if ($line) { $line -replace '^telemetry=' }) 'disabled'
    } -Fix { param($c) & $c.Data.Tools.Gh @('config', 'set', 'telemetry', 'disabled') | Out-Null }

    New-Check 'jq' -Kind clean -Hint 'links no network library (otool -L) and reads only its input'
    New-Check 'yq' -Kind clean -Hint 'no telemetry or update-check strings in the binary; reads local files'
    New-Check 'yazi' -Kind clean -Hint 'no telemetry or update check; reaches the network only when ya pkg fetches a plugin on request'
    New-Check 'uv' -Kind clean -Hint 'no telemetry; sends a platform user agent to PyPI on installs, and no switch turns that off'
    New-Check 'nvm' -Kind clean -Hint 'a shell function; reaches nodejs.org only on nvm install and ls-remote'
    New-Check 'docker' -Kind clean -Hint 'the Homebrew CLI only; no update check, and it exports OTEL metrics only to an endpoint a context or DOCKER_CLI_OTEL_EXPORTER_OTLP_ENDPOINT names (the podman context names none); lsof saw only unix sockets during docker run'
    New-Check 'rtk' -Kind clean -Hint 'the Homebrew build has no telemetry endpoint (rtk telemetry status), and RTK_TELEMETRY_DISABLED=1 blocks it anyway; no update check'
    New-Check 'cfn-lint' -Kind clean -Hint 'reaches AWS only on --update-specs, --update-iam-policies or --update-documentation; a lint behind a proxy trap opened no socket'
    New-Check 'conftest' -Kind clean -Hint 'reaches the network only on conftest pull or a remote --update URL; test and --version behind a proxy trap opened no socket'

    $orcaDb = Join-Path $support 'orca/profiles/local-default/profile-state.db'
    New-Check 'Orca' -App 'Orca' -Hint 'Settings → Privacy → telemetry (PostHog) off' -Data @{ Tools = $Tools; Marker = $orcaDb } -Test {
        param($c)
        # immutable=1: Orca keeps the database in WAL mode, where a plain -readonly open fails without the -shm file.
        $v = "$(& $c.Data.Tools.Sqlite @("file:$($c.Data.Marker)?mode=ro&immutable=1", 'select json_extract(payload, ''$.telemetry.optedIn'') from profile_state_documents where domain = ''settings'''))".Trim()
        Compare-Value 'telemetry.optedIn' $(if ($v -in '0', '1') { @{ '0' = 'false'; '1' = 'true' }[$v] }) 'false'
    }
    New-Check 'Antigravity app' -Kind manual -Hint 'account-level, unreadable here; keep Settings → Account → Enable Telemetry off' `
        -Data @{ Marker = (Join-Path $support 'Antigravity') }
    $parallels = Join-Path $HomePath 'Library/Preferences/com.parallels.Parallels Desktop.plist'
    # Both are checkboxes in Preferences → General; each shows unticked while they read 2 and 0.
    New-Check 'Parallels Desktop' -App 'Parallels Desktop' -Hint 'Preferences → General → Check for updates and Download updates automatically off' -Data @{ Tools = $Tools; Marker = $parallels } -Test {
        param($c)
        $want = [ordered]@{ 'Check for updates' = '2'; 'Download updates automatically' = '0' }
        foreach ($k in $want.Keys) {
            $v = "$(& $c.Data.Tools.Defaults @('read', 'com.parallels.Parallels Desktop', "Application preferences.$k"))".Trim()
            Compare-Value $k $(if ($v) { $v }) $want[$k]
        }
    }

    # -like patterns. A tool joins this list only with a reason in this script or SKILL.md; tools you assessed
    # yourself, and software you must leave alone, go in $KnownFile (SKILL.md, "Your own known tools").
    $known = @(
        # Checked above, or covered by an opt-out in opt-outs.zsh.
        'claude-code*', 'codex', 'codex-code-mode-host', '@google/gemini-cli', 'gemini-cli', 'antigravity-cli', 'agy', 'Antigravity IDE', 'Antigravity', 'zed',
        'herdr', 'ghostty', 'obsidian', 'dbeaver*', 'ollama*', 'podman-desktop', 'Podman Desktop', 'terminal-browser', 'sourcegit', 'gh',
        'python3*', 'rtk', 'Orca', 'Parallels Desktop', 'npm', 'dotnet-sdk', 'powershell', 'awscli', 'sops', 'opentofu', 'terraform', 'twg',
        # Assessed clean above, or in SKILL.md's "No off switch exists".
        'jq', 'yq', 'yazi', 'uv', 'nvm', 'docker', 'cfn-lint', 'conftest', 'context-mode', 'herdr-app', 'herdr-core', 'hc',
        # Font casks install font files only; Apple's bundled apps fall under macOS's own analytics setting.
        'font-*', 'Safari', 'GarageBand', 'Keynote', 'Numbers', 'Pages', 'iMovie', 'Utilities')
    New-Check 'Unknown-tool sweep' -Kind sweep -Hint "add it to $KnownFile" -Data @{ Tools = $Tools; HomePath = $HomePath; Known = $known; KnownFile = $KnownFile } -Test {
        param($c)
        $raw = @(& $c.Data.Tools.Inventory $c.Data.HomePath)
        if (-not $raw) { throw 'the inventory listed nothing, so nothing was swept' }
        Get-UnknownTools $raw (@($c.Data.Known) + @(Read-KnownPatterns (Read-Lines $c.Data.KnownFile)))
    }
}

# --- Engine. ---

function Get-BackupPath([string]$Path) { "$Path.bak-$(Get-Date -Format 'yyyyMMdd-HHmm')" }

# A Claude Code plugin cache path names one version, which goes once the plugin updates; ~/.zprofile must source a
# copy that stays, so a cache path becomes the same file in the marketplace checkout when that exists.
# shortcut: assumes the plugin sits at its marketplace's root, as this repo's marketplace.json says; upgrade if it moves.
function Get-StablePath([string]$Path) {
    $stable = $Path -replace '/\.claude/plugins/cache/([^/]+)/[^/]+/[^/]+/', '/.claude/plugins/marketplaces/$1/'
    if ($stable -ne $Path -and (Test-Path -LiteralPath $stable)) { $stable } else { $Path }
}

# Never overwrites a backup: a second apply in the same minute must not replace the original with a fixed copy.
function Backup-File([string]$Path) {
    $bak = Get-BackupPath $Path
    if ((Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $bak)) { Copy-Item -LiteralPath $Path $bak }
}

function Format-Line([string]$Status, [string]$Text) { '{0,-10} {1}' -f $Status, $Text }

function Get-CheckLines($Check, [string]$Action, [scriptblock]$IsRunning) {
    $c = $Check
    if (-not (& $c.Installed $c)) { return Format-Line 'n/a' "$($c.Name) (not installed)" }
    switch ($c.Kind) {
        'clean' { return Format-Line 'ok' "$($c.Name): assessed clean, $($c.Hint)" }
        'manual' {
            $note = if ($c.Test) { try { & $c.Test $c } catch { $null } }
            return Format-Line 'manual' ("$($c.Name): $($c.Hint)" + $(if ($note) { " ($note)" }))
        }
    }
    # An unreadable file is reported and never fixed: rewriting what could not be parsed would lose it.
    try { $problems = @(& $c.Test $c) } catch { return Format-Line 'VIOLATION' "$($c.Name): cannot read it: $($_.Exception.Message) (fix: $($c.Hint))" }
    if ($c.Kind -eq 'sweep') {
        if (-not $problems) { return Format-Line 'ok' "$($c.Name): every installed tool is assessed" }
        return $problems | ForEach-Object { Format-Line 'REVIEW' "${_}: installed, not assessed (assess it, then add a check or $($c.Hint))" }
    }
    if (-not $problems) { return Format-Line 'ok' $c.Name }
    $what = "$($c.Name): $($problems -join '; ')"
    if ($Action -eq 'status' -or -not $c.Fix) { return Format-Line 'VIOLATION' "$what (fix: $($c.Hint))" }
    if ($c.App -and (& $IsRunning $c.App)) { return Format-Line 'VIOLATION' "$what (close $($c.App) and re-run)" }
    try {
        foreach ($f in $c.Files) { Backup-File $f }
        & $c.Fix $c | Out-Null
        $left = @(& $c.Test $c)
    }
    catch { return Format-Line 'VIOLATION' "$what (fix failed: $($_.Exception.Message))" }
    if ($left) { Format-Line 'VIOLATION' "$($c.Name): $($left -join '; ') (still wrong after the fix; fix: $($c.Hint))" }
    else { Format-Line 'fixed' $c.Name }
}

# Runs every check, printing each line as it goes. Returns the lines and the exit code instead of
# exiting, so the tests can run it on fake checks.
function Invoke-PrivacyCheck([Parameter(Mandatory)][object[]]$Checks, [Parameter(Mandatory)][ValidateSet('status', 'apply')][string]$Action,
    [scriptblock]$IsRunning = { $false }) {
    $result = [pscustomobject]@{ ExitCode = 0; Lines = [Collections.Generic.List[string]]::new() }
    foreach ($c in $Checks) {
        foreach ($line in @(Get-CheckLines $c $Action $IsRunning)) {
            if ($line -match '^(VIOLATION|REVIEW) ') { $result.ExitCode = 1 }
            $result.Lines.Add($line)
            Write-Host $line
        }
    }
    $result
}

if (-not $IsMacOS) { throw 'macOS only.' }
$HomePath = (Resolve-Path -LiteralPath $HomePath).Path
$tools = @{
    # A clean login shell: an inherited opt-out must not hide one ~/.zprofile lost.
    LoginEnv  = { param($HomePath) env -i "HOME=$HomePath" "USER=$env:USER" 'PATH=/usr/bin:/bin:/usr/sbin:/sbin' zsh -lc env }
    Has       = { param($Name) [bool](Get-Command $Name -CommandType Application -ErrorAction Ignore) }
    Brew      = { param([string[]]$Arguments) env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew @Arguments 2>$null }
    Gh        = { param([string[]]$Arguments) gh @Arguments 2>$null }
    Sqlite    = { param([string[]]$Arguments) sqlite3 @Arguments 2>$null }
    Defaults  = { param([string[]]$Arguments) defaults @Arguments 2>$null }
    Inventory = {
        param($HomePath)
        $npm = "export NVM_DIR='$HomePath/.nvm'; . `"`$(brew --prefix nvm)/nvm.sh`"; npm ls -g --depth=0 --json --no-update-notifier"
        $sources = @(
            { env HOMEBREW_NO_AUTO_UPDATE=1 brew leaves }
            { env HOMEBREW_NO_AUTO_UPDATE=1 brew list --cask }
            { (bash -c $npm | ConvertFrom-Json -AsHashtable).dependencies.Keys }
            { uv tool list }
            { Get-ChildItem -LiteralPath (Join-Path $HomePath '.local/bin') -Name }
            { Get-ChildItem -LiteralPath '/Applications' -Name })
        foreach ($s in $sources) { try { & $s 2>$null } catch { Write-Host "  sweep source failed: $_" } }
    }
}
$isRunning = { param($App) [bool](ps -axo comm | Select-String -SimpleMatch "/$App.app/Contents/") }
$optOuts = Get-StablePath (Resolve-Path (Join-Path $PSScriptRoot '../opt-outs.zsh')).Path
$checks = Get-PrivacyChecks -HomePath $HomePath -OptOuts $optOuts -KnownFile $KnownFile -Tools $tools
$result = Invoke-PrivacyCheck $checks $Action $isRunning
if ($Action -eq 'apply') { "Apply run finished $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), exit $($result.ExitCode)." }
exit $result.ExitCode
