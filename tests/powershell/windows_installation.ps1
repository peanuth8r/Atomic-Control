param([string]$Root, [string]$Work, [string]$Case)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$helper = Join-Path $Root 'scripts/install-windows-execution-prerequisites.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($helper, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($function in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}

function Require { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Must-Fail { param([scriptblock]$Action) $failed = $false; try { & $Action } catch { $failed = $true }; Require $failed 'Expected operation to fail' }

New-Item -ItemType Directory -Path $Work -Force | Out-Null
if ($Case.StartsWith('tree-')) {
    $source = Join-Path $Work 'source'
    $destination = Join-Path $Work 'destination'
    New-Item -ItemType Directory -Path $source, $destination | Out-Null
    Set-Content -LiteralPath (Join-Path $source 'module.psm1') -Value 'pinned source'
    Copy-Item -LiteralPath (Join-Path $source 'module.psm1') -Destination $destination
    switch ($Case) {
        'tree-reuse' { Assert-AtomicFrameworkTree $source $destination }
        'tree-change' {
            Set-Content -LiteralPath (Join-Path $destination 'module.psm1') -Value 'modified source'
            Must-Fail { Assert-AtomicFrameworkTree $source $destination }
            Require ((Get-Content (Join-Path $destination 'module.psm1')) -eq 'modified source') 'Existing content was overwritten'
        }
        'tree-missing' {
            Remove-Item -LiteralPath (Join-Path $destination 'module.psm1')
            Must-Fail { Assert-AtomicFrameworkTree $source $destination }
        }
        'tree-extra' {
            Set-Content -LiteralPath (Join-Path $destination 'unexpected.ps1') -Value 'unexpected'
            Must-Fail { Assert-AtomicFrameworkTree $source $destination }
        }
        'tree-link' {
            New-Item -ItemType SymbolicLink -Path (Join-Path $destination 'linked') -Target $source | Out-Null
            Must-Fail { Assert-AtomicFrameworkTree $source $destination }
        }
        'tree-metadata' {
            Set-Content -LiteralPath (Join-Path $destination 'PSGetModuleInfo.xml') -Value 'client metadata'
            Assert-AtomicFrameworkTree $source $destination -AllowedExtraFiles @('PSGetModuleInfo.xml')
        }
        'tree-install' {
            Remove-Item -LiteralPath $destination -Recurse
            Set-Content -LiteralPath (Join-Path $source '.hidden-source') -Value 'also pinned'
            function Protect-AtomicFrameworkTree { param($Directory) Require (Test-Path $Directory) 'Protected tree is missing' }
            Install-AtomicVerifiedTree -Source $source -Destination $destination
            Assert-AtomicFrameworkTree $source $destination
            Require (Test-Path (Join-Path $destination '.hidden-source')) 'Hidden source files were omitted'
        }
        'tree-publish-failure' {
            Remove-Item -LiteralPath $destination -Recurse
            function Protect-AtomicFrameworkTree { param($Directory) throw 'Fixture ACL setup failed' }
            Must-Fail { Install-AtomicVerifiedTree -Source $source -Destination $destination }
            Require (-not (Test-Path $destination)) 'A half-installed dependency was published'
            Require (@(Get-ChildItem $Work -Filter '.execution-module-*').Count -eq 0) 'Failed staging tree remains'
        }
    }
} elseif ($Case.StartsWith('yaml-')) {
    $env:ProgramFiles = Join-Path $Work 'program-files'
    $fixture = Join-Path $Work 'gallery'
    New-Item -ItemType Directory -Path (Join-Path $fixture 'lib/net47') -Force | Out-Null
    Set-Content (Join-Path $fixture 'powershell-yaml.psd1') '@{ModuleVersion="0.4.12";RootModule="powershell-yaml.psm1"}'
    Set-Content (Join-Path $fixture 'powershell-yaml.psm1') '# fixture module: no execution'
    Set-Content (Join-Path $fixture 'lib/net47/fixture.dll') 'fixture assembly bytes'
    Set-Content (Join-Path $fixture 'LICENSE') 'fixture license'
    Set-Content (Join-Path $fixture 'README.md') 'fixture documentation'
    $global:galleryArchive = Join-Path $Work 'gallery.zip'
    Compress-Archive -Path (Join-Path $fixture '*') -DestinationPath $global:galleryArchive
    $global:badArchive = $Case -eq 'yaml-bad-hash'
    $global:protectedPaths = [Collections.Generic.List[string]]::new()
    function Invoke-WebRequest {
        param([switch]$UseBasicParsing, [string]$Uri, [string]$OutFile)
        Require ($Uri -eq 'https://www.powershellgallery.com/api/v2/package/powershell-yaml/0.4.12') 'Unexpected package source'
        Copy-Item -LiteralPath $global:galleryArchive -Destination $OutFile
    }
    function Get-FileHash {
        param([string]$LiteralPath, [string]$Algorithm)
        if ($LiteralPath.EndsWith('yaml.zip')) {
            $hash = if ($global:badArchive) { '0' * 64 } else { 'd4602bc7a4a093766520422d53ca8b09acde162286fae11e2ee6c8edfea07810' }
            return [pscustomobject]@{Hash=$hash}
        }
        Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
    }
    function Protect-AtomicFrameworkTree { param($Directory) $global:protectedPaths.Add($Directory) }
    function Install-Module { throw 'Installer must not invoke an interactive package manager' }
    function Set-PSRepository { throw 'Repository trust must not change' }
    $stage = Join-Path $Work 'stage1'
    New-Item -ItemType Directory -Path $stage | Out-Null
    $destination = Join-Path $env:ProgramFiles 'WindowsPowerShell/Modules/powershell-yaml/0.4.12'
    if ($global:badArchive) {
        Must-Fail { Install-AtomicYamlDependency -Stage $stage }
        Require (-not (Test-Path $destination)) 'Corrupt archive installed a module'
    } else {
        Install-AtomicYamlDependency -Stage $stage
        Require (Test-Path (Join-Path $destination 'powershell-yaml.psd1')) 'All-users YAML module is missing'
        Require (Test-Path (Join-Path $destination 'lib/net47/fixture.dll')) 'YAML runtime library is missing'
        Require ($global:protectedPaths.Count -eq 1) 'YAML module was not protected'
        $second = Join-Path $Work 'stage2'
        New-Item -ItemType Directory -Path $second | Out-Null
        if ($Case -eq 'yaml-reuse') {
            Set-Content (Join-Path $destination 'PSGetModuleInfo.xml') 'retained metadata'
            Install-AtomicYamlDependency -Stage $second
            Require ((Get-Content (Join-Path $destination 'PSGetModuleInfo.xml')) -eq 'retained metadata') 'Existing module metadata was overwritten'
        } elseif ($Case -eq 'yaml-change') {
            Set-Content (Join-Path $destination 'powershell-yaml.psm1') 'changed module'
            Must-Fail { Install-AtomicYamlDependency -Stage $second }
            Require ((Get-Content (Join-Path $destination 'powershell-yaml.psm1')) -eq 'changed module') 'Different module was silently overwritten'
        }
    }
} elseif ($Case.StartsWith('installer-')) {
    $installer = Join-Path $Root 'apps/agent/packaging/Install-Agent.ps1'
    $ast = [Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$parseErrors)
    Require ($parseErrors.Count -eq 0) 'Installer has syntax errors'
    $statements = @($ast.EndBlock.Statements)
    $first = -1
    for ($index = 0; $index -lt $statements.Count; $index++) {
        if ($statements[$index] -is [Management.Automation.Language.AssignmentStatementAst] -and $statements[$index].Left.Extent.Text -eq '$preparedConfigFile') { $first = $index; break }
    }
    Require ($first -ge 0) 'Installer enrollment preparation is missing'
    $phase = ($statements[$first..($statements.Count - 1)] | ForEach-Object { $_.Extent.Text }) -join "`n"
    $phaseFile = Join-Path $Work 'install-phase.ps1'
    [IO.File]::WriteAllText($phaseFile, $phase, [Text.UTF8Encoding]::new($false))
    $global:record = [Collections.Generic.List[string]]::new()
    $global:failFramework = $Case -eq 'installer-failure'
    $InstallRoot = Join-Path $Work 'installed'
    $runtime = Join-Path $InstallRoot 'runtime'
    $stateRoot = Join-Path $Work 'state'
    $scripts = Join-Path $runtime 'scripts'
    New-Item -ItemType Directory -Path $scripts, $stateRoot -Force | Out-Null
    $bootstrapFile = Join-Path $Work 'bootstrap.json'
    Set-Content $bootstrapFile '{"enrollment_token":"test-only-token"}'
    $original = Join-Path $Work 'agent.json'
    $packageConfig = [pscustomobject]@{
        actor_id = 'test-actor'; hostname = 'fixture-host'; profiles = @([pscustomobject]@{id='test-profile';account='test-user'})
        revision = ''; delivery_mode = 'on_demand'; state_root = 'original-path'
        invoke_module_path = 'missing'; invoke_module_sha256 = 'placeholder'
    }
    $packageConfig | ConvertTo-Json -Depth 10 | Set-Content $original
    if ($Case -eq 'installer-legacy') { $packageConfig.revision = 'pinned-catalog' }
    $before = (Get-FileHash $original).Hash
    @'
[CmdletBinding(SupportsShouldProcess)]
param($ConfigFile, $InstallRoot, [switch]$PrepareForEnrollment)
if (-not $PrepareForEnrollment) { throw 'Fresh setup must allow a service that does not exist yet' }
$global:record.Add('framework')
if ($global:failFramework) { throw 'Fixture framework download failed' }
$prepared = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
$prepared.invoke_module_path = Join-Path $InstallRoot 'Invoke-AtomicRedTeam/Invoke-AtomicRedTeam.psd1'
$prepared.invoke_module_sha256 = 'a' * 64
[IO.File]::WriteAllText($ConfigFile, ($prepared | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
'@ | Set-Content -LiteralPath (Join-Path $scripts 'install-windows-execution-prerequisites.ps1')
    function Test-AgentPython {
        if ($args -contains 'apps.agent.bootstrap') {
            $global:record.Add('enroll')
            $position = [Array]::IndexOf($args, '--config')
            $global:enrolled = Get-Content -LiteralPath $args[$position + 1] -Raw | ConvertFrom-Json
        } elseif ($args -contains 'apps.agent.windows_catalog') {
            $global:record.Add('catalog')
            $position = [Array]::IndexOf($args, '--config')
            $prepared = Get-Content -LiteralPath $args[$position + 1] -Raw | ConvertFrom-Json
            $prepared | Add-Member -NotePropertyName catalog_verification_enabled -NotePropertyValue $true -Force
            [IO.File]::WriteAllText($args[$position + 1], ($prepared | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
        } elseif ($args -contains 'apps.agent.service') {
            $global:record.Add('register-service')
        } else { throw 'Unexpected Python invocation' }
        $global:LASTEXITCODE = 0
    }
    function Start-Service { param($Name, $ErrorAction) $global:record.Add('start-service') }
    $PythonPath = 'Test-AgentPython'
    $StartService = $true
    $service = $null
    if ($global:failFramework) {
        Must-Fail { & $phaseFile }
        Require (($global:record -join ',') -eq 'framework') 'A failed prerequisite setup enrolled or started the actor'
    } else {
        & $phaseFile
        $expected = if ($Case -eq 'installer-legacy') { 'framework,catalog,enroll,register-service,start-service' } else { 'framework,enroll,register-service,start-service' }
        Require (($global:record -join ',') -eq $expected) 'Prerequisites must succeed before enrollment and startup'
        Require ($global:enrolled.invoke_module_sha256 -eq ('a' * 64)) 'The verified module pin was not enrolled'
        Require ($global:enrolled.actor_id -eq 'test-actor') 'Actor binding changed'
        Require ($global:enrolled.profiles[0].id -eq 'test-profile') 'Profile binding changed'
        Require ($global:enrolled.python_path -eq 'Test-AgentPython') 'Actual interpreter was not prepared'
        if ($Case -eq 'installer-legacy') { Require $global:enrolled.catalog_verification_enabled 'Catalog preparation was lost before enrollment' }
    }
    Require ((Get-FileHash $original).Hash -eq $before) 'Downloaded package configuration was changed'
    Require (@(Get-ChildItem $InstallRoot -Filter '.enrollment-config-*').Count -eq 0) 'Temporary prepared configuration was not removed'
} else { throw 'Unknown test case' }
Write-Output "Passed $Case"
