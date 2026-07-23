@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem SQL Server forensic table collector for Windows Server 2016+.
rem This is a single-file BAT/PowerShell hybrid. It requires sqlcmd.exe and bcp.exe.
rem Authentication uses the Windows identity running this file; no password is stored.

if "%~1"=="" goto :USAGE
if /I "%~1"=="/?" goto :USAGE
if /I "%~1"=="-h" goto :USAGE
if /I "%~1"=="--help" goto :USAGE

set "DFIR_SQL_SERVER=%~1"
set "DFIR_SQL_OUTPUT=%~2"
set "DFIR_SQL_COLLECTOR=%~f0"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $text=[IO.File]::ReadAllText($env:DFIR_SQL_COLLECTOR); $marker=':__POWERSHELL_BELOW__'; $pos=$text.LastIndexOf($marker); if($pos -lt 0){throw 'Embedded PowerShell marker is missing.'}; $code=$text.Substring($pos+$marker.Length); & ([ScriptBlock]::Create($code)) -Server $env:DFIR_SQL_SERVER -OutputRoot $env:DFIR_SQL_OUTPUT"
set "DFIR_SQL_RC=%ERRORLEVEL%"

set "DFIR_SQL_SERVER="
set "DFIR_SQL_OUTPUT="
set "DFIR_SQL_COLLECTOR="
exit /b %DFIR_SQL_RC%

:USAGE
echo.
echo SQL Server forensic table collector
echo.
echo Usage:
echo   %~nx0 SERVER [OUTPUT_DIRECTORY]
echo.
echo Examples:
echo   %~nx0 SQL01
echo   %~nx0 "SQL01\INSTANCE" "D:\Evidence\SQL01"
echo   %~nx0 "tcp:10.10.10.20,1433" "\\EVIDENCE01\Case-001\SQL01"
echo.
echo Requirements:
echo   - Run under an authorized Windows account with CONNECT and SELECT access.
echo   - sqlcmd.exe and bcp.exe must be installed and available in PATH.
echo   - The output directory must be empty or not yet exist.
echo.
exit /b 64

:__POWERSHELL_BELOW__
param(
    [Parameter(Mandatory = $true)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$OutputRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:CollectionFailed = $false
$script:FailureRecords = New-Object 'System.Collections.Generic.List[string]'
$script:CollectorVersion = '1.0.0'
$script:RootPath = ''
$script:LogPath = ''
$script:SqlcmdPath = ''
$script:BcpPath = ''

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch {
    # Console encoding does not affect evidence files.
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [int]$MaximumLength = 80
    )

    $safe = [Regex]::Replace($Name, '[\x00-\x1f<>:"/\\|?*]', '_')
    $safe = $safe.Trim().TrimEnd('.', ' ')
    if ([String]::IsNullOrWhiteSpace($safe)) {
        $safe = '_unnamed'
    }

    $reserved = @(
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    )
    if ($reserved -contains $safe.ToUpperInvariant()) {
        $safe = '_' + $safe
    }

    if ($safe.Length -gt $MaximumLength) {
        $safe = $safe.Substring(0, $MaximumLength).TrimEnd('.', ' ')
    }
    return $safe
}

function Get-ShortHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash) -replace '-', '').Substring(0, 12).ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Quote-SqlIdentifier {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    return '[' + $Name.Replace(']', ']]') + ']'
}

function ConvertFrom-SqlUnicodeHex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hex
    )

    $value = $Hex.Trim()
    if ($value.StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
        $value = $value.Substring(2)
    }
    if (($value.Length % 2) -ne 0 -or $value -notmatch '\A[0-9a-fA-F]*\z') {
        throw ('Invalid SQL hexadecimal Unicode value: {0}' -f $Hex)
    }

    $bytes = New-Object byte[] ($value.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($value.Substring($index * 2, 2), 16)
    }
    return [Text.Encoding]::Unicode.GetString($bytes)
}

function Write-CollectionLog {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = '{0} [{1}] {2}' -f ([DateTimeOffset]::Now.ToString('yyyy-MM-ddTHH:mm:ss.fffzzz')), $Level, $Message
    Write-Host $line
    if ($script:LogPath) {
        [IO.File]::AppendAllText($script:LogPath, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    }
}

function Add-Failure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage,

        [Parameter(Mandatory = $false)]
        [string]$Database = '',

        [Parameter(Mandatory = $false)]
        [string]$Object = '',

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:CollectionFailed = $true
    $cleanMessage = ($Message -replace '[\r\n\t]+', ' ').Trim()
    $record = "{0}`t{1}`t{2}`t{3}" -f $Stage, $Database, $Object, $cleanMessage
    $script:FailureRecords.Add($record)
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $false)]
        [string]$CommandLogPath = ''
    )

    $output = @(& $FilePath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE

    if ($CommandLogPath) {
        $outputText = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        [IO.File]::WriteAllText(
            $CommandLogPath,
            $outputText + [Environment]::NewLine,
            (New-Object Text.UTF8Encoding($false))
        )
    }

    if ($exitCode -ne 0) {
        $message = ($output | ForEach-Object { $_.ToString() }) -join ' | '
        throw ('Command failed with exit code {0}: {1}' -f $exitCode, $message)
    }
    return $output
}

function Invoke-SqlcmdToFile {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Database = '',

        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$NoTrim
    )

    $arguments = @('-S', $Server, '-E', '-l', '30', '-b', '-r', '1', '-h', '-1', '-s', "`t", '-u')
    if (-not $NoTrim) {
        $arguments += '-W'
    }
    if ($Database) {
        $arguments += @('-d', $Database)
    }
    $arguments += @('-Q', $Query, '-o', $Path)
    [void](Invoke-External -FilePath $script:SqlcmdPath -Arguments $arguments)
}

function Read-UnicodeLines {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return @(Get-Content -LiteralPath $Path -Encoding Unicode | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })
}

function Write-FailureFile {
    if (-not $script:RootPath) {
        return
    }

    $failurePath = Join-Path $script:RootPath 'failures.tsv'
    $header = "stage`tdatabase`tobject`tmessage"
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add($header)
    foreach ($record in $script:FailureRecords) {
        $lines.Add($record)
    }
    [IO.File]::WriteAllLines($failurePath, $lines, (New-Object Text.UTF8Encoding($true)))
}

function Write-HashManifest {
    if (-not $script:RootPath -or -not (Test-Path -LiteralPath $script:RootPath -PathType Container)) {
        return
    }

    $manifestPath = Join-Path $script:RootPath 'hashes.tsv'
    $manifestHashPath = Join-Path $script:RootPath 'hashes.tsv.sha256'
    $rootWithSlash = $script:RootPath.TrimEnd('\') + '\'

    $files = @(Get-ChildItem -LiteralPath $script:RootPath -File -Recurse |
        Where-Object { $_.FullName -ne $manifestPath -and $_.FullName -ne $manifestHashPath } |
        Sort-Object FullName)

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add("sha256`tbytes`trelative_path")
    foreach ($file in $files) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $relative = $file.FullName.Substring($rootWithSlash.Length)
        $lines.Add(("{0}`t{1}`t{2}" -f $hash, $file.Length, $relative))
    }
    [IO.File]::WriteAllLines($manifestPath, $lines, (New-Object Text.UTF8Encoding($true)))

    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        $manifestHashPath,
        ('{0} *hashes.tsv{1}' -f $manifestHash, [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
}

function Export-Table {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Database,

        [Parameter(Mandatory = $true)]
        [string]$Schema,

        [Parameter(Mandatory = $true)]
        [string]$Table,

        [Parameter(Mandatory = $true)]
        [string]$DataDirectory,

        [Parameter(Mandatory = $true)]
        [string]$LogDirectory
    )

    $objectName = $Schema + '.' + $Table
    $objectHash = Get-ShortHash ($Database + [char]0 + $Schema + [char]0 + $Table)
    $baseName = '{0}__{1}__{2}' -f (ConvertTo-SafeFileName $Schema 45), (ConvertTo-SafeFileName $Table 70), $objectHash
    $finalPath = Join-Path $DataDirectory ($baseName + '.bcp')
    $partialPath = $finalPath + '.partial'
    $commandLogPath = Join-Path $LogDirectory ($baseName + '.log')
    $quotedObject = (Quote-SqlIdentifier $Schema) + '.' + (Quote-SqlIdentifier $Table)
    $query = 'SELECT * FROM ' + $quotedObject

    Write-CollectionLog -Level INFO -Message ('Exporting {0} / {1}' -f $Database, $objectName)
    $arguments = @(
        $query,
        'queryout',
        $partialPath,
        '-S', $Server,
        '-T',
        '-d', $Database,
        '-n',
        '-a', '65535',
        '-l', '30',
        '-q'
    )

    try {
        [void](Invoke-External -FilePath $script:BcpPath -Arguments $arguments -CommandLogPath $commandLogPath)
        Move-Item -LiteralPath $partialPath -Destination $finalPath
        $length = (Get-Item -LiteralPath $finalPath).Length
        Write-CollectionLog -Level INFO -Message ('Completed {0} / {1} ({2} bytes)' -f $Database, $objectName, $length)
    } catch {
        $message = $_.Exception.Message
        Add-Failure -Stage 'table_export' -Database $Database -Object $objectName -Message $message
        Write-CollectionLog -Level ERROR -Message ('Failed {0} / {1}: {2}' -f $Database, $objectName, $message)
    }
}

try {
    $script:SqlcmdPath = (Get-Command sqlcmd.exe -ErrorAction Stop).Source
    $script:BcpPath = (Get-Command bcp.exe -ErrorAction Stop).Source

    if ([String]::IsNullOrWhiteSpace($OutputRoot)) {
        $collectorDirectory = Split-Path -Parent $env:DFIR_SQL_COLLECTOR
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $OutputRoot = Join-Path $collectorDirectory ('SQL_Collection_{0}_{1}' -f $env:COMPUTERNAME, $timestamp)
    } else {
        $OutputRoot = [Environment]::ExpandEnvironmentVariables($OutputRoot)
        if (-not [IO.Path]::IsPathRooted($OutputRoot)) {
            $OutputRoot = Join-Path (Get-Location).Path $OutputRoot
        }
    }

    $fullOutputPath = [IO.Path]::GetFullPath($OutputRoot)
    $outputPathRoot = [IO.Path]::GetPathRoot($fullOutputPath)
    if ($fullOutputPath.TrimEnd('\') -eq $outputPathRoot.TrimEnd('\')) {
        throw ('A drive or share root cannot be used as the output directory: {0}' -f $fullOutputPath)
    }
    $script:RootPath = $fullOutputPath.TrimEnd('\')
    if (Test-Path -LiteralPath $script:RootPath) {
        $existingItems = @(Get-ChildItem -LiteralPath $script:RootPath -Force)
        if ($existingItems.Count -gt 0) {
            throw ('Output directory is not empty: {0}' -f $script:RootPath)
        }
    } else {
        [void](New-Item -ItemType Directory -Path $script:RootPath)
    }

    $script:LogPath = Join-Path $script:RootPath 'collection.log'
    [IO.File]::WriteAllText($script:LogPath, '', (New-Object Text.UTF8Encoding($false)))

    Write-CollectionLog -Level INFO -Message ('Collector version: {0}' -f $script:CollectorVersion)
    Write-CollectionLog -Level INFO -Message ('Collector host: {0}' -f $env:COMPUTERNAME)
    Write-CollectionLog -Level INFO -Message ('Collector identity: {0}' -f [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Write-CollectionLog -Level INFO -Message ('Target SQL Server: {0}' -f $Server)
    Write-CollectionLog -Level INFO -Message ('Output directory: {0}' -f $script:RootPath)
    Write-CollectionLog -Level INFO -Message ('sqlcmd: {0}' -f $script:SqlcmdPath)
    Write-CollectionLog -Level INFO -Message ('bcp: {0}' -f $script:BcpPath)

    $hostMetadataPath = Join-Path $script:RootPath 'collector_host.tsv'
    $hostMetadata = @(
        "field`tvalue",
        ("collector_version`t{0}" -f $script:CollectorVersion),
        ("collector_host`t{0}" -f $env:COMPUTERNAME),
        ("collector_identity`t{0}" -f [Security.Principal.WindowsIdentity]::GetCurrent().Name),
        ("collector_os`t{0}" -f [Environment]::OSVersion.VersionString),
        ("powershell_version`t{0}" -f $PSVersionTable.PSVersion.ToString()),
        ("target_server`t{0}" -f $Server),
        ("collection_started`t{0}" -f [DateTimeOffset]::Now.ToString('o')),
        ("sqlcmd_path`t{0}" -f $script:SqlcmdPath),
        ("bcp_path`t{0}" -f $script:BcpPath)
    )
    [IO.File]::WriteAllLines($hostMetadataPath, $hostMetadata, (New-Object Text.UTF8Encoding($true)))

    $serverMetadataPath = Join-Path $script:RootPath 'server_metadata.tsv'
    $serverQuery = @"
SET NOCOUNT ON;
SELECT
    CONVERT(nvarchar(128), SERVERPROPERTY('ServerName')),
    CONVERT(nvarchar(128), SERVERPROPERTY('MachineName')),
    CONVERT(nvarchar(128), SERVERPROPERTY('InstanceName')),
    CONVERT(nvarchar(128), SERVERPROPERTY('Edition')),
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')),
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductLevel')),
    CONVERT(nvarchar(128), SERVERPROPERTY('Collation')),
    CONVERT(nvarchar(128), ORIGINAL_LOGIN()),
    CONVERT(nvarchar(33), SYSDATETIMEOFFSET(), 127);
"@
    Invoke-SqlcmdToFile -Database 'master' -Query $serverQuery -Path $serverMetadataPath
    Write-CollectionLog -Level INFO -Message 'Connection test succeeded.'

    $databaseMetadataPath = Join-Path $script:RootPath 'databases.tsv'
    $databaseMetadataQuery = @"
SET NOCOUNT ON;
SELECT
    name,
    state_desc,
    recovery_model_desc,
    CONVERT(varchar(10), compatibility_level),
    ISNULL(collation_name, ''),
    ISNULL(SUSER_SNAME(owner_sid), ''),
    CONVERT(nvarchar(33), create_date, 126),
    CONVERT(varchar(20), ISNULL((SELECT SUM(CONVERT(bigint, size)) * 8192 FROM sys.master_files mf WHERE mf.database_id = d.database_id), 0))
FROM sys.databases d
WHERE database_id > 4
  AND source_database_id IS NULL
ORDER BY name;
"@
    Invoke-SqlcmdToFile -Database 'master' -Query $databaseMetadataQuery -Path $databaseMetadataPath

    $uncollectedDatabasePath = Join-Path $script:RootPath 'uncollected_databases.tsv'
    $uncollectedDatabaseQuery = @"
SET NOCOUNT ON;
SELECT
    name,
    state_desc,
    CONVERT(varchar(1), ISNULL(HAS_DBACCESS(name), 0)),
    CASE
        WHEN state_desc <> 'ONLINE' THEN 'database_not_online'
        WHEN ISNULL(HAS_DBACCESS(name), 0) <> 1 THEN 'no_database_access'
        ELSE 'unknown'
    END
FROM sys.databases
WHERE database_id > 4
  AND source_database_id IS NULL
  AND (state_desc <> 'ONLINE' OR ISNULL(HAS_DBACCESS(name), 0) <> 1)
ORDER BY name;
"@
    Invoke-SqlcmdToFile -Database 'master' -Query $uncollectedDatabaseQuery -Path $uncollectedDatabasePath
    $uncollectedDatabases = @(Read-UnicodeLines -Path $uncollectedDatabasePath)
    if ($uncollectedDatabases.Count -gt 0) {
        foreach ($uncollectedDatabase in $uncollectedDatabases) {
            Add-Failure -Stage 'database_skipped' -Message $uncollectedDatabase
        }
        Write-CollectionLog -Level WARN -Message ('User databases that cannot be collected: {0}. Review uncollected_databases.tsv.' -f $uncollectedDatabases.Count)
    }

    $databaseListPath = Join-Path $script:RootPath 'database_export_list.hex.txt'
    $databaseListQuery = @"
SET NOCOUNT ON;
SELECT sys.fn_varbintohexstr(CONVERT(varbinary(256), name))
FROM sys.databases
WHERE database_id > 4
  AND state_desc = 'ONLINE'
  AND source_database_id IS NULL
  AND HAS_DBACCESS(name) = 1
ORDER BY name;
"@
    Invoke-SqlcmdToFile -Database 'master' -Query $databaseListQuery -Path $databaseListPath
    $databaseHexLines = @(Read-UnicodeLines -Path $databaseListPath)
    $databases = @($databaseHexLines | ForEach-Object { ConvertFrom-SqlUnicodeHex $_ })

    if ($databases.Count -eq 0) {
        throw 'No accessible online user databases were found.'
    }
    Write-CollectionLog -Level INFO -Message ('Accessible online user databases: {0}' -f $databases.Count)

    foreach ($database in $databases) {
        if ([String]::IsNullOrWhiteSpace($database)) {
            continue
        }

        $databaseHash = Get-ShortHash $database
        $databaseDirectoryName = '{0}__{1}' -f (ConvertTo-SafeFileName $database 80), $databaseHash
        $databaseDirectory = Join-Path $script:RootPath $databaseDirectoryName
        $dataDirectory = Join-Path $databaseDirectory 'tables'
        $bcpLogDirectory = Join-Path $databaseDirectory 'bcp_logs'
        [void](New-Item -ItemType Directory -Path $dataDirectory -Force)
        [void](New-Item -ItemType Directory -Path $bcpLogDirectory -Force)

        Write-CollectionLog -Level INFO -Message ('Enumerating database: {0}' -f $database)

        try {
            $databaseInfoPath = Join-Path $databaseDirectory 'database.tsv'
            $databaseInfoQuery = @"
SET NOCOUNT ON;
SELECT
    DB_NAME(),
    state_desc,
    recovery_model_desc,
    user_access_desc,
    CONVERT(varchar(10), compatibility_level),
    ISNULL(collation_name, ''),
    CONVERT(nvarchar(33), create_date, 126),
    CONVERT(varchar(20), ISNULL(DATABASEPROPERTYEX(DB_NAME(), 'Updateability'), ''))
FROM sys.databases
WHERE name = DB_NAME();
"@
            Invoke-SqlcmdToFile -Database $database -Query $databaseInfoQuery -Path $databaseInfoPath

            $tableListPath = Join-Path $databaseDirectory 'tables.tsv'
            $tableListQuery = @"
SET NOCOUNT ON;
SELECT
    SCHEMA_NAME(t.schema_id),
    t.name,
    CONVERT(varchar(20), ISNULL(SUM(CASE WHEN p.index_id IN (0, 1) THEN p.rows ELSE 0 END), 0)),
    CONVERT(nvarchar(33), t.create_date, 126),
    CONVERT(nvarchar(33), t.modify_date, 126),
    CONVERT(varchar(1), t.is_memory_optimized),
    CONVERT(varchar(1), t.temporal_type)
FROM sys.tables t
LEFT JOIN sys.partitions p ON p.object_id = t.object_id
WHERE t.is_ms_shipped = 0
GROUP BY t.schema_id, t.name, t.create_date, t.modify_date, t.is_memory_optimized, t.temporal_type
ORDER BY SCHEMA_NAME(t.schema_id), t.name;
"@
            Invoke-SqlcmdToFile -Database $database -Query $tableListQuery -Path $tableListPath

            $columnMetadataPath = Join-Path $databaseDirectory 'columns.tsv'
            $columnMetadataQuery = @"
SET NOCOUNT ON;
SELECT
    SCHEMA_NAME(t.schema_id),
    t.name,
    CONVERT(varchar(10), c.column_id),
    c.name,
    TYPE_NAME(c.user_type_id),
    CONVERT(varchar(10), c.max_length),
    CONVERT(varchar(10), c.precision),
    CONVERT(varchar(10), c.scale),
    CONVERT(varchar(1), c.is_nullable),
    CONVERT(varchar(1), c.is_identity),
    CONVERT(varchar(1), c.is_computed),
    ISNULL(cc.definition, ''),
    ISNULL(dc.definition, ''),
    ISNULL(c.collation_name, '')
FROM sys.tables t
JOIN sys.columns c ON c.object_id = t.object_id
LEFT JOIN sys.computed_columns cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id
LEFT JOIN sys.default_constraints dc ON dc.object_id = c.default_object_id
WHERE t.is_ms_shipped = 0
ORDER BY SCHEMA_NAME(t.schema_id), t.name, c.column_id;
"@
            Invoke-SqlcmdToFile -Database $database -Query $columnMetadataQuery -Path $columnMetadataPath

            $indexMetadataPath = Join-Path $databaseDirectory 'indexes.tsv'
            $indexMetadataQuery = @"
SET NOCOUNT ON;
SELECT
    SCHEMA_NAME(t.schema_id),
    t.name,
    i.name,
    i.type_desc,
    CONVERT(varchar(1), i.is_unique),
    CONVERT(varchar(1), i.is_primary_key),
    CONVERT(varchar(1), i.is_unique_constraint),
    CONVERT(varchar(1), i.is_disabled),
    ISNULL(i.filter_definition, '')
FROM sys.tables t
JOIN sys.indexes i ON i.object_id = t.object_id
WHERE t.is_ms_shipped = 0
  AND i.index_id > 0
ORDER BY SCHEMA_NAME(t.schema_id), t.name, i.index_id;
"@
            Invoke-SqlcmdToFile -Database $database -Query $indexMetadataQuery -Path $indexMetadataPath

            $tableRows = @(Read-UnicodeLines -Path $tableListPath)
            Write-CollectionLog -Level INFO -Message ('User tables in {0}: {1}' -f $database, $tableRows.Count)

            $tableExportListPath = Join-Path $databaseDirectory 'table_export_list.hex.tsv'
            $tableExportListQuery = @"
SET NOCOUNT ON;
SELECT
    sys.fn_varbintohexstr(CONVERT(varbinary(256), SCHEMA_NAME(t.schema_id))),
    sys.fn_varbintohexstr(CONVERT(varbinary(256), t.name))
FROM sys.tables t
WHERE t.is_ms_shipped = 0
ORDER BY SCHEMA_NAME(t.schema_id), t.name;
"@
            Invoke-SqlcmdToFile -Database $database -Query $tableExportListQuery -Path $tableExportListPath
            $tableExportRows = @(Read-UnicodeLines -Path $tableExportListPath)

            foreach ($tableRow in $tableExportRows) {
                $parts = $tableRow -split "`t", 2
                if ($parts.Count -lt 2) {
                    $message = 'Could not parse table metadata line: ' + $tableRow
                    Add-Failure -Stage 'table_enumeration' -Database $database -Message $message
                    Write-CollectionLog -Level ERROR -Message $message
                    continue
                }
                $schema = ConvertFrom-SqlUnicodeHex $parts[0]
                $table = ConvertFrom-SqlUnicodeHex $parts[1]
                Export-Table -Database $database -Schema $schema -Table $table -DataDirectory $dataDirectory -LogDirectory $bcpLogDirectory
            }
        } catch {
            $message = $_.Exception.Message
            Add-Failure -Stage 'database_collection' -Database $database -Message $message
            Write-CollectionLog -Level ERROR -Message ('Database collection failed for {0}: {1}' -f $database, $message)
        }
    }

    Write-FailureFile
    if ($script:CollectionFailed) {
        Write-CollectionLog -Level WARN -Message ('Collection completed with {0} failure(s). Review failures.tsv.' -f $script:FailureRecords.Count)
    } else {
        Write-CollectionLog -Level INFO -Message 'Collection completed successfully.'
    }
} catch {
    $fatalMessage = $_.Exception.Message
    $script:CollectionFailed = $true
    if ($script:RootPath) {
        Add-Failure -Stage 'fatal' -Message $fatalMessage
        Write-CollectionLog -Level ERROR -Message ('Fatal error: {0}' -f $fatalMessage)
        Write-FailureFile
    } else {
        Write-Host ('Fatal error: {0}' -f $fatalMessage) -ForegroundColor Red
    }
} finally {
    if ($script:RootPath -and (Test-Path -LiteralPath $script:RootPath -PathType Container)) {
        try {
            Write-HashManifest
            Write-Host ('SHA-256 manifest written under: {0}' -f $script:RootPath)
        } catch {
            $script:CollectionFailed = $true
            Write-Host ('Could not write SHA-256 manifest: {0}' -f $_.Exception.Message) -ForegroundColor Red
        }
    }
}

if ($script:CollectionFailed) {
    exit 2
}
exit 0
