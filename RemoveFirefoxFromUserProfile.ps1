param(
    [Parameter(Mandatory=$false, HelpMessage="Путь к каталогу профилей пользователей")]
    [string]$ProfilesPath = "C:\Users",
    
    [Parameter(Mandatory=$false, HelpMessage="Выполнять очистку реестра")]
    [bool]$CleanRegistry = $true,
    
    [Parameter(Mandatory=$false, HelpMessage="Выводить подробные сообщения")]
    [bool]$VerboseOutput = $true,
    
    [Parameter(Mandatory=$false, HelpMessage="Удалять профили Firefox с диска")]
    [bool]$RemoveFirefoxProfiles = $false,
    
    [Parameter(Mandatory=$false, HelpMessage="Удалять кэш Firefox")]
    [bool]$RemoveCache = $true,
    
    [Parameter(Mandatory=$false, HelpMessage="Удалять ярлыки Firefox")]
    [bool]$RemoveShortcuts = $true,
    
    [Parameter(Mandatory=$false, HelpMessage="Обрабатывать всех пользователей или только текущего")]
    [ValidateSet("All", "Current")]
    [string]$UserScope = "Current"
)

function Remove-Firefox-For-User {
    param($UserProfile, $ProfilesRoot, $CleanReg, $Verbose, $RemoveProfiles, $RemoveCache, $RemoveShortcuts)
    
    $UserName = $UserProfile.LocalPath.Split('\')[-1]
    $UserPath = $UserProfile.LocalPath
    
    if ($Verbose) {
        Write-Output "=== Обработка пользователя: $UserName ==="
    }
    
    # Базовые пути для удаления (всегда выполняются)
    $TargetPaths = @()
    
    # Добавляем пути для профилей Firefox если включено
    if ($RemoveProfiles) {
        $TargetPaths += @(
            @{Path = "$UserPath\AppData\Roaming\Mozilla"; Type = "Folder"},
            @{Path = "$UserPath\AppData\Local\Mozilla"; Type = "Folder"},
            @{Path = "$UserPath\AppData\LocalLow\Mozilla"; Type = "Folder"}
        )
    } else {
        # Если не удаляем профили, удаляем только конкретные папки Firefox
        $TargetPaths += @(
            @{Path = "$UserPath\AppData\Roaming\Mozilla\Firefox"; Type = "Folder"},
            @{Path = "$UserPath\AppData\Local\Mozilla\Firefox"; Type = "Folder"}
        )
    }
    
    # Добавляем кэш если включено
    if ($RemoveCache) {
        $TargetPaths += @(
            @{Path = "$UserPath\AppData\Local\Temp\Mozilla*"; Type = "Wildcard"},
            @{Path = "$UserPath\AppData\Local\Temp\*firefox*"; Type = "Wildcard"},
            @{Path = "$UserPath\AppData\Local\Mozilla\Firefox\Profiles\*\cache2"; Type = "Wildcard"}
        )
    }
    
    # Добавляем ярлыки если включено
    if ($RemoveShortcuts) {
        $TargetPaths += @(
            @{Path = "$UserPath\Desktop\*Firefox*"; Type = "Wildcard"},
            @{Path = "$UserPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*Firefox*"; Type = "Wildcard"},
            @{Path = "$UserPath\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\*Firefox*"; Type = "Wildcard"}
        )
    }
    
    # Удаление файлов и папок
    $removedCount = 0
    foreach ($Target in $TargetPaths) {
        try {
            switch ($Target.Type) {
                "Folder" {
                    if (Test-Path $Target.Path) {
                        Remove-Item $Target.Path -Recurse -Force -ErrorAction SilentlyContinue
                        $removedCount++
                        if ($Verbose) {
                            Write-Output "  ✓ Удалена папка: $($Target.Path)"
                        }
                    }
                }
                "Wildcard" {
                    $items = Get-ChildItem -Path (Split-Path $Target.Path) -Filter (Split-Path $Target.Path -Leaf) -ErrorAction SilentlyContinue
                    foreach ($item in $items) {
                        Remove-Item $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        $removedCount++
                        if ($Verbose) {
                            Write-Output "  ✓ Удален: $($item.FullName)"
                        }
                    }
                }
            }
        } catch {
            if ($Verbose) {
                Write-Warning "  ✗ Ошибка удаления: $($Target.Path) - $($_.Exception.Message)"
            }
        }
    }
    
    if ($Verbose -and $removedCount -eq 0) {
        Write-Output "  ℹ Не найдено данных Firefox для удаления"
    }
    
    # Очистка реестра
    if ($CleanReg -and $UserProfile.SID) {
        Clean-UserRegistry -UserSID $UserProfile.SID -UserName $UserName -Verbose $Verbose -RemoveProfiles $RemoveProfiles
    }
}

function Clean-UserRegistry {
    param($UserSID, $UserName, $Verbose, $RemoveProfiles)
    
    try {
        # Загружаем куст реестра если не загружен
        $HivePath = "HKU\$UserSID"
        $HiveFile = "$ProfilesPath\$UserName\NTUSER.DAT"
        
        if (-not (Test-Path "Registry::$HivePath")) {
            if (Test-Path $HiveFile) {
                reg load "HKU\$UserSID" $HiveFile 2>&1 | Out-Null
                if ($Verbose) {
                    Write-Output "  ✓ Загружен реестр пользователя"
                }
            } else {
                if ($Verbose) {
                    Write-Output "  ℹ Файл реестра не найден: $HiveFile"
                }
                return
            }
        }
        
        # Основные разделы для удаления (всегда)
        $RegPathsToRemove = @(
            "Software\Clients\StartMenuInternet\FIREFOX.EXE",
            "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox"
        )
        
        # Расширенные разделы если удаляем профили
        if ($RemoveProfiles) {
            $RegPathsToRemove += @(
                "Software\Mozilla",
                "Software\MozillaPlugins", 
                "Software\Classes\FirefoxHTML",
                "Software\Classes\FirefoxURL"
            )
        } else {
            # Если не удаляем профили, оставляем настройки Mozilla
            $RegPathsToRemove += @(
                "Software\Mozilla\Firefox"
            )
        }
        
        # Удаляем разделы реестра
        $regRemovedCount = 0
        foreach ($RegPath in $RegPathsToRemove) {
            $FullPath = "$HivePath\$RegPath"
            if (Test-Path "Registry::$FullPath") {
                Remove-Item "Registry::$FullPath" -Recurse -Force -ErrorAction SilentlyContinue
                $regRemovedCount++
                if ($Verbose) {
                    Write-Output "  ✓ Удален реестр: $RegPath"
                }
            }
        }
        
        if ($Verbose -and $regRemovedCount -eq 0) {
            Write-Output "  ℹ Не найдено записей реестра Firefox для удаления"
        }
        
        # Выгружаем куст реестра
        reg unload "HKU\$UserSID" 2>&1 | Out-Null
        if ($Verbose) {
            Write-Output "  ✓ Выгружен реестр пользователя"
        }
        
    } catch {
        if ($Verbose) {
            Write-Warning "  ✗ Ошибка работы с реестром: $($_.Exception.Message)"
        }
    }
}

function Get-CurrentUserProfile {
    # Получаем профиль текущего пользователя
    $CurrentUserName = $env:USERNAME
    $CurrentUserProfile = Get-WmiObject -Class Win32_UserProfile | Where-Object { 
        $_.LocalPath -eq "$ProfilesPath\$CurrentUserName" 
    }
    
    if (-not $CurrentUserProfile) {
        Write-Warning "Не удалось найти профиль текущего пользователя: $CurrentUserName"
        return $null
    }
    
    return $CurrentUserProfile
}

# Основной код
Write-Output "=== Очистка Firefox ==="
Write-Output "Режим обработки: $UserScope"
Write-Output "Каталог профилей: $ProfilesPath"
Write-Output "Очистка реестра: $CleanRegistry"
Write-Output "Удаление профилей Firefox: $RemoveFirefoxProfiles"
Write-Output "Удаление кэша: $RemoveCache"
Write-Output "Удаление ярлыков: $RemoveShortcuts"
Write-Output "Подробный вывод: $VerboseOutput"
Write-Output ""

# Проверяем существование пути
if (-not (Test-Path $ProfilesPath)) {
    Write-Error "ОШИБКА: Каталог профилей не существует: $ProfilesPath"
    exit 1
}

# Получаем список профилей для обработки
$ProfilesToProcess = @()

switch ($UserScope) {
    "Current" {
        Write-Output "Режим: Обработка только текущего пользователя"
        $CurrentProfile = Get-CurrentUserProfile
        if ($CurrentProfile) {
            $ProfilesToProcess = @($CurrentProfile)
            Write-Output "Текущий пользователь: $env:USERNAME"
        }
    }
    "All" {
        Write-Output "Режим: Обработка всех пользователей"
        # Получаем все профили пользователей (кроме системных)
        $AllProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { 
            $_.LocalPath -like "$ProfilesPath\*" -and 
            $_.LocalPath -notlike "*Default*" -and 
            $_.LocalPath -notlike "*Public*" -and
            $_.Special -eq $false
        }
        $ProfilesToProcess = $AllProfiles
    }
}

Write-Output "Найдено профилей для обработки: $($ProfilesToProcess.Count)"
Write-Output ""

if ($ProfilesToProcess.Count -eq 0) {
    Write-Warning "Не найдено профилей для обработки"
    exit 0
}

# Обрабатываем каждый профиль
$processedCount = 0
foreach ($Profile in $ProfilesToProcess) {
    Remove-Firefox-For-User -UserProfile $Profile -ProfilesRoot $ProfilesPath -CleanReg $CleanRegistry -Verbose $VerboseOutput -RemoveProfiles $RemoveFirefoxProfiles -RemoveCache $RemoveCache -RemoveShortcuts $RemoveShortcuts
    $processedCount++
}

Write-Output ""
Write-Output "=== Очистка завершена ==="
Write-Output "Обработано профилей: $processedCount"
Write-Output "Режим: $UserScope"
Write-Output "Каталог профилей: $ProfilesPath"
