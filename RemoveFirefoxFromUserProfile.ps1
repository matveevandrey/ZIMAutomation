<#
.SYNONOPSIS
    Скрипт для удаления Mozilla Firefox из профилей пользователей

.DESCRIPTION
    Этот скрипт удаляет данные Mozilla Firefox (файлы, папки, реестр, ярлыки) 
    для текущего или всех пользователей в системе. Поддерживает гибкую настройку 
    через параметры командной строки.

.PARAMETER CleanRegistry
    Выполнять очистку реестра (по умолчанию: $true)

.PARAMETER VerboseOutput
    Выводить подробные сообщения (по умолчанию: $true)

.PARAMETER RemoveFirefoxProfiles
    Удалять профили Firefox с диска (по умолчанию: $false)

.PARAMETER RemoveCache
    Удалять кэш Firefox (по умолчанию: $true)

.PARAMETER RemoveShortcuts
    Удалять ярлыки Firefox (по умолчанию: $true)

.PARAMETER UserScope
    Обрабатывать всех пользователей или только текущего (по умолчанию: Current)

.PARAMETER Help
    Показать справку по использованию скрипта

.EXAMPLE
    # Удалить Firefox только для текущего пользователя (безопасный режим)
    .\RemoveFirefoxFromUserProfile.ps1

.EXAMPLE
    # Удалить Firefox для всех пользователей
    .\RemoveFirefoxFromUserProfile.ps1 -UserScope "All"

.EXAMPLE
    # Полная очистка Firefox для всех пользователей
    .\RemoveFirefoxFromUserProfile.ps1 -UserScope "All" -RemoveFirefoxProfiles $true

.EXAMPLE
    # Удалить только кэш и ярлыки для текущего пользователя
    .\RemoveFirefoxFromUserProfile.ps1 -RemoveFirefoxProfiles $false -RemoveCache $true -RemoveShortcuts $true

.EXAMPLE
    # Тихий режим для всех пользователей
    .\RemoveFirefoxFromUserProfile.ps1 -UserScope "All" -VerboseOutput $false

.EXAMPLE
    # Показать справку
    .\RemoveFirefoxFromUserProfile.ps1 -Help

.NOTES
    Автор: AMV
    Требует: PowerShell 3.0+, права администратора для режима "All"
    Версия: 2.3
    Имя файла: RemoveFirefoxFromUserProfile.ps1
#>

param(
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
    [string]$UserScope = "Current",
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Функция для отображения справки
function Show-Usage {
    Write-Output ""
    Write-Output "=== RemoveFirefoxFromUserProfile.ps1 ==="
    Write-Output "Скрипт удаления Mozilla Firefox из профилей пользователей"
    Write-Output ""
    Write-Output "ОСНОВНЫЕ СЦЕНАРИИ ИСПОЛЬЗОВАНИЯ:"
    Write-Output ""
    Write-Output "1.  Базовое использование (текущий пользователь):"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1"
    Write-Output ""
    Write-Output "2.  Для всех пользователей (требует админ права):"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -UserScope All"
    Write-Output ""
    Write-Output "3.  Полное удаление Firefox для всех пользователей:"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -UserScope All -RemoveFirefoxProfiles `$true"
    Write-Output ""
    Write-Output "4.  Только кэш и ярлыки:"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -RemoveFirefoxProfiles `$false -RemoveCache `$true -RemoveShortcuts `$true"
    Write-Output ""
    Write-Output "5.  Тихий режим (без вывода):"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -UserScope All -VerboseOutput `$false"
    Write-Output ""
    Write-Output "6.  Показать справку:"
    Write-Output "    .\RemoveFirefoxFromUserProfile.ps1 -Help"
    Write-Output ""
    Write-Output "ПАРАМЕТРЫ:"
    Write-Output "  -UserScope: All | Current (кто обрабатывается)"
    Write-Output "  -RemoveFirefoxProfiles: `$true | `$false (удалять ли профили)"
    Write-Output "  -RemoveCache: `$true | `$false (удалять ли кэш)"
    Write-Output "  -RemoveShortcuts: `$true | `$false (удалять ли ярлыки)"
    Write-Output "  -CleanRegistry: `$true | `$false (чистить ли реестр)"
    Write-Output "  -Help : Показать эту справку"
    Write-Output ""
    Write-Output "ПРИМЕРЫ КОМАНД:"
    Write-Output "  .\RemoveFirefoxFromUserProfile.ps1 -UserScope All"
    Write-Output "  .\RemoveFirefoxFromUserProfile.ps1 -UserScope Current -RemoveFirefoxProfiles `$true"
    Write-Output "  .\RemoveFirefoxFromUserProfile.ps1 -Help"
    Write-Output ""
}

# Показываем справку если запрошена помощь
if ($Help -or $args -contains "-?" -or $args -contains "/?" -or $args -contains "--Help") {
    Show-Usage
    exit 0
}

function Get-AllUserProfiles {
    <#
    .SYNOPSIS
        Получает все пользовательские профили из реестра
    #>
    
    $profiles = @()
    
    try {
        # Способ 1: Через реестр (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList)
        $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        if (Test-Path $profileListPath) {
            $profileSIDs = Get-ChildItem $profileListPath | Where-Object { 
                $_.PSChildName -notlike "*_Classes" -and $_.PSChildName -match "^S-1-5-21-" 
            }
            
            foreach ($sid in $profileSIDs) {
                try {
                    $profilePath = $sid.GetValue("ProfileImagePath")
                    $sidValue = $sid.PSChildName
                    
                    if ($profilePath -and (Test-Path $profilePath)) {
                        $profiles += [PSCustomObject]@{
                            SID = $sidValue
                            Path = $profilePath
                            UserName = (Split-Path $profilePath -Leaf)
                        }
                    }
                } catch {
                    # Пропускаем проблемные профили
                    continue
                }
            }
        }
        
        # Способ 2: Через WMI (резервный способ)
        if ($profiles.Count -eq 0) {
            $wmiProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { 
                $_.Special -eq $false -and 
                $_.LocalPath -notlike "*Default*" -and 
                $_.LocalPath -notlike "*Public*" -and
                $_.LocalPath -like "*\Users\*"
            }
            
            foreach ($profile in $wmiProfiles) {
                $profiles += [PSCustomObject]@{
                    SID = $profile.SID
                    Path = $profile.LocalPath
                    UserName = (Split-Path $profile.LocalPath -Leaf)
                }
            }
        }
        
        return $profiles
    } catch {
        Write-Warning "Ошибка при получении списка профилей: $($_.Exception.Message)"
        return @()
    }
}

function Remove-Firefox-For-CurrentUser {
    param($CleanReg, $Verbose, $RemoveProfiles, $RemoveCache, $RemoveShortcuts)
    
    $UserName = $env:USERNAME
    $UserProfilePath = $env:USERPROFILE
    
    if ($Verbose) {
        Write-Output "=== Обработка текущего пользователя: $UserName ==="
        Write-Output "Путь к профилю: $UserProfilePath"
    }
    
    # Базовые пути для удаления на основе переменных окружения
    $TargetPaths = @()
    
    # Добавляем пути для профилей Firefox если включено
    if ($RemoveProfiles) {
        $TargetPaths += @(
            @{Path = "$env:APPDATA\Mozilla"; Type = "Folder"},
            @{Path = "$env:LOCALAPPDATA\Mozilla"; Type = "Folder"},
            @{Path = "$env:USERPROFILE\AppData\LocalLow\Mozilla"; Type = "Folder"}
        )
    } else {
        # Если не удаляем профили, удаляем только конкретные папки Firefox
        $TargetPaths += @(
            @{Path = "$env:APPDATA\Mozilla\Firefox"; Type = "Folder"},
            @{Path = "$env:LOCALAPPDATA\Mozilla\Firefox"; Type = "Folder"}
        )
    }
    
    # Добавляем кэш если включено
    if ($RemoveCache) {
        $TargetPaths += @(
            @{Path = "$env:LOCALAPPDATA\Temp\Mozilla*"; Type = "Wildcard"},
            @{Path = "$env:LOCALAPPDATA\Temp\*firefox*"; Type = "Wildcard"},
            @{Path = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\cache2"; Type = "Wildcard"}
        )
    }
    
    # Добавляем ярлыки если включено
    if ($RemoveShortcuts) {
        $TargetPaths += @(
            @{Path = "$env:USERPROFILE\Desktop\*Firefox*"; Type = "Wildcard"},
            @{Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\*Firefox*"; Type = "Wildcard"},
            @{Path = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\*Firefox*"; Type = "Wildcard"}
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
    
    # Очистка реестра для текущего пользователя
    if ($CleanReg) {
        Clean-CurrentUserRegistry -Verbose $Verbose -RemoveProfiles $RemoveProfiles
    }
}

function Remove-Firefox-For-AllUsers {
    param($CleanReg, $Verbose, $RemoveProfiles, $RemoveCache, $RemoveShortcuts)
    
    # Получаем все профили через реестр
    $allProfiles = Get-AllUserProfiles
    
    if ($Verbose) {
        Write-Output "Найдено пользовательских профилей: $($allProfiles.Count)"
        Write-Output ""
    }
    
    foreach ($profile in $allProfiles) {
        $userName = $profile.UserName
        $userPath = $profile.Path
        $userSID = $profile.SID
        
        if ($Verbose) {
            Write-Output "=== Обработка пользователя: $userName ==="
            Write-Output "Путь к профилю: $userPath"
            Write-Output "SID: $userSID"
        }
        
        # Базовые пути для удаления
        $TargetPaths = @()
        
        if ($RemoveProfiles) {
            $TargetPaths += @(
                @{Path = "$userPath\AppData\Roaming\Mozilla"; Type = "Folder"},
                @{Path = "$userPath\AppData\Local\Mozilla"; Type = "Folder"},
                @{Path = "$userPath\AppData\LocalLow\Mozilla"; Type = "Folder"}
            )
        } else {
            $TargetPaths += @(
                @{Path = "$userPath\AppData\Roaming\Mozilla\Firefox"; Type = "Folder"},
                @{Path = "$userPath\AppData\Local\Mozilla\Firefox"; Type = "Folder"}
            )
        }
        
        if ($RemoveCache) {
            $TargetPaths += @(
                @{Path = "$userPath\AppData\Local\Temp\Mozilla*"; Type = "Wildcard"},
                @{Path = "$userPath\AppData\Local\Temp\*firefox*"; Type = "Wildcard"}
            )
        }
        
        if ($RemoveShortcuts) {
            $TargetPaths += @(
                @{Path = "$userPath\Desktop\*Firefox*"; Type = "Wildcard"},
                @{Path = "$userPath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*Firefox*"; Type = "Wildcard"}
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
                    Write-Warning "  ✗ Ошибка удаления: $($Target.Path)"
                }
            }
        }
        
        # Очистка реестра
        if ($CleanReg -and $userSID) {
            Clean-UserRegistry -UserSID $userSID -UserName $userName -UserPath $userPath -Verbose $Verbose -RemoveProfiles $RemoveProfiles
        }
        
        if ($Verbose) {
            Write-Output ""
        }
    }
}

function Clean-CurrentUserRegistry {
    param($Verbose, $RemoveProfiles)
    
    try {
        if ($Verbose) {
            Write-Output "  Очистка реестра текущего пользователя..."
        }
        
        # Основные разделы для удаления (всегда)
        $RegPathsToRemove = @(
            "HKCU:\Software\Clients\StartMenuInternet\FIREFOX.EXE",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox"
        )
        
        # Расширенные разделы если удаляем профили
        if ($RemoveProfiles) {
            $RegPathsToRemove += @(
                "HKCU:\Software\Mozilla",
                "HKCU:\Software\MozillaPlugins", 
                "HKCU:\Software\Classes\FirefoxHTML",
                "HKCU:\Software\Classes\FirefoxURL"
            )
        } else {
            # Если не удаляем профили, оставляем настройки Mozilla
            $RegPathsToRemove += @(
                "HKCU:\Software\Mozilla\Firefox"
            )
        }
        
        # Удаляем разделы реестра
        $regRemovedCount = 0
        foreach ($RegPath in $RegPathsToRemove) {
            if (Test-Path $RegPath) {
                Remove-Item $RegPath -Recurse -Force -ErrorAction SilentlyContinue
                $regRemovedCount++
                if ($Verbose) {
                    Write-Output "  ✓ Удален реестр: $RegPath"
                }
            }
        }
        
        if ($Verbose -and $regRemovedCount -eq 0) {
            Write-Output "  ℹ Не найдено записей реестра Firefox для удаления"
        }
        
    } catch {
        if ($Verbose) {
            Write-Warning "  ✗ Ошибка работы с реестром: $($_.Exception.Message)"
        }
    }
}

function Clean-UserRegistry {
    param($UserSID, $UserName, $UserPath, $Verbose, $RemoveProfiles)
    
    try {
        # Загружаем куст реестра если не загружен
        $HivePath = "HKU\$UserSID"
        $HiveFile = "$UserPath\NTUSER.DAT"
        
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

# Основной код
Write-Output "=== RemoveFirefoxFromUserProfile.ps1 ==="
Write-Output "Скрипт удаления Mozilla Firefox из профилей пользователей"
Write-Output ""

# Показываем краткую справку при запуске
Write-Output "Используйте -Help для просмотра полной справки"
Write-Output ""

Write-Output "НАСТРОЙКИ:"
Write-Output "  Режим обработки: $UserScope"
Write-Output "  Очистка реестра: $CleanRegistry"
Write-Output "  Удаление профилей Firefox: $RemoveFirefoxProfiles"
Write-Output "  Удаление кэша: $RemoveCache"
Write-Output "  Удаление ярлыков: $RemoveShortcuts"
Write-Output "  Подробный вывод: $VerboseOutput"
Write-Output ""

# Обрабатываем в зависимости от выбранного режима
switch ($UserScope) {
    "Current" {
        Write-Output "РЕЖИМ: Обработка только текущего пользователя"
        Write-Output "Текущий пользователь: $env:USERNAME"
        Write-Output "Путь к профилю: $env:USERPROFILE"
        Write-Output ""
        
        Remove-Firefox-For-CurrentUser -CleanReg $CleanRegistry -Verbose $VerboseOutput -RemoveProfiles $RemoveFirefoxProfiles -RemoveCache $RemoveCache -RemoveShortcuts $RemoveShortcuts
        $processedCount = 1
    }
    "All" {
        Write-Output "РЕЖИМ: Обработка всех пользователей"
        
        # Проверяем права администратора для режима "All"
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-Warning "ВНИМАНИЕ: Для обработки всех пользователей требуются права администратора!"
            Write-Output "Запустите PowerShell от имени администратора или используйте -UserScope Current"
            exit 1
        }
        
        Write-Output ""
        
        # Запрос подтверждения для режима "All"
        if ($VerboseOutput) {
            $confirmation = Read-Host "Вы уверены, что хотите удалить Firefox для ВСЕХ пользователей? (y/N)"
            if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
                Write-Output "Операция отменена пользователем"
                exit 0
            }
        }
        
        Write-Output "Начинаем очистку для всех пользователей..."
        Write-Output "Определяем профили через реестр..."
        Write-Output ""
        
        Remove-Firefox-For-AllUsers -CleanReg $CleanRegistry -Verbose $VerboseOutput -RemoveProfiles $RemoveFirefoxProfiles -RemoveCache $RemoveCache -RemoveShortcuts $RemoveShortcuts
        $allProfiles = Get-AllUserProfiles
        $processedCount = $allProfiles.Count
    }
}

Write-Output ""
Write-Output "=== ОЧИСТКА ЗАВЕРШЕНА ==="
Write-Output "Обработано профилей: $processedCount"
Write-Output "Режим: $UserScope"

if ($UserScope -eq "Current") {
    Write-Output "Профиль: $env:USERPROFILE"
}

Write-Output ""

# Показываем итоговые рекомендации
if ($RemoveFirefoxProfiles) {
    Write-Output "РЕКОМЕНДАЦИИ:"
    Write-Output "  - Firefox полностью удален из профилей пользователей"
    Write-Output "  - Пользователям потребуется переустановить Firefox при необходимости"
} else {
    Write-Output "РЕКОМЕНДАЦИИ:"
    Write-Output "  - Сохранены настройки Mozilla, удалены только данные Firefox"
    Write-Output "  - При повторной установке Firefox настройки могут восстановиться"
}

Write-Output ""
Write-Output "Для просмотра справки выполните: .\RemoveFirefoxFromUserProfile.ps1 -Help"
