# 🛡️ WinUnlocker
> Windows Repair & Malware Removal Toolkit

![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)
![Language](https://img.shields.io/badge/language-C%2B%2B17-00599C?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--2.0-green?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0-orange?style=flat-square)

```
██╗    ██╗██╗███╗   ██╗██╗   ██╗███╗   ██╗██╗      ██████╗  ██████╗██╗  ██╗███████╗██████╗
██║    ██║██║████╗  ██║██║   ██║████╗  ██║██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║ █╗ ██║██║██╔██╗ ██║██║   ██║██╔██╗ ██║██║     ██║   ██║██║     █████╔╝ █████╗  ██████╔╝
██║███╗██║██║██║╚██╗██║██║   ██║██║╚██╗██║██║     ██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚███╔███╔╝██║██║ ╚████║╚██████╔╝██║ ╚████║███████╗╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

Консольный инструмент для восстановления Windows после заражения вирусами.  
Работает в **обычной Windows**, **WinRE** и **WinPE** — без графической оболочки.

---

## ✨ Возможности

| # | Модуль | Описание |
|---|--------|----------|
| 1 | 🔍 **Task Manager** | Просмотр всех процессов, завершение по PID или имени, выделение подозрительных |
| 2 | 🚀 **Autorun Manager** | Просмотр и удаление записей автозапуска из 8 ключей реестра |
| 3 | 🔓 **Restrictions Unlocker** | Снятие блокировок диспетчера задач, regedit, cmd, панели управления и др. |
| 4 | 🧹 **Registry Cleaner** | Поиск и удаление битых ссылок в реестре |
| 5 | ⚙️ **Services Manager** | Просмотр, запуск, остановка и отключение служб Windows |
| 6 | 📁 **File Manager** | Навигация по файловой системе, удаление вредоносных файлов, сканирование Temp/Startup |

---

## 🖥️ Скриншот

```
  System : Windows 6.2 Build 9200
  Host   : DESKTOP-XXXXX   User: user
  Rights : Administrator

  ┌─────────────────────────────────────────────┐
  │              MAIN MENU                      │
  ├─────────────────────────────────────────────┤
  │  1. Task Manager        (view / kill processes) │
  │  2. Autorun Manager     (startup entries)       │
  │  3. Restrictions        (unlock Task Mgr...)    │
  │  4. Registry Cleaner    (broken entries)        │
  │  5. Services Manager    (Windows services)      │
  │  6. File Manager        (browse / delete files) │
  │  0. Exit                                        │
  └─────────────────────────────────────────────┘

  > Choose option: _
```

---

## 🚀 Использование

### Обычный запуск
Правый клик на `WinUnlocker.exe` → **Запуск от имени администратора**

### Запуск из WinRE (Recovery Environment)
```
1. Загрузи Windows в режим восстановления
2. Troubleshoot → Advanced Options → Command Prompt
3. Перейди на диск с файлом и запусти:
   D:\WinUnlocker.exe
```

### Запуск с загрузочной флешки (WinPE)
```
E:\WinUnlocker.exe
```

---

## 🔨 Сборка из исходников

### Требования
- Windows 7 / 8 / 10 / 11 (x64)
- Visual Studio 2019 или 2022
- Workload: **Desktop development with C++**
- Стандарт: **C++17**

### Шаги
```
1. Клонируй репозиторий:
   git clone https://github.com/UltimateHatred/WinUnlocker.git

2. Открой Visual Studio → File → Open → Folder
   Выбери папку с проектом

3. Создай новый проект Console App (C++)
   и добавь все .h и .cpp файлы

4. Project → Properties:
   C/C++ → Language → C++17
   Linker → System → Console

5. Ctrl+Shift+B — сборка
```

---

## 📋 Структура проекта

```
WinUnlocker/
├── main.cpp          # Точка входа, главное меню, UAC
├── utils.h           # Утилиты: цвета консоли, реестр, хелперы
├── tasks.h           # Диспетчер задач
├── autorun.h         # Менеджер автозапуска
├── restrictions.h    # Разблокировка ограничений Windows
├── registry.h        # Чистка реестра
├── services.h        # Управление службами
└── filemanager.h     # Файловый менеджер
```

---

## ⚠️ Важно

- Для большинства функций требуются права **Администратора**
- Программа автоматически запрашивает UAC при запуске
- Антивирус может срабатывать на эвристику — это нормально для инструментов работающих с реестром и процессами
- Используй только на своих устройствах или с разрешения владельца

---

## 📜 Лицензия

Проект распространяется под лицензией [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt).

---

## 👤 Автор

UltimateHatred

Сделано с ❤️ и C++
