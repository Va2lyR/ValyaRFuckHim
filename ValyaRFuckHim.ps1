# Check for Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`""
    exit
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml
Add-Type -AssemblyName System.Windows.Forms

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$installDir = "$env:USERPROFILE\Downloads\ValyaRFuckHim"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { $installDir }
$logoPath = Join-Path $scriptDir "logo.jpg"


# TOOL DATA

$ToolData = @(
    @{ Name="Xkzutos Mod Analyzer";      Desc="Analyzes Minecraft mods using metadata and hashes";   Category="ModAnalyzer"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/xkzuto96/xkzutos-mod-analyzer/main/XkzutosModAnalyzer.ps1')" },
    @{ Name="Meow Mod Analyzer";         Desc="Analyzes Minecraft mods for suspicious indicators";  Category="ModAnalyzer"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/MeowTonynoh/MeowModAnalyzer/main/MeowModAnalyzer.ps1')" },
    @{ Name="P1aegg Mod Analyzer";       Desc="Analyzes Minecraft mods and files";                  Category="ModAnalyzer"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/p1aegg/powershell/refs/heads/main/modanalyzer.ps1)" },
    @{ Name="Yarp Mod Analyzer";         Desc="Analyzes Minecraft mods for cheat indicators";      Category="ModAnalyzer"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/YarpLetapStan/PowershellScripts/refs/heads/main/YarpsModAnalyzer6.0.ps1)" },
    @{ Name="Yumiko Mod Analyzer";       Desc="Analyzes Minecraft mods for suspicious content";    Category="ModAnalyzer"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/veridondevvv/YumikoModAnalyzer/refs/heads/main/YumikoModAnalyzer.ps1')" },
    @{ Name="Habibi Mod Analyzer";       Desc="Analyzes Minecraft mods for suspicious content";    Category="ModAnalyzer"; Type="Cmd"; Command="Set-ExecutionPolicy Bypass -Scope Process; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/HadronCollision/PowershellScripts/refs/heads/main/HabibiModAnalyzer.ps1')" },

    @{ Name="TeslaPro Doomsday Detector"; Desc="Launches the Doomsday client detection workflow";   Category="ClientsDetector"; Type="Cmd"; Command="iex (irm 'https://raw.githubusercontent.com/TeslaPros/DoomsdayDetector/main/DoomsdayClientDetectorV3.ps1')" },
    @{ Name="TeslaPro GhostClientFinder"; Desc="Detects Ghost Client traces and modifications";     Category="ClientsDetector"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/TeslaPros/GhostClientFucker/refs/heads/main/GhostClientFucker.ps1')" },
    @{ Name="CheesyDqrkisFucker";        Desc="Searches for Dqrkis-related traces";                Category="ClientsDetector"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/cheesecatlol/DQRKIS-FUCKER/refs/heads/main/DqrkisFucker.ps1')" },
    @{ Name="Praiselily Doomsday Finder"; Desc="Finds Doomsday client artefacts";                   Category="ClientsDetector"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/DoomsdayFinder.ps1)" },
    @{ Name="Zedoon DoomsDay Detector";   Desc="Detects Doomsday client traces";                    Category="ClientsDetector"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/zedoonvm1/powershell-scripts/refs/heads/main/DoomsDayDetector.ps1)" },
    @{ Name="MeowClientFucker";           Desc="Detects known cheat client artefacts";              Category="ClientsDetector"; Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowClientFucker/releases/latest" },
    @{ Name="MeowDoomsdayFucker";         Desc="Detects Doomsday cheat artefacts";                 Category="ClientsDetector"; Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowDoomsdayFucker/releases/latest" },

    @{ Name="PrefetchView";          Desc="Parses prefetch, extracts file info";          Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/PrefetchView/releases/latest" },
    @{ Name="BAMReveal";             Desc="Parses BAM forensic artefact";                 Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/BAMReveal/releases/latest" },
    @{ Name="StringsParser";         Desc="Strings + YARA + signatures scanner";          Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/StringsParser/releases/latest" },
    @{ Name="Fileless";              Desc="Detects fileless via eventlog + memdump";      Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/Fileless/releases/latest" },
    @{ Name="DPS-Analyzer";          Desc="Analyzes DPS memory";                          Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/DPS-Analyzer/releases/latest" },
    @{ Name="UserAssistView";        Desc="Parses UserAssist registry artifact";          Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/UserAssistView/releases/latest" },
    @{ Name="JournalParser";         Desc="Parses NTFS USNJournal entries";               Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/JournalParser/releases/latest" },
    @{ Name="InjGen";                Desc="Detects JNI/JVMTI memory injections";         Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/InjGen/releases/latest" },
    @{ Name="USBDetector";           Desc="Detects USB device history";                   Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/USBDetector/releases/latest" },
    @{ Name="PFTrace";               Desc="Rundll32/Regsvr32 prefetch analysis";          Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/PFTrace/releases/latest" },
    @{ Name="CheckDeletedUSN";       Desc="Compares USN timestamp vs boot time";          Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/CheckDeletedUSN/releases/latest" },
    @{ Name="JARParser";             Desc="Parses JAR prefetch, DcomLaunch strings";      Category="Orbdiff";    Type="GitHub"; URL="https://github.com/Orbdiff/JARParser/releases/latest" },
    @{ Name="BAM-parser";            Desc="Parses BAM entries for execution history";     Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/BAM-parser/releases/latest" },
    @{ Name="PathsParser";           Desc="Extracts and analyzes executable paths";       Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/PathsParser/releases/latest" },
    @{ Name="JournalTrace";          Desc="Traces file activity via USN journal";         Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/JournalTrace/releases/latest" },
    @{ Name="KernelLiveDumpTool";    Desc="Captures live kernel memory dump";             Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/KernelLiveDumpTool/releases/latest" },
    @{ Name="BamDeletedKeys";        Desc="Finds deleted BAM registry keys";              Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/BamDeletedKeys/releases/latest" },
    @{ Name="Espouken Tool";         Desc="All-in-one SS forensics toolkit";              Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/Tool/releases/latest" },
    @{ Name="pcasvc-executed";       Desc="Extracts PCA service execution records";       Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/pcasvc-executed/releases/latest" },
    @{ Name="process-parser";        Desc="Parses process execution artefacts";           Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/process-parser/releases/latest" },
    @{ Name="prefetch-parser";       Desc="Parses Windows prefetch files";                Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/prefetch-parser/releases/latest" },
    @{ Name="ActivitiesCache";       Desc="Parses ActivitiesCache execution history";     Category="Spokwn";     Type="GitHub"; URL="https://github.com/spokwn/ActivitiesCache-execution/releases/latest" },
    @{ Name="MeowResolver";          Desc="Resolves obfuscated strings in binaries";      Category="Tonynoh";    Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowResolver/releases/latest" },
    @{ Name="MeowNovowareFucker";    Desc="Detects Novoware cheat artefacts";             Category="Tonynoh";    Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowNovowareFucker/releases/latest" },
    @{ Name="MeowImportsChecker";    Desc="Checks PE imports for suspicious DLLs";        Category="Tonynoh";    Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowImportsChecker/releases/latest" },
    @{ Name="PSHunter";              Desc="Hunts suspicious PowerShell activity";         Category="Praiselily"; Type="GitHub"; URL="https://github.com/praiselily/PSHunter/releases/latest" },
    @{ Name="AltDetector";           Desc="Detects alternate account artefacts";          Category="Praiselily"; Type="GitHub"; URL="https://github.com/praiselily/AltDetector/releases/latest" },
    @{ Name="WeHateFakers";          Desc="Checks hotspot / tethering logs";              Category="Praiselily"; Type="Cmd";    Command="iwr https://raw.githubusercontent.com/praiselily/WeHateFakers/refs/heads/main/HotspotLogs.ps1 | iex" },
    @{ Name="CommonDirectories";     Desc="Lists files in common suspicious dirs";        Category="Praiselily"; Type="Cmd";    Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/CommonDirectories.ps1')" },
    @{ Name="HarddiskConverter";     Desc="Converts harddisk identifiers for review";     Category="Praiselily"; Type="Cmd";    Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/HarddiskConverter.ps1')" },
    @{ Name="Services";              Desc="Lists and analyzes running services";          Category="Praiselily"; Type="Cmd";    Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Services.ps1')" },
    @{ Name="SignedScheduledTasks";  Desc="Finds unsigned / suspicious scheduled tasks"; Category="Praiselily"; Type="Cmd";    Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Signed-Scheduled-Tasks.ps1')" },
    @{ Name="RL ModAnalyzer";        Desc="Analyzes mod files for cheat indicators";     Category="RedLotus";   Type="GitHub"; URL="https://github.com/ItzIceHere/RedLotus-Mod-Analyzer/releases/latest" },
    @{ Name="RL TaskSentinel";       Desc="Monitors scheduled tasks for anomalies";      Category="RedLotus";   Type="GitHub"; URL="https://github.com/ItzIceHere/RedLotus-Task-Sentinel/releases/latest" },
    @{ Name="RL AltChecker";         Desc="Checks for alternate account indicators";     Category="RedLotus";   Type="GitHub"; URL="https://github.com/ItzIceHere/RedLotusAltChecker/releases/latest" },
    @{ Name="ComputerActivityView";  Desc="Timeline of computer activity events";        Category="NirSoft";    Type="Web";    URL="https://www.nirsoft.net/utils/computer_activity_view.html" },
    @{ Name="AmcacheParser";         Desc="Parses AMCache with YARA + signatures";       Category="NirSoft";    Type="Web";    URL="https://download.ericzimmermanstools.com/net9/AmcacheParser.zip" },
    @{ Name="SystemInformer";        Desc="Advanced process and kernel inspector";        Category="NirSoft";    Type="Link";   URL="https://www.systeminformer.com/canary" },
    @{ Name="DIE-engine";            Desc="Detects file type, packer, compiler";         Category="NirSoft";    Type="Web";    URL="https://github.com/horsicq/DIE-engine/releases" },
    @{ Name="DQRKIS-FUCKER";         Desc="Detects DQRKIS cheat artefacts";              Category="NirSoft";    Type="Cmd";    Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/cheesecatlol/DQRKIS-FUCKER/refs/heads/main/DqrkisFucker.ps1')" },
    @{ Name="MacroDetector";         Desc="Detects macro / clicker software traces";     Category="NirSoft";    Type="Cmd";    Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/NiccBlahh/MacroDetector/refs/heads/main/MacroDetector.ps1')" },
    @{ Name="Jarabel";               Desc="Locates .jar files with detailed checks";     Category="NirSoft";    Type="GitHub"; URL="https://github.com/nay-cat/Jarabel/releases/latest" },
    @{ Name="Luyten";                Desc="Open source Java decompiler GUI (Procyon)";   Category="NirSoft";    Type="GitHub"; URL="https://github.com/deathmarine/Luyten/releases/latest" },
    @{ Name="VMAware";               Desc="Advanced VM detection library and tool";      Category="NirSoft";    Type="GitHub"; URL="https://github.com/kernelwernel/VMAware/releases/latest" },
    @{ Name="Velociraptor";          Desc="Endpoint DFIR and threat hunting agent";      Category="NirSoft";    Type="GitHub"; URL="https://github.com/Velocidex/velociraptor/releases/latest" },
    @{ Name="NTFS Parser";           Desc="NTFS forensics: MFT, Bitlocker, USN";        Category="NirSoft";    Type="GitHub"; URL="https://github.com/thewhiteninja/ntfstool/releases/latest" },
    @{ Name="Hayabusa";              Desc="Fast forensics timeline generator";           Category="NirSoft";    Type="GitHub"; URL="https://github.com/Yamato-Security/hayabusa/releases/latest" },
    @{ Name="Everything";            Desc="Instant filename search engine for Windows";  Category="NirSoft";    Type="Link";   URL="https://www.voidtools.com/downloads/" },
    @{ Name="HxD";                   Desc="Fast hex editor with disk and RAM editing";   Category="NirSoft";    Type="Link";   URL="https://mh-nexus.de/en/hxd/" },
    @{ Name="bstrings";              Desc="Searches strings with regex + YARA";          Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/bstrings.zip" },
    @{ Name="JLECmd";                Desc="Parses Jump List files (CLI)";                Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/JLECmd.zip" },
    @{ Name="JumpListExplorer";      Desc="GUI explorer for Jump List artefacts";        Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip" },
    @{ Name="MFTECmd";               Desc="Parses MFT, UsnJrnl, LogFile, Boot";         Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/MFTECmd.zip" },
    @{ Name="PECmd";                 Desc="Parses Windows prefetch files (CLI)";         Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/PECmd.zip" },
    @{ Name="RecentFileCacheParser"; Desc="Parses RecentFileCache.bcf artefact";         Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/RecentFileCacheParser.zip" },
    @{ Name="RegistryExplorer";      Desc="GUI explorer for registry hives";             Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip" },
    @{ Name="ShellBagsExplorer";     Desc="GUI explorer for ShellBags artefacts";        Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/ShellBagsExplorer.zip" },
    @{ Name="SrumECmd";              Desc="Parses SRUM database for usage data";         Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/SrumECmd.zip" },
    @{ Name="TimelineExplorer";      Desc="GUI viewer for CSV timeline output";          Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip" },
    @{ Name="FullEventLogView";      Desc="Views all Windows event log entries";         Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/fulleventlogview.zip" },
    @{ Name="NetworkUsageView";      Desc="Shows network usage per process";             Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/networkusageview.zip" },
    @{ Name="BrowserDownloadsView";  Desc="Lists all browser download history";          Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/browserdownloadsview.zip" },
    @{ Name="AlternateStreamView";   Desc="Reveals hidden NTFS alternate streams";       Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/alternatestreamview.zip" },
    @{ Name="USBDeview";             Desc="Lists all USB devices ever connected";        Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/usbdeview.zip" },
    @{ Name="OpenSaveFilesView";     Desc="Shows files opened/saved via dialogs";        Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/opensavefilesview.zip" },
    @{ Name="ExecutedProgramsList";  Desc="Lists programs run from various sources";     Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/executedprogramslist.zip" },
    @{ Name="TaskSchedulerView";     Desc="Views all scheduled tasks and history";       Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/taskschedulerview.zip" },
    @{ Name="JumpListsView";         Desc="Views Jump List recent/frequent files";       Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/jumplistsview.zip" },
    @{ Name="WinPrefetchView";       Desc="Views Windows prefetch file details";         Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/winprefetchview.zip" },
    @{ Name="RegScanner";            Desc="Scans registry for values / patterns";        Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/regscanner.zip" },
    @{ Name="ShellBagsView";         Desc="Views ShellBags folder access history";       Category="Zimmerman";  Type="Web";    URL="https://www.nirsoft.net/utils/shellbagsview.zip" },
    @{ Name="NET 9.0";               Desc="Microsoft .NET 9 SDK runtime";                Category="Dependencies"; Type="Web"; URL="https://download.visualstudio.microsoft.com/download/pr/92dba916-bc51-4e76-8b0e-d41d37ce5fa4/ab08f3e95bf7a3d3da336a7e8c8eca63/dotnet-sdk-9.0.203-win-x64.exe" },
    @{ Name="NET 10.0";              Desc="Microsoft .NET 10 runtime";                   Category="Dependencies"; Type="Web"; URL="https://download.visualstudio.microsoft.com/download/pr/b3f93f0e-9e5e-4b4c-a4c4-36db0c4b0e3e/dotnet-runtime-10.0.0-win-x64.exe" },
    @{ Name="VSRedist";              Desc="Visual C++ redistributable (x64)";            Category="Dependencies"; Type="Web"; URL="https://aka.ms/vs/17/release/vc_redist.x64.exe" },

    @{ Name="AmcacheParser++";       Desc="High-performance Amcache parser with YARA + VT";       Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="Autoruns++";            Desc="Autoruns alternative with USN monitoring";              Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="BamParser++";           Desc="BAM execution history with YARA engine";               Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="BrowserDownloadsView++"; Desc="Multi-browser download history with USN highlighting"; Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="BrowsingHistoryView++"; Desc="Multi-browser history with domain flagging + VT";      Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="CrashedFileViewer++";   Desc="Windows crash artifacts with USN highlighting";        Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="JournalTrace++";        Desc="USN Journal analysis with bypass detections";          Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="KernelLiveDump++";      Desc="Dumps Kernel/User-mode RAM with string results";      Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="MFTExplorer++";         Desc="$MFT view with suspicious ADS identification";        Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="PathsParser++";         Desc="Paths parser GUI with YARA + USN viewer";              Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="PowerShellParser++";    Desc="PowerShell history with bypass detection";             Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="SavedFilesViewer++";    Desc="Files saved to disk with cross-referenced timestamps"; Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="SRUMExplorer++";        Desc="Maps file paths from SRUM with YARA + USN";           Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="StringExplorer++";      Desc="String data, entropy, and VirusTotal integration";     Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="USBDeview++";           Desc="USB device logs cross-referenced against DeviceHunt";  Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },
    @{ Name="WinPrefetchView++";     Desc="WinPrefetchView with bypass detections + YARA";        Category="DetectAC"; Type="GitHub"; URL="https://github.com/detect-ac/Detect.ac-Free-Tools/releases/latest" },

    @{ Name="Services Checker";      Desc="Nicc service checker";                                Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/NiccBlahh/ServiceChecker/refs/heads/main/ServiceChecker.ps1')" },
    @{ Name="Zeezy Services";        Desc="Zeezyexe services checker";                           Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/zeezyexe/services-checker/refs/heads/main/zeezyservices.ps1')" },
    @{ Name="All In One";            Desc="Enr1c0o all-in-one screenshare script";               Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Enr1c0o/Powershell-Scripts/refs/heads/main/All-in-one.ps1')" },
    @{ Name="JAR Parser Script";     Desc="L4rpsucks JAR parser";                                Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/l4rpsucks/Scripts/refs/heads/main/JARParser.ps1')" },
    @{ Name="Fileless Bypass Detection"; Desc="Detects fileless bypass techniques";                Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/l4rpsucks/Scripts/refs/heads/main/FilelessBypassDetection.ps1')" },
    @{ Name="Zeezy Macro Scanner";   Desc="Zeezy macro scanner";                                 Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/zeezyexe/macro-scanner/refs/heads/main/catchmacro.ps1')" },
    @{ Name="ClassLoader Dump";      Desc="Dumps ClassLoader data";                               Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/p1aegg/powershell/refs/heads/main/ClassLoaderDump.ps1')" },
    @{ Name="Prefetch Integrity Analyzer"; Desc="RedLotus prefetch integrity analyzer";            Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusPrefetchIntegrityAnalyzer.ps1')" },
    @{ Name="Lily Services";         Desc="PraiseLily services checker";                         Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Lafferrr/SSTools/refs/heads/main/LilysServices.ps1')" },
    @{ Name="Lily Services Enabler"; Desc="Services enabler";                                    Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Lafferrr/SSTools/refs/heads/main/LilysServicesEnabler.ps1')" },

    @{ Name="P1AE Javaw";            Desc="Best Javaw scanner";                                  Category="Others"; Type="GitHub"; URL="https://github.com/p1aegg/javaw/releases/latest" },
    @{ Name="MacroScanner";          Desc="Lafferr Macro Scanner";                               Category="Others"; Type="GitHub"; URL="https://github.com/Lafferrr/MacroScanner/releases/latest" },
    @{ Name="StringChecker";         Desc="Lafferrs Strings Checker";                            Category="Others"; Type="GitHub"; URL="https://github.com/Lafferrr/SSTools/releases/latest" },
    @{ Name="Java Library Analyzer"; Desc="Lafferr Java Library Analyzer";                       Category="Others"; Type="GitHub"; URL="https://github.com/Lafferrr/SSTools/releases/latest" },
    @{ Name="PJ Cheat Scanner Lite"; Desc="String Checker by gorbgallin";                        Category="Others"; Type="GitHub"; URL="https://github.com/gorbgallin/Pj-sCheatScannerLite/releases/latest" },

    @{ Name="JarAnalyzer";           Desc="JAR file analyzer and decompiler";                     Category="Valyar"; Type="Web";    URL="https://github.com/Va2lyR/ValyaRFuckHim/releases/download/ss/JarAnalyzer.exe" },

    @{ Name="NET 8.0";               Desc="Microsoft .NET 8 SDK runtime";                        Category="Dependencies"; Type="Web"; URL="https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-8.0.423-windows-x64-installer" },

    @{ Name="Echo Journal";          Desc="Echo journal analysis tool";                           Category="Echo"; Type="GitHub"; URL="https://github.com/Echo-Anticheat/Echo-Journal/releases/latest" },
    @{ Name="Echo UserAssist";       Desc="Echo UserAssist registry viewer";                      Category="Echo"; Type="GitHub"; URL="https://github.com/Echo-Anticheat/Echo-Journal/releases/latest" },
    @{ Name="Echo UsbTool";          Desc="Echo USB record analysis";                             Category="Echo"; Type="GitHub"; URL="https://github.com/Echo-Anticheat/Echo-Journal/releases/latest" },

    @{ Name="PathDuzenleyicisiV2";   Desc="Path organizer v2";                                    Category="TRSSCommunity"; Type="GitHub"; URL="https://github.com/trSScommunity/PathDuzenleyiciV2/releases/latest" },
    @{ Name="MzHunter";              Desc="MZ header scanner";                                    Category="TRSSCommunity"; Type="GitHub"; URL="https://github.com/trSScommunity/MZHunter/releases/latest" },
    @{ Name="MandarinTool";          Desc="Multi SS tool / JAR decompiler";                       Category="TRSSCommunity"; Type="GitHub"; URL="https://github.com/Mehmetyll/Mandarin-Tool/releases/latest" },

    @{ Name="MagnetEncryptedDiskDetector"; Desc="Encrypted disk detector";                         Category="Magnet"; Type="Web"; URL="https://go.magnetforensics.com/e/52162/MagnetEncryptedDiskDetector/kpt9bg/1663239667/h/LtXFtTL-Soawv5C1oL3BIEghi7e1Lx93yesZLR--Ok0" },
    @{ Name="MRCv120";               Desc="RAM dump tool";                                        Category="Magnet"; Type="Web"; URL="https://go.magnetforensics.com/e/52162/mail-utm-campaign-UTMC-0000044/llr4bg/1663358653/h/4kZ9Y4i2yPRqBzuQMrywA_v5bfkpG3rG8gEiSWrYU70" },

    @{ Name="FTK Imager";            Desc="Disk imaging tool";                                    Category="Forensics"; Type="Web"; URL="https://archive.org/download/access-data-ftk-imager-4.7.1/AccessData_FTK_Imager_4.7.1.exe" },
    @{ Name="Hayabusa v3.6";         Desc="Windows event log analyzer";                           Category="Forensics"; Type="GitHub"; URL="https://github.com/Yamato-Security/hayabusa/releases/latest" },
    @{ Name="Velociraptor";          Desc="Digital forensics platform";                           Category="Forensics"; Type="GitHub"; URL="https://github.com/Velocidex/velociraptor/releases/latest" },

    @{ Name="SystemInformer";        Desc="Advanced system monitor";                              Category="SystemTools"; Type="GitHub"; URL="https://github.com/winsiderss/si-builds/releases/latest" },
    @{ Name="Everything";            Desc="Instant file search engine";                           Category="SystemTools"; Type="Web"; URL="https://www.voidtools.com/Everything-1.4.1.1032.x64-Setup.exe" },
    @{ Name="ProcessHacker";         Desc="Process hacker";                                       Category="SystemTools"; Type="Web"; URL="https://sourceforge.net/projects/processhacker/files/latest/download" },

    @{ Name="InjGen v2";             Desc="Injection detection tool";                             Category="Analysis"; Type="GitHub"; URL="https://github.com/NotRequiem/InjGen/releases/latest" },
    @{ Name="Luyten";                Desc="Java decompiler";                                      Category="Analysis"; Type="GitHub"; URL="https://github.com/deathmarine/Luyten/releases/latest" },
    @{ Name="DPS Analyzer (nay-cat)"; Desc="DPS analyzer";                                       Category="Analysis"; Type="GitHub"; URL="https://github.com/nay-cat/dpsanalyzer/releases/latest" },
    @{ Name="DIE Engine";            Desc="Detect-It-Easy PE analyzer";                           Category="Analysis"; Type="GitHub"; URL="https://github.com/horsicq/DIE-engine/releases/latest" },

    @{ Name="Jarabel Light";         Desc="JAR analysis tool";                                    Category="Misc"; Type="GitHub"; URL="https://github.com/nay-cat/Jarabel/releases/latest" },
    @{ Name="Unicode";               Desc="Unicode character analyzer";                           Category="Misc"; Type="GitHub"; URL="https://github.com/RRancio/Exec/releases/latest" },
    @{ Name="CachedProgramsList";    Desc="Cache program list";                                   Category="Misc"; Type="GitHub"; URL="https://github.com/ponei/CachedProgramsList/releases/latest" },
    @{ Name="TimeChangeDetect";      Desc="System time change detector";                          Category="Misc"; Type="GitHub"; URL="https://github.com/santiagolin/TimeChangeDetect/releases/latest" },
    @{ Name="HardlinkFinder";        Desc="Hardlink detection";                                   Category="Misc"; Type="GitHub"; URL="https://github.com/praiselily/HardlinkFinder/releases/latest" },

    @{ Name="LastActivityView";      Desc="List recent user activity";                            Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/lastactivityview.zip" },
    @{ Name="UsbDriveLog";           Desc="Show USB drive history";                               Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/usbdrivelog.zip" },
    @{ Name="WinDefLogView";         Desc="Windows Defender log viewer";                          Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/windeflogview.zip" },
    @{ Name="UninstallView";         Desc="List installed programs";                              Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/uninstallview-x64.zip" },
    @{ Name="LoadedDllsView";        Desc="Loaded DLL list";                                      Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/loadeddllsview-x64.zip" },
    @{ Name="Clipboardic";           Desc="Clipboard history viewer";                             Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/clipboardic.zip" },

    @{ Name="WxTCmd";                Desc="Windows Timeline database";                            Category="Zimmerman"; Type="Web"; URL="https://download.ericzimmermanstools.com/net6/WxTCmd.zip" },

    @{ Name="TeslaPro MacroFinder";  Desc="Macro finder tool";                                    Category="TeslaPro"; Type="GitHub"; URL="https://github.com/TeslaPros/TeslaProMacroFinder/releases/latest" },
    @{ Name="TeslaPro VPNFinder";    Desc="VPN finder";                                           Category="TeslaPro"; Type="GitHub"; URL="https://github.com/TeslaPros/VPNChecker/releases/latest" },
    @{ Name="TeslaPro GhostClientFucker"; Desc="Ghost client detector";                           Category="TeslaPro"; Type="GitHub"; URL="https://github.com/TeslaPros/GhostClientFucker/releases/latest" },

    @{ Name="JAR Scanner";           Desc="JAR scanner by Praiselily";                            Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/JARScanner/refs/heads/main/JARScanner.ps1')" },
    @{ Name="Service Enabler";       Desc="Service enabler by Praiselily";                        Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Service-Enabler.ps1')" },
    @{ Name="BAM Robado Checker";    Desc="Check stolen BAM records";                             Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/IlleUco/ScreenShare/main/BamRobadoIlleUco.ps1')" },
    @{ Name="Recycle Bin Checker";   Desc="Recycle bin analyzer";                                 Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/IlleUco/ScreenShare/main/RecycleBinChecker.ps1')" },
    @{ Name="PrismScreenShareAnalyze"; Desc="PrismSSAnalyzer";                                    Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/JustWolfeyy/PrismScreenShareAnalyzer/refs/heads/main/PrismSSAnalyzer.ps1')" },
    @{ Name="USB Events Viewer";     Desc="USB history viewer";                                   Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/IlleUco/ScreenShare/main/USBEvents.ps1')" },
    @{ Name="RedLotus BAM";          Desc="RedLotus BAM inspection";                              Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/PureIntent/ScreenShare/main/RedLotusBam.ps1')" },
    @{ Name="Javaw-Scanner";         Desc="Javaw scanner by DrakFlxme";                           Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/DrakFlxme/Javaw-Scanner.ps1/refs/heads/main/Javaw-Scanner.ps1')" },
    @{ Name="File-Scanner-Powershell"; Desc="RedLotus file scanner";                               Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/RedLotus-Development/File-Scanner-Powershell/refs/heads/Red-Lotus/REDLOTUS-AdminEXEs.ps1')" },
    @{ Name="RedLotus Collector";    Desc="RedLotus forensic collector";                          Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/RedLotusForensics/tool/main/Collector.ps1')" },
    @{ Name="TeslaPro Macro Finder Script"; Desc="TeslaPro macro finder";                          Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/TeslaPros/TeslaProMacroFinder/main/TeslaProMacroFinder_V3.ps1')" },
    @{ Name="TeslaPro VPN Finder Script"; Desc="TeslaPro VPN finder";                              Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/TeslaPros/VPNChecker/main/VPNFinder.ps1')" },
    @{ Name="TeslaPro Injector Detector"; Desc="Injector detector";                                Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Sellgui/Injectdetect/refs/heads/main/Injector%20Scanner.ps1')" },
    @{ Name="TeslaPro Prime Macro Detector"; Desc="Prime macro detector";                          Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Sellgui/Javamacrodetector/refs/heads/main/Macro%20Detector.ps1')" },
    @{ Name="TeslaPro Velaris Detector"; Desc="Velaris detector";                                  Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Va2lyR/-TeslaProSS-Toolv2/refs/heads/main/tools/Velaris-Detector.ps1')" },
    @{ Name="TeslaPro Prestige Finder"; Desc="Prestige finder";                                   Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Sellgui/Egitserpragger/refs/heads/main/EgitserpRaper.ps1')" },
    @{ Name="Macro Detector (Nickk)"; Desc="Detect macro software";                               Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Nickk196/MacroDetector/main/MacroDetector.ps1')" }
)


# DISCLAIMER DIALOG

[xml]$disclaimerXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="ValyaRFuckHim" Width="520" Height="480" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" FontFamily="Segoe UI">
    <Window.Resources>
        <Style x:Key="CancelBtnStyle" TargetType="Button">
            <Setter Property="Background" Value="#141414"/>
            <Setter Property="Foreground" Value="#888888"/>
            <Setter Property="BorderBrush" Value="#2A2A2A"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Height" Value="40"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="#141414" CornerRadius="8" BorderBrush="#2A2A2A" BorderThickness="1">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#1A1A1A"/>
                                <Setter Property="Foreground" Value="#AAAAAA"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="AcceptBtnStyle" TargetType="Button">
            <Setter Property="Background" Value="#E53935"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
            <Setter Property="BorderBrush" Value="#E53935"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Height" Value="40"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="#E53935" CornerRadius="8" BorderBrush="#E53935" BorderThickness="1">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#F44336"/>
                                <Setter TargetName="b" Property="BorderBrush" Value="#F44336"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Border Background="#0A0A0A" BorderBrush="#1E1E1E" BorderThickness="1" Padding="28" CornerRadius="8">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="*"/>
                <RowDefinition Height="56"/>
            </Grid.RowDefinitions>
            <StackPanel Grid.Row="0">
                <TextBlock Text="ValyaRFuckHim" FontSize="22" FontWeight="Bold" Foreground="#FFFFFF" Margin="0,0,0,4"/>
                <TextBlock Text="ALL u want here" FontSize="11" Foreground="#E53935" Margin="0,0,0,20"/>
                <Border Background="#1E1E1E" Height="1" Margin="0,0,0,20"/>
                <TextBlock TextWrapping="Wrap" Foreground="#AAAAAA" FontSize="12" Margin="0,0,0,14" Text="This toolkit was built and curated by ValyaR. Every tool included is open-source and fetched directly from its original GitHub repository. Your data is never collected, stored, or shared."/>
                <TextBlock TextWrapping="Wrap" Foreground="#AAAAAA" FontSize="12" Margin="0,0,0,14" Text="IMPORTANT: Before running any tool, take a moment to research what it does. GitHub repositories can be compromised at any time. ValyaR is not responsible for any damage caused by third-party tools. You are solely responsible for verifying and using them at your own risk."/>
                <TextBlock TextWrapping="Wrap" Foreground="#AAAAAA" FontSize="12" Margin="0,0,0,14" Text="By clicking Accept, you confirm that you understand these risks and agree to use this toolkit responsibly."/>
                <Border Background="#1E1E1E" Height="1" Margin="0,0,0,16"/>
                <TextBlock TextWrapping="Wrap" Foreground="#FFFFFF" FontSize="12" FontWeight="SemiBold" Text="You must agree to continue."/>
            </StackPanel>
            <Grid Grid.Row="1" VerticalAlignment="Bottom">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="12"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Button x:Name="CancelBtn" Grid.Column="0" Content="Cancel" Style="{StaticResource CancelBtnStyle}"/>
                <Button x:Name="AcceptBtn" Grid.Column="2" Content="Accept &amp; Continue" Style="{StaticResource AcceptBtnStyle}"/>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

$disclaimerReader = New-Object System.Xml.XmlNodeReader $disclaimerXaml
$disclaimerWindow = [Windows.Markup.XamlReader]::Load($disclaimerReader)
$disclaimerWindow.Add_MouseLeftButtonDown({ try { $disclaimerWindow.DragMove() } catch {} })
$CancelBtn = $disclaimerWindow.FindName("CancelBtn")
$AcceptBtn = $disclaimerWindow.FindName("AcceptBtn")
$script:disclaimerAccepted = $false
$AcceptBtn.Add_Click({ $script:disclaimerAccepted = $true; $disclaimerWindow.Close() })
$CancelBtn.Add_Click({ $script:disclaimerAccepted = $false; $disclaimerWindow.Close() })
$disclaimerWindow.ShowDialog() | Out-Null
if (-not $script:disclaimerAccepted) { exit }


# MAIN WINDOW XAML

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="ValyaRFuckHim" Width="1200" Height="750" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" FontFamily="Segoe UI">
    <Window.Resources>
        <SolidColorBrush x:Key="Bg" Color="#0A0A0A"/>
        <SolidColorBrush x:Key="Surface" Color="#0F0F0F"/>
        <SolidColorBrush x:Key="Surface2" Color="#141414"/>
        <SolidColorBrush x:Key="Border" Color="#181818"/>
        <SolidColorBrush x:Key="Accent" Color="#E53935"/>
        <SolidColorBrush x:Key="Text" Color="#F0F0F0"/>
        <SolidColorBrush x:Key="TextSec" Color="#888888"/>
        <SolidColorBrush x:Key="TextDim" Color="#444444"/>
        <Style x:Key="TitleBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#444444"/>
            <Setter Property="Width" Value="40"/>
            <Setter Property="Height" Value="32"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="Transparent" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#E53935"/>
                                <Setter Property="Foreground" Value="#FFFFFF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="SideBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#666666"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Height" Value="30"/>
            <Setter Property="Margin" Value="0,1"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="Transparent" CornerRadius="6" Padding="12,0">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#161616"/>
                                <Setter Property="Foreground" Value="#FFFFFF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="ScrollViewer">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ScrollViewer">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="0"/>
                            </Grid.ColumnDefinitions>
                            <Border Grid.Column="0" Background="Transparent">
                                <ScrollContentPresenter/>
                            </Border>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Border Background="{StaticResource Bg}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="10">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="40"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <Border Grid.Row="0" Background="#0C0C0C" BorderBrush="{StaticResource Border}" BorderThickness="0,0,0,1">
                <Grid Margin="16,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <Border Background="#E53935" Width="6" Height="6" CornerRadius="3" Margin="0,0,8,0" VerticalAlignment="Center"/>
                        <TextBlock Text="VALYAR" FontSize="12" FontWeight="Bold" Foreground="#FFFFFF" FontFamily="Consolas" VerticalAlignment="Center"/>
                        <Border Background="#1A1A1A" Width="1" Height="14" Margin="10,0" VerticalAlignment="Center"/>
                        <Border x:Name="StatusBadge" Background="#1A0000" Padding="8,2" VerticalAlignment="Center" CornerRadius="3">
                            <TextBlock x:Name="StatusBadgeText" Text="IDLE" FontSize="8" FontWeight="Bold" Foreground="#E53935" FontFamily="Consolas"/>
                        </Border>
                        <TextBlock x:Name="StatusTitle" Text="Ready" FontSize="10" Foreground="#777777" VerticalAlignment="Center" Margin="8,0,0,0"/>
                        <TextBlock x:Name="StatusSub" Text="Select a tool to begin." FontSize="9" Foreground="#333333" VerticalAlignment="Center" Margin="6,0,0,0"/>
                    </StackPanel>
                    <StackPanel Grid.Column="1" Orientation="Horizontal">
                        <Button x:Name="MinBtn" Style="{StaticResource TitleBtn}" Content="&#x2013;"/>
                        <Button x:Name="CloseBtn" Style="{StaticResource TitleBtn}" Content="X"/>
                    </StackPanel>
                </Grid>
            </Border>

            <Grid Grid.Row="1">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="200"/>
                </Grid.ColumnDefinitions>
                <Border Grid.Column="0" Margin="12,8,6,8">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        <WrapPanel x:Name="CatBar" Grid.Row="0" Margin="2,0,2,6"/>
                        <TabControl x:Name="ToolsTab" Grid.Row="1" Background="Transparent" BorderThickness="0" Padding="2">
                            <TabControl.Resources>
                                <Style TargetType="TabItem">
                                    <Setter Property="Visibility" Value="Collapsed"/>
                                </Style>
                            </TabControl.Resources>
                        </TabControl>
                    </Grid>
                </Border>

                <Border Grid.Column="1" Background="#0C0C0C" BorderBrush="{StaticResource Border}" BorderThickness="1,0,0,0">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        <Grid Grid.Row="0">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            <Border Grid.Row="0" Background="#080808">
                                <Grid>
                                    <Image x:Name="LogoImage" Width="200" Height="140" Stretch="UniformToFill" ClipToBounds="True" Opacity="0.7"/>
                                    <Border VerticalAlignment="Bottom">
                                        <Border.Background>
                                            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
                                                <GradientStop Color="#00080808" Offset="0"/>
                                                <GradientStop Color="#FF080808" Offset="1"/>
                                            </LinearGradientBrush>
                                        </Border.Background>
                                    </Border>
                                </Grid>
                            </Border>
                            <Border Grid.Row="1" Background="#0C0C0C" Padding="14,8">
                                <StackPanel>
                                    <TextBlock Text="VALYAR" FontSize="13" FontWeight="Bold" Foreground="#FFFFFF" FontFamily="Consolas"/>
                                    <TextBlock Text="ALL u want here" FontSize="8" Foreground="#444444" Margin="0,1,0,0"/>
                                </StackPanel>
                            </Border>
                        </Grid>
                        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                            <StackPanel Margin="0,4,0,4">
                                <Border Background="{StaticResource Surface}" Margin="8,2" Padding="10,6" CornerRadius="8">
                                    <StackPanel>
                                        <TextBlock Text="ACTIONS" FontSize="7" FontWeight="SemiBold" Foreground="#333333" FontFamily="Consolas" Margin="0,0,0,4"/>
                                        <Button x:Name="OpenFolderBtn" Content="Open Install Folder" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="ClearCacheBtn" Content="Clear Downloaded Files" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="OpenCmdBtn" Content="Open Terminal" Style="{StaticResource SideBtn}"/>
                                    </StackPanel>
                                </Border>
                                <Border Background="{StaticResource Surface}" Margin="8,2" Padding="10,6" CornerRadius="8">
                                    <StackPanel>
                                        <TextBlock Text="QUICK ACCESS" FontSize="7" FontWeight="SemiBold" Foreground="#333333" FontFamily="Consolas" Margin="0,0,0,4"/>
                                        <Button x:Name="BtnPrefetch" Content="Prefetch" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnRecent" Content="Recent Files" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnTemp" Content="Temp Folder" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnRecycleBin" Content="Recycle Bin" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnCrashDump" Content="Crash Dump" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnMsinfo32" Content="System Info" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnAppwiz" Content="Programs and Features" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnControlFolders" Content="Control Panel" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnWinHistory" Content="Windows History" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="BtnIndexedLoc" Content="Indexed Locations" Style="{StaticResource SideBtn}"/>
                                    </StackPanel>
                                </Border>
                                <Border Background="{StaticResource Surface}" Margin="8,2" Padding="10,6" CornerRadius="8">
                                    <StackPanel>
                                        <TextBlock Text="CREDITS" FontSize="7" FontWeight="SemiBold" Foreground="#333333" FontFamily="Consolas" Margin="0,0,0,4"/>
                                        <TextBlock Text="_iaec" FontSize="10" FontWeight="SemiBold" Foreground="#888888" FontFamily="Consolas"/>
                                        <TextBlock Text="Discord: _iaec" FontSize="8" Foreground="#444444" Margin="0,2,0,0"/>
                                        <TextBlock Text="GitHub: Va2lyR" FontSize="8" Foreground="#444444" Margin="0,1,0,0"/>
                                    </StackPanel>
                                </Border>
                                <Border Background="{StaticResource Surface}" Margin="8,2" Padding="10,6" CornerRadius="8">
                                    <Grid>
                                        <Grid.RowDefinitions>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="100"/>
                                        </Grid.RowDefinitions>
                                        <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,4">
                                            <Border Background="#E53935" Width="4" Height="4" CornerRadius="2" Margin="0,0,6,0" VerticalAlignment="Center"/>
                                            <TextBlock Text="LOG" FontSize="7" FontWeight="SemiBold" Foreground="#333333" FontFamily="Consolas" VerticalAlignment="Center"/>
                                        </StackPanel>
                                        <TextBox x:Name="LogBox" Grid.Row="1" Background="#080808" Foreground="#E53935" BorderBrush="#141414" BorderThickness="1" FontFamily="Consolas" FontSize="8" IsReadOnly="True" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap" Padding="6,4" VerticalAlignment="Stretch"/>
                                    </Grid>
                                </Border>
                            </StackPanel>
                        </ScrollViewer>
                    </Grid>
                </Border>
            </Grid>

            <Border Grid.Row="2" Background="#0C0C0C" BorderBrush="{StaticResource Border}" BorderThickness="0,1,0,0" Padding="14,4">
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <Border Background="#E53935" Width="4" Height="4" CornerRadius="2" Margin="0,0,6,0" VerticalAlignment="Center"/>
                    <TextBlock Text="VALYAR" FontSize="8" FontWeight="SemiBold" Foreground="#444444" FontFamily="Consolas" VerticalAlignment="Center"/>
                    <Border Background="#181818" Width="1" Height="10" Margin="10,0" VerticalAlignment="Center"/>
                    <TextBlock Text="v1.0" FontSize="8" Foreground="#2A2A2A" FontFamily="Consolas" VerticalAlignment="Center"/>
                </StackPanel>
            </Border>
        </Grid>
    </Border>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$MinBtn        = $window.FindName("MinBtn")
$CloseBtn      = $window.FindName("CloseBtn")
$StatusTitle   = $window.FindName("StatusTitle")
$StatusSub     = $window.FindName("StatusSub")
$StatusBadge   = $window.FindName("StatusBadgeText")
$LogBox        = $window.FindName("LogBox")
$ToolsTab      = $window.FindName("ToolsTab")
$CatBar        = $window.FindName("CatBar")
$OpenFolderBtn = $window.FindName("OpenFolderBtn")
$ClearCacheBtn = $window.FindName("ClearCacheBtn")
$OpenCmdBtn    = $window.FindName("OpenCmdBtn")
$BtnPrefetch   = $window.FindName("BtnPrefetch")
$BtnRecent     = $window.FindName("BtnRecent")
$BtnTemp       = $window.FindName("BtnTemp")
$BtnRecycleBin = $window.FindName("BtnRecycleBin")
$BtnCrashDump  = $window.FindName("BtnCrashDump")
$BtnMsinfo32   = $window.FindName("BtnMsinfo32")
$BtnAppwiz     = $window.FindName("BtnAppwiz")
$BtnControlFolders = $window.FindName("BtnControlFolders")
$BtnWinHistory = $window.FindName("BtnWinHistory")
$BtnIndexedLoc = $window.FindName("BtnIndexedLoc")
$LogoImage     = $window.FindName("LogoImage")

# Load logo image - try local first, then download from GitHub
$logoLoaded = $false
if (Test-Path -LiteralPath $logoPath) {
    try {
        $bi = New-Object System.Windows.Media.Imaging.BitmapImage
        $bi.BeginInit()
        $bi.UriSource = New-Object System.Uri($logoPath)
        $bi.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $bi.EndInit()
        $bi.Freeze()
        $LogoImage.Source = $bi
        $logoLoaded = $true
    } catch {}
}
if (-not $logoLoaded) {
    try {
        $logoUrl = "https://raw.githubusercontent.com/Va2lyR/ValyaRFuckHim/refs/heads/main/logo.jpg"
        $tempLogo = "$env:TEMP\vrfh_logo.jpg"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        (New-Object System.Net.WebClient).DownloadFile($logoUrl, $tempLogo)
        if (Test-Path -LiteralPath $tempLogo) {
            $bi = New-Object System.Windows.Media.Imaging.BitmapImage
            $bi.BeginInit()
            $bi.UriSource = New-Object System.Uri($tempLogo)
            $bi.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
            $bi.EndInit()
            $bi.Freeze()
            $LogoImage.Source = $bi
        }
    } catch {}
}


# HELPERS

function Write-Log {
    param([string]$msg)
    $time = Get-Date -Format "HH:mm:ss"
    $LogBox.Dispatcher.Invoke([Action]{
        $LogBox.AppendText("[$time] $msg`r`n")
        $LogBox.ScrollToEnd()
    })
}

function Set-Status {
    param($title, $sub, $badge = "BUSY")
    $window.Dispatcher.Invoke([Action]{
        $StatusTitle.Text = $title
        $StatusSub.Text   = $sub
        $StatusBadge.Text = $badge
    })
}

function Start-AppOrScript {
    param([Parameter(Mandatory=$true)][string]$Path, [string]$WorkingDirectory)
    if (-not $WorkingDirectory) { $WorkingDirectory = Split-Path -Parent $Path }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $qp = '"' + $Path + '"'
    switch ($ext) {
        ".cmd" { Start-Process -FilePath "cmd.exe" -ArgumentList "/k", $qp -WorkingDirectory $WorkingDirectory -WindowStyle Normal }
        ".bat" { Start-Process -FilePath "cmd.exe" -ArgumentList "/k", $qp -WorkingDirectory $WorkingDirectory -WindowStyle Normal }
        default { Start-Process -FilePath $Path -WorkingDirectory $WorkingDirectory -WindowStyle Normal }
    }
}

function Save-UrlToFile {
    param([Parameter(Mandatory=$true)][string]$Uri, [Parameter(Mandatory=$true)][string]$OutFile)
    $tempFile = "$OutFile.download"
    if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
    $client = New-Object System.Net.WebClient
    $client.Headers.Add("User-Agent", "ValyaRFuckHim")
    try {
        $client.DownloadFile($Uri, $tempFile)
        if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction Stop }
        Move-Item -LiteralPath $tempFile -Destination $OutFile -Force -ErrorAction Stop
    } finally {
        $client.Dispose()
        if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
    }
}

function Start-DownloadedTool {
    param([Parameter(Mandatory=$true)][string]$Directory, [string]$PreferredFile)
    if ($PreferredFile -and (Test-Path -LiteralPath $PreferredFile) -and ($PreferredFile -notmatch "\.zip$")) {
        Write-Log "Launching $(Split-Path -Leaf $PreferredFile)"
        Start-AppOrScript -Path $PreferredFile -WorkingDirectory (Split-Path -Parent $PreferredFile)
        return $true
    }
    $launchable = Get-ChildItem -Path $Directory -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match "^\.(exe|cmd|bat)$" } |
        Sort-Object @{ Expression = { if ($_.Extension -eq ".exe") { 0 } else { 1 } } }, FullName |
        Select-Object -First 1
    if ($launchable) {
        Write-Log "Launching $($launchable.Name)"
        Start-AppOrScript -Path $launchable.FullName -WorkingDirectory $launchable.DirectoryName
        return $true
    }
    Write-Log "No executable found - opening folder."
    Start-Process -FilePath explorer.exe -ArgumentList "`"$Directory`""
    return $false
}

function Get-GitHubAssetUrl {
    param([string]$ReleaseUrl)
    if ($ReleaseUrl -match "github\.com/([^/]+)/([^/]+)/releases/tag/(.+)$") {
        $user = $Matches[1]; $repo = $Matches[2]
        $tag = [Uri]::EscapeDataString(([Uri]::UnescapeDataString($Matches[3])).TrimEnd("/"))
        $api = "https://api.github.com/repos/$user/$repo/releases/tags/$tag"
        try {
            $rel = Invoke-RestMethod -Uri $api -Headers @{"User-Agent"="ValyaRFuckHim"} -ErrorAction Stop
            $asset = $rel.assets | Where-Object { $_.name -match "\.(exe|zip|cmd|bat)$" } | Select-Object -First 1
            if ($asset) { return @{ url=$asset.browser_download_url; name=$asset.name } }
        } catch { Write-Log "GitHub lookup failed: $($_.Exception.Message)" }
    }
    return $null
}


function Show-SourceCode {
    param([string]$ToolName, [string]$ToolType, [string]$ToolUrl, [string]$ToolCommand)

    $srcWin = New-Object System.Windows.Window
    $srcWin.Title = "Source - $ToolName"
    $srcWin.Width = 800
    $srcWin.Height = 600
    $srcWin.WindowStartupLocation = "CenterScreen"
    $srcWin.ResizeMode = "CanResize"
    $srcWin.WindowStyle = "None"
    $srcWin.AllowsTransparency = $true
    $srcWin.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#0B0B0B"))
    $srcWin.FontFamily = [System.Windows.Media.FontFamily]::new("Segoe UI")

    $mainBorder = New-Object System.Windows.Controls.Border
    $mainBorder.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#0B0B0B"))
    $mainBorder.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1E1E1E"))
    $mainBorder.BorderThickness = 1
    $mainBorder.CornerRadius = 12

    $rootGrid = New-Object System.Windows.Controls.Grid
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(42) }))
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(1) }))
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }))

    $header = New-Object System.Windows.Controls.Border
    $header.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#0D0D0D"))
    $headerGrid = New-Object System.Windows.Controls.Grid
    $headerGrid.Margin = "16,0"
    $headerGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }))
    $headerGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::Auto }))

    $titlePanel = New-Object System.Windows.Controls.StackPanel
    $titlePanel.Orientation = "Horizontal"
    $titlePanel.VerticalAlignment = "Center"
    $titleIcon = New-Object System.Windows.Controls.TextBlock
    $titleIcon.Text = "}"
    $titleIcon.FontSize = 13
    $titleIcon.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#E53935"))
    $titleIcon.Margin = "0,0,8,0"
    $titleIcon.VerticalAlignment = "Center"
    $titleText = New-Object System.Windows.Controls.TextBlock
    $titleText.Text = $ToolName
    $titleText.FontSize = 12
    $titleText.FontWeight = "SemiBold"
    $titleText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#FFFFFF"))
    $titleText.VerticalAlignment = "Center"
    $titlePanel.Children.Add($titleIcon) | Out-Null
    $titlePanel.Children.Add($titleText) | Out-Null
    [System.Windows.Controls.Grid]::SetColumn($titlePanel, 0)
    $headerGrid.Children.Add($titlePanel) | Out-Null

    $closeBtn = New-Object System.Windows.Controls.Button
    $closeBtn.Width = 36
    $closeBtn.Height = 28
    $closeBtn.Cursor = "Hand"
    $closeBtn.Background = "Transparent"
    $closeBtn.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#555555"))
    $closeBtn.FontFamily = [System.Windows.Media.FontFamily]::new("Segoe MDL2 Assets")
    $closeBtn.FontSize = 10
    $closeBtn.Content = "X"
    $closeBtnTemplate = New-Object System.Windows.Controls.ControlTemplate([System.Windows.Controls.Button])
    $closeBtnBorder = New-Object System.Windows.Controls.Border
    $closeBtnBorder.Background = "Transparent"
    $closeBtnBorder.CornerRadius = 6
    $closeBtnCP = New-Object System.Windows.Controls.ContentPresenter
    $closeBtnCP.HorizontalAlignment = "Center"
    $closeBtnCP.VerticalAlignment = "Center"
    $closeBtnBorder.Children.Add($closeBtnCP) | Out-Null
    $closeBtnTemplate.VisualTree = $closeBtnBorder
    $closeBtn.Template = $closeBtnTemplate
    $closeBtn.Add_Click({ $srcWin.Close() })
    [System.Windows.Controls.Grid]::SetColumn($closeBtn, 1)
    $headerGrid.Children.Add($closeBtn) | Out-Null
    [System.Windows.Controls.Grid]::SetRow($header, 0)
    $header.Child = $headerGrid
    $rootGrid.Children.Add($header) | Out-Null

    $sep = New-Object System.Windows.Controls.Border
    $sep.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1E1E1E"))
    [System.Windows.Controls.Grid]::SetRow($sep, 1)
    $rootGrid.Children.Add($sep) | Out-Null

    $contentArea = New-Object System.Windows.Controls.Grid
    $contentArea.Margin = "16,12"
    [System.Windows.Controls.Grid]::SetRow($contentArea, 2)

    $loadingText = New-Object System.Windows.Controls.TextBlock
    $loadingText.Text = "Loading source code..."
    $loadingText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#555555"))
    $loadingText.FontSize = 12
    $loadingText.HorizontalAlignment = "Center"
    $loadingText.VerticalAlignment = "Center"
    $contentArea.Children.Add($loadingText) | Out-Null

    $rootGrid.Children.Add($contentArea) | Out-Null
    $mainBorder.Child = $rootGrid
    $srcWin.Content = $mainBorder

    $srcWin.Add_MouseLeftButtonDown({ try { $srcWin.DragMove() } catch {} })

    $srcWin.Show()

    $srcCode = ""
    $srcUrl = ""

    if ($ToolType -eq "Cmd" -and $ToolCommand) {
        $urlMatch = [regex]::Match($ToolCommand, 'https?://[^\s''"]+')
        if ($urlMatch.Success) {
            $srcUrl = $urlMatch.Value
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $srcCode = (Invoke-WebRequest -Uri $srcUrl -UseBasicParsing -TimeoutSec 10).Content
            } catch {
                $srcCode = "Failed to fetch source code.`n`nURL: $srcUrl`n`nError: $($_.Exception.Message)"
            }
        } else {
            $srcCode = "Script command (no direct URL found):`n`n$ToolCommand"
        }
    } elseif ($ToolType -eq "GitHub" -and $ToolUrl) {
        $srcUrl = $ToolUrl -replace "/releases/latest$", ""
        $srcCode = "GitHub Repository: $srcUrl`n`nOpening in browser..."
        Start-Process $srcUrl
    } elseif ($ToolType -eq "Web" -and $ToolUrl) {
        $srcUrl = $ToolUrl
        $srcCode = "Download URL:`n$ToolUrl`n`nOpening in browser..."
        Start-Process $srcUrl
    } elseif ($ToolType -eq "Link" -and $ToolUrl) {
        $srcUrl = $ToolUrl
        $srcCode = "Link URL:`n$ToolUrl`n`nOpening in browser..."
        Start-Process $srcUrl
    } else {
        $srcCode = "No source code available for this tool."
    }

    $contentArea.Children.Clear()

    $urlBar = New-Object System.Windows.Controls.Border
    $urlBar.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#131313"))
    $urlBar.CornerRadius = 6
    $urlBar.Padding = "10,6"
    $urlBar.Margin = "0,0,0,10"

    $urlGrid = New-Object System.Windows.Controls.Grid
    $urlGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::Auto }))
    $urlGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }))

    $urlIcon = New-Object System.Windows.Controls.TextBlock
    $urlIcon.Text = "@"
    $urlIcon.FontSize = 11
    $urlIcon.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#555555"))
    $urlIcon.Margin = "0,0,8,0"
    $urlIcon.VerticalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($urlIcon, 0)
    $urlGrid.Children.Add($urlIcon) | Out-Null

    $urlText = New-Object System.Windows.Controls.TextBlock
    $urlText.Text = $srcUrl
    $urlText.FontSize = 11
    $urlText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#E53935"))
    $urlText.TextTrimming = "CharacterEllipsis"
    $urlText.VerticalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($urlText, 1)
    $urlGrid.Children.Add($urlText) | Out-Null

    $urlBar.Child = $urlGrid
    $contentArea.Children.Add($urlBar) | Out-Null

    $codeBox = New-Object System.Windows.Controls.TextBox
    $codeBox.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#0D0D0D"))
    $codeBox.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#E53935"))
    $codeBox.FontFamily = [System.Windows.Media.FontFamily]::new("Consolas")
    $codeBox.FontSize = 11
    $codeBox.TextWrapping = "NoWrap"
    $codeBox.AcceptsReturn = $true
    $codeBox.AcceptsTab = $true
    $codeBox.IsReadOnly = $true
    $codeBox.Text = $srcCode
    $codeBox.BorderThickness = 1
    $codeBox.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1E1E1E"))
    $codeBox.VerticalScrollBarVisibility = "Auto"
    $codeBox.HorizontalScrollBarVisibility = "Auto"
    $codeBox.Padding = "12,8"
    $codeBox.CaretBrush = "Transparent"
    $contentArea.Children.Add($codeBox) | Out-Null

    $mainBorder.ClipToBounds = $true
}


# TABS

$AllCategories = @("Valyar","ModAnalyzer","ClientsDetector","Orbdiff","Spokwn","Tonynoh","Praiselily","RedLotus","DetectAC","TeslaPro","Echo","TRSSCommunity","Magnet","Forensics","SystemTools","Analysis","Misc","NirSoft","Zimmerman","Scripts","Others","Dependencies")

$script:usedCats = @()

foreach ($cat in $AllCategories) {
    $catTools = $ToolData | Where-Object { $_.Category -eq $cat }
    if (-not $catTools) { continue }
    $script:usedCats += $cat

    $tab = New-Object System.Windows.Controls.TabItem
    $tab.Header = $cat
    $scroll = New-Object System.Windows.Controls.ScrollViewer
    $scroll.VerticalScrollBarVisibility = "Auto"
    $scroll.HorizontalScrollBarVisibility = "Disabled"
    $wrap = New-Object System.Windows.Controls.WrapPanel
    $wrap.Margin = "4"

    foreach ($tool in $catTools) {
        $t = $tool
        $btn = New-Object System.Windows.Controls.Button
        $btn.Width = 224; $btn.Height = 86; $btn.FontSize = 12; $btn.Margin = "6"; $btn.Cursor = "Hand"; $btn.Foreground = "#E0E0E0"

        $btnStack = New-Object System.Windows.Controls.StackPanel
        $btnStack.Margin = "14,10"
        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $t.Name; $nameBlock.FontSize = 12; $nameBlock.FontWeight = "SemiBold"; $nameBlock.TextWrapping = "Wrap"; $nameBlock.Foreground = "#FFFFFF"
        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $t.Desc; $descBlock.FontSize = 10; $descBlock.Opacity = 0.4; $descBlock.TextWrapping = "Wrap"; $descBlock.Margin = "0,4,0,0"; $descBlock.Foreground = "#999999"
        $btnStack.Children.Add($nameBlock) | Out-Null
        $btnStack.Children.Add($descBlock) | Out-Null

        $btn.Content = $btnStack

        $borderFactory = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
        $borderFactory.Name = "BtnBorder"
        $borderFactory.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#141414")))
        $borderFactory.SetValue([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1E1E1E")))
        $borderFactory.SetValue([System.Windows.Controls.Border]::BorderThicknessProperty, [System.Windows.Thickness]::new(1))
        $borderFactory.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(10))
        $borderFactory.SetValue([System.Windows.UIElement]::RenderTransformOriginProperty, [System.Windows.Point]::new(0.5, 0.5))

        $contentFactory = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.ContentPresenter])
        $contentFactory.SetValue([System.Windows.Controls.ContentPresenter]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
        $contentFactory.SetValue([System.Windows.Controls.ContentPresenter]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
        $borderFactory.AppendChild($contentFactory)

        $template = [System.Windows.Controls.ControlTemplate]::new([System.Windows.Controls.Button])
        $template.VisualTree = $borderFactory
        $btn.Template = $template

        $btn.Add_Loaded({
            $b = $_.Source
            if ([Windows.Media.VisualTreeHelper]::GetChildrenCount($b) -gt 0) {
                $border = [Windows.Media.VisualTreeHelper]::GetChild($b, 0)
                if ($border) {
                    $st = [System.Windows.Media.ScaleTransform]::new(1.0, 1.0)
                    $border.RenderTransform = $st
                    $b.Resources["sc"] = $st
                }
            }
        })

        $btn.Add_MouseEnter({
            $b = $_.Source; $sc = $b.Resources["sc"]
            if (-not $sc -or -not ($sc -is [System.Windows.Media.ScaleTransform])) { return }
            $d = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(130))
            $ease = [Windows.Media.Animation.CubicEase]::new()
            $ax = [Windows.Media.Animation.DoubleAnimation]::new(1.06, $d); $ax.EasingFunction = $ease
            $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $ax)
            $ay = [Windows.Media.Animation.DoubleAnimation]::new(1.06, $d); $ay.EasingFunction = $ease
            $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $ay)
            $b.Foreground = [Windows.Media.Brushes]::White
        })

        $btn.Add_MouseLeave({
            $b = $_.Source; $sc = $b.Resources["sc"]
            if (-not $sc -or -not ($sc -is [System.Windows.Media.ScaleTransform])) { return }
            $d = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(180))
            $ease = [Windows.Media.Animation.CubicEase]::new()
            $ax = [Windows.Media.Animation.DoubleAnimation]::new(1.0, $d); $ax.EasingFunction = $ease
            $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $ax)
            $ay = [Windows.Media.Animation.DoubleAnimation]::new(1.0, $d); $ay.EasingFunction = $ease
            $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $ay)
            $b.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom("#E0E0E0")
        })

        $btn.Add_PreviewMouseDown({
            $b = $_.Source; $sc = $b.Resources["sc"]
            if (-not $sc -or -not ($sc -is [System.Windows.Media.ScaleTransform])) { return }
            $d = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(80))
            $ax = [Windows.Media.Animation.DoubleAnimation]::new(0.95, $d)
            $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $ax)
            $ay = [Windows.Media.Animation.DoubleAnimation]::new(0.95, $d)
            $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $ay)
        })

        $btn.Add_PreviewMouseUp({
            $b = $_.Source; $sc = $b.Resources["sc"]
            if (-not $sc -or -not ($sc -is [System.Windows.Media.ScaleTransform])) { return }
            $d = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(100))
            $ax = [Windows.Media.Animation.DoubleAnimation]::new(1.06, $d)
            $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $ax)
            $ay = [Windows.Media.Animation.DoubleAnimation]::new(1.06, $d)
            $sc.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $ay)
        })

        $btn.Add_Click({
            $clickedBtn = $_.Source
            $tName = ($clickedBtn.Content.Children[0]).Text
            $tData = $ToolData | Where-Object { $_.Name -eq $tName } | Select-Object -First 1
            $clickedBtn.IsEnabled = $false

            $sc = $clickedBtn.Resources["sc"]
            if ($sc -and ($sc -is [System.Windows.Media.ScaleTransform])) {
                $dP = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(80))
                $sc.BeginAnimation([Windows.Media.ScaleTransform]::ScaleXProperty, [Windows.Media.Animation.DoubleAnimation]::new(0.93, $dP))
                $sc.BeginAnimation([Windows.Media.ScaleTransform]::ScaleYProperty, [Windows.Media.Animation.DoubleAnimation]::new(0.93, $dP))
            }

            $script:timer = [Windows.Threading.DispatcherTimer]::new()
            $script:timer.Interval = [TimeSpan]::FromMilliseconds(100)
            $script:timerBtn = $clickedBtn
            $script:timerName = $tName
            $script:timerData = $tData
            $script:timer.Add_Tick({
                $script:timer.Stop()
                $sc2 = $script:timerBtn.Resources["sc"]
                if ($sc2 -and ($sc2 -is [System.Windows.Media.ScaleTransform])) {
                    $dR = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(150))
                    $ez = [Windows.Media.Animation.CubicEase]::new()
                    $xR = [Windows.Media.Animation.DoubleAnimation]::new(1.0, $dR); $xR.EasingFunction = $ez
                    $yR = [Windows.Media.Animation.DoubleAnimation]::new(1.0, $dR); $yR.EasingFunction = $ez
                    $sc2.BeginAnimation([Windows.Media.ScaleTransform]::ScaleXProperty, $xR)
                    $sc2.BeginAnimation([Windows.Media.ScaleTransform]::ScaleYProperty, $yR)
                }
                $script:timerBtn.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom("#E0E0E0")

                if ($script:timerData.Type -eq "Link") {
                    Start-Process $script:timerData.URL
                    Set-Status "Ready" "Opened $($script:timerName) in browser." "IDLE"
                    $script:timerBtn.IsEnabled = $true
                } elseif ($script:timerData.Type -eq "Cmd") {
                    Set-Status "Running" "Launching $($script:timerName)..." "BUSY"
                    Write-Log "Starting: $($script:timerName)"
                    $rsc = [runspacefactory]::CreateRunspace()
                    $rsc.ApartmentState = "STA"; $rsc.ThreadOptions = "ReuseThread"; $rsc.Open()
                    $rsc.SessionStateProxy.SetVariable("timerData", $script:timerData)
                    $rsc.SessionStateProxy.SetVariable("timerName", $script:timerName)
                    $rsc.SessionStateProxy.SetVariable("timerBtn", $script:timerBtn)
                    $rsc.SessionStateProxy.SetVariable("dispatcher", $script:timerBtn.Dispatcher)
                    $rsc.SessionStateProxy.SetVariable("StatusTitle", $StatusTitle)
                    $rsc.SessionStateProxy.SetVariable("StatusSub", $StatusSub)
                    $rsc.SessionStateProxy.SetVariable("StatusBadge", $StatusBadge)
                    $rsc.SessionStateProxy.SetVariable("LogBox", $LogBox)
                    $psc = [powershell]::Create(); $psc.Runspace = $rsc
                    $null = $psc.AddScript({
                        function Set-StatusBg { param($t,$s,$b)
                            $dispatcher.Invoke([Action]{ $StatusTitle.Text=$t; $StatusSub.Text=$s; $StatusBadge.Text=$b })
                        }
                        function Write-LogBg { param($m)
                            $dispatcher.Invoke([Action]{ $LogBox.AppendText("[$(Get-Date -f 'HH:mm:ss')] $m`n"); $LogBox.ScrollToEnd() })
                        }
                        try {
                            Start-Process "powershell.exe" -ArgumentList @("-NoExit","-NoProfile","-ExecutionPolicy","Bypass","-Command",$timerData.Command)
                            Write-LogBg "Launched: $timerName"
                            Set-StatusBg "Ready" "$timerName launched." "IDLE"
                        } catch {
                            Write-LogBg "Error: $_"
                            Set-StatusBg "Error" "Failed to launch $timerName." "ERR"
                        }
                        $dispatcher.Invoke([Action]{ $timerBtn.IsEnabled = $true })
                    })
                    $null = $psc.BeginInvoke()
                } else {
                    Set-Status "Downloading" "Fetching $($script:timerName)..." "BUSY"
                    Write-Log "Starting download: $($script:timerName)"
                    $rs = [runspacefactory]::CreateRunspace()
                    $rs.ApartmentState = "STA"; $rs.ThreadOptions = "ReuseThread"; $rs.Open()
                    $rs.SessionStateProxy.SetVariable("tData", $script:timerData)
                    $rs.SessionStateProxy.SetVariable("installDir", $installDir)
                    $rs.SessionStateProxy.SetVariable("dispatcher", $script:timerBtn.Dispatcher)
                    $rs.SessionStateProxy.SetVariable("btn", $script:timerBtn)
                    $rs.SessionStateProxy.SetVariable("StatusTitle", $StatusTitle)
                    $rs.SessionStateProxy.SetVariable("StatusSub", $StatusSub)
                    $rs.SessionStateProxy.SetVariable("StatusBadge", $StatusBadge)
                    $rs.SessionStateProxy.SetVariable("LogBox", $LogBox)
                    $ps = [powershell]::Create(); $ps.Runspace = $rs
                    $null = $ps.AddScript({
                        function Set-StatusBg { param($title,$sub,$badge)
                            $dispatcher.Invoke([Action]{ $StatusTitle.Text=$title; $StatusSub.Text=$sub; $StatusBadge.Text=$badge })
                        }
                        function Write-LogBg { param($msg)
                            $dispatcher.Invoke([Action]{ $LogBox.AppendText("[$(Get-Date -f 'HH:mm:ss')] $msg`n"); $LogBox.ScrollToEnd() })
                        }
                        try {
                            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                            $destDir = "$installDir\$($tData.Category)\$($tData.Name)"
                            if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                            if ($tData.Type -eq "GitHub") {
                                $urlParts = $tData.URL -replace "https://github.com/","" -split "/"
                                $apiUrl = "https://api.github.com/repos/$($urlParts[0])/$($urlParts[1])/releases/latest"
                                $release = Invoke-RestMethod -Uri $apiUrl -Headers @{"User-Agent"="ValyaRFuckHim"} -ErrorAction Stop
                                $asset = $release.assets | Where-Object { $_.name -match "\.(zip|exe)$" } | Select-Object -First 1
                                if (-not $asset) { throw "No downloadable asset found." }
                                $dlUrl = $asset.browser_download_url; $fileName = $asset.name; $destFile = "$destDir\$fileName"
                            } else {
                                $dlUrl = $tData.URL; $fileName = ($tData.URL -split "/")[-1]; $destFile = "$destDir\$fileName"
                            }
                            if (Test-Path $destFile) {
                                Write-LogBg "Cached: $fileName - skipping download."
                            } else {
                                Write-LogBg "Downloading $fileName..."
                                $wc = New-Object System.Net.WebClient; $wc.DownloadFile($dlUrl, $destFile)
                                Write-LogBg "Download complete: $fileName"
                            }
                            if ($fileName -match "\.zip$") {
                                Write-LogBg "Extracting..."
                                Expand-Archive -Path $destFile -DestinationPath $destDir -Force -ErrorAction Stop
                                $exe = Get-ChildItem -Path $destDir -Filter "*.exe" -Recurse | Select-Object -First 1
                                if ($exe) { Write-LogBg "Launching $($exe.Name)..."; Start-Process -FilePath $exe.FullName }
                                else { $dispatcher.Invoke([Action]{ Start-Process -FilePath explorer.exe -ArgumentList "`"$destDir`"" }) }
                            } else {
                                Write-LogBg "Launching $fileName..."; Start-Process -FilePath $destFile
                            }
                            Set-StatusBg "Ready" "$($tData.Name) launched successfully." "IDLE"
                        } catch {
                            Write-LogBg "Error: $_"
                            Set-StatusBg "Error" "Something went wrong with $($tData.Name)." "ERR"
                        }
                        $dispatcher.Invoke([Action]{ $btn.IsEnabled = $true })
                        $rs.Close()
                    })
                    $null = $ps.BeginInvoke()
                }
            })
            $timer.Start()
        })

        $wrap.Children.Add($btn) | Out-Null
    }

    $scroll.Content = $wrap
    $tab.Content = $scroll
    $ToolsTab.Items.Add($tab) | Out-Null
}


# CATEGORY BAR (fixed buttons - they never move)
$script:toolsTabRef = $ToolsTab
$script:catButtons = @()
$script:activeCatIdx = 0
foreach ($c in $script:usedCats) {
    $cnt = @($ToolData | Where-Object { $_.Category -eq $c }).Count
    $pill = New-Object System.Windows.Controls.Button
    $pill.Content = "$c ($cnt)"
    $pill.FontSize = 10
    $pill.Height = 28
    $pill.Padding = "12,0"
    $pill.Margin = "3,2"
    $pill.Cursor = "Hand"
    $pill.Foreground = "#777777"
    $pill.Tag = $script:catButtons.Count

    $pBorder = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
    $pBorder.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#131313")))
    $pBorder.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(6))
    $pBorder.SetValue([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#222222")))
    $pBorder.SetValue([System.Windows.Controls.Border]::BorderThicknessProperty, [System.Windows.Thickness]::new(1))
    $pContent = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.ContentPresenter])
    $pContent.SetValue([System.Windows.Controls.ContentPresenter]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
    $pContent.SetValue([System.Windows.Controls.ContentPresenter]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
    $pBorder.AppendChild($pContent)
    $pTemplate = [System.Windows.Controls.ControlTemplate]::new([System.Windows.Controls.Button])
    $pTemplate.VisualTree = $pBorder
    $pill.Template = $pTemplate

    $pill.Add_Loaded({
        $lb = $_.Source
        if ($null -eq $lb.Tag) { $lb = $this }
        if ([Windows.Media.VisualTreeHelper]::GetChildrenCount($lb) -gt 0) {
            $lbrd = [Windows.Media.VisualTreeHelper]::GetChild($lb, 0)
            if ($lbrd -and $lbrd -is [System.Windows.Controls.Border] -and $lb.Tag -eq $script:activeCatIdx) {
                $lb.Foreground = [Windows.Media.Brushes]::White
                $lbrd.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#E53935"))
                $lbrd.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#E53935"))
            }
        }
    })
    $pill.Add_MouseEnter({
        $hb = $_.Source
        if ($null -eq $hb.Tag) { $hb = $this }
        if ($hb.Tag -ne $script:activeCatIdx -and [Windows.Media.VisualTreeHelper]::GetChildrenCount($hb) -gt 0) {
            $hbrd = [Windows.Media.VisualTreeHelper]::GetChild($hb, 0)
            if ($hbrd -and $hbrd -is [System.Windows.Controls.Border]) {
                $hbrd.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1C1C1C"))
            }
        }
    })
    $pill.Add_MouseLeave({
        $hb = $_.Source
        if ($null -eq $hb.Tag) { $hb = $this }
        if ($hb.Tag -ne $script:activeCatIdx -and [Windows.Media.VisualTreeHelper]::GetChildrenCount($hb) -gt 0) {
            $hbrd = [Windows.Media.VisualTreeHelper]::GetChild($hb, 0)
            if ($hbrd -and $hbrd -is [System.Windows.Controls.Border]) {
                $hbrd.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#131313"))
            }
        }
    })
    $pill.Add_Click({
        $clicked = $_.Source
        if ($null -eq $clicked.Tag) { $clicked = $this }
        $script:toolsTabRef.SelectedIndex = $clicked.Tag
        $script:activeCatIdx = $clicked.Tag
        foreach ($b in $script:catButtons) {
            $cbrd = $null
            if ([Windows.Media.VisualTreeHelper]::GetChildrenCount($b) -gt 0) {
                $cbrd = [Windows.Media.VisualTreeHelper]::GetChild($b, 0)
            }
            if ($b.Tag -eq $script:activeCatIdx) {
                $b.Foreground = [Windows.Media.Brushes]::White
                if ($cbrd) {
                    $cbrd.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#E53935"))
                    $cbrd.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#E53935"))
                }
            } else {
                $b.Foreground = "#777777"
                if ($cbrd) {
                    $cbrd.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#131313"))
                    $cbrd.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#222222"))
                }
            }
        }
    })

    $script:catButtons += $pill
    $CatBar.Children.Add($pill) | Out-Null
}
if ($ToolsTab.Items.Count -gt 0) { $ToolsTab.SelectedIndex = 0 }


# EVENTS

$window.Add_MouseLeftButtonDown({ try { $window.DragMove() } catch {} })
$CloseBtn.Add_Click({ $window.Close() })
$MinBtn.Add_Click({ $window.WindowState = "Minimized" })

$OpenFolderBtn.Add_Click({
    if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }
    Start-Process explorer.exe $installDir
    Write-Log "Opened install folder."
})

$ClearCacheBtn.Add_Click({
    if (Test-Path $installDir) {
        $items = Get-ChildItem -Path $installDir -Force -ErrorAction SilentlyContinue
        $count = @($items).Count
        $items | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Cleared $count item(s) from install folder."
        Set-Status "Clean" "Removed downloaded files and folders." "IDLE"
    } else {
        Write-Log "Nothing to clear - install folder does not exist yet."
    }
})

$OpenCmdBtn.Add_Click({
    Start-Process -FilePath "cmd.exe"
    Write-Log "Opened Terminal."
})

$BtnPrefetch.Add_Click({
    Start-Process explorer.exe "C:\Windows\Prefetch"
    Write-Log "Opened Prefetch folder."
})

$BtnRecent.Add_Click({
    Start-Process explorer.exe "shell:recent"
    Write-Log "Opened Recent Files."
})

$BtnTemp.Add_Click({
    Start-Process explorer.exe $env:TEMP
    Write-Log "Opened Temp folder."
})

$BtnRecycleBin.Add_Click({
    Start-Process explorer.exe "shell:recyclebinfolder"
    Write-Log "Opened Recycle Bin."
})

$BtnCrashDump.Add_Click({
    $dumpPath = "$env:SYSTEMROOT\Minidump"
    if (Test-Path $dumpPath) { Start-Process explorer.exe $dumpPath }
    else { Start-Process explorer.exe "$env:SYSTEMROOT" }
    Write-Log "Opened Crash Dump folder."
})

$BtnMsinfo32.Add_Click({
    Start-Process msinfo32.exe
    Write-Log "Opened System Information."
})

$BtnAppwiz.Add_Click({
    Start-Process appwiz.cpl
    Write-Log "Opened Programs & Features."
})

$BtnControlFolders.Add_Click({
    Start-Process explorer.exe "shell:control"
    Write-Log "Opened Control Panel."
})

$BtnWinHistory.Add_Click({
    Start-Process explorer.exe "shell:history"
    Write-Log "Opened Windows History."
})

$BtnIndexedLoc.Add_Click({
    Start-Process explorer.exe "shell:IndexedLocations"
    Write-Log "Opened Indexed Locations."
})

Write-Log "Files saved to: $installDir"
Set-Status "Ready" "Select a tool to launch or download it." "IDLE"

$window.ShowDialog() | Out-Null