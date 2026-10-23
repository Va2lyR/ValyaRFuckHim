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


#region TOOL DATA

$ToolData = @(
    @{ Name="ValyaR Jar Analyzer";  Desc="JAR file analyzer and decompiler";             Category="ValyaR"; Type="Web"; URL="https://github.com/Va2lyR/ValyaRJarAnalyzer/releases/download/2.3.1/ValyaRJarAnalyzer-2.3.1.exe" },
    @{ Name="ValyaR Mod Analyzer";  Desc="Analyzes Minecraft mods for cheat indicators"; Category="ValyaR"; Type="Web"; URL="https://github.com/Va2lyR/ValyaRModAnalyzer/releases/download/v1.0/ValyaRModAnalyzer.exe" },

    @{ Name="Xkzutos Mod Analyzer"; Desc="Analyzes Minecraft mods using metadata and hashes"; Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/xkzuto96/xkzutos-mod-analyzer/main/XkzutosModAnalyzer.ps1')" },

    @{ Name="Meow Mod Analyzer";  Desc="Analyzes Minecraft mods for suspicious indicators"; Category="Tonynoh"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/MeowTonynoh/MeowModAnalyzer/main/MeowModAnalyzer.ps1')" },
    @{ Name="MeowClientFucker";   Desc="Detects known cheat client artefacts";             Category="Tonynoh"; Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowClientFucker/releases/latest" },
    @{ Name="MeowDoomsdayFucker"; Desc="Detects Doomsday cheat artefacts";                Category="Tonynoh"; Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowDoomsdayFucker/releases/latest" },
    @{ Name="MeowResolver";       Desc="Resolves obfuscated strings in binaries";         Category="Tonynoh"; Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowResolver/releases/latest" },
    @{ Name="MeowNovowareFucker"; Desc="Detects Novoware cheat artefacts";                Category="Tonynoh"; Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowNovowareFucker/releases/latest" },
    @{ Name="MeowImportsChecker"; Desc="Checks PE imports for suspicious DLLs";           Category="Tonynoh"; Type="GitHub"; URL="https://github.com/MeowTonynoh/MeowImportsChecker/releases/latest" },

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

    @{ Name="Praiselily Doomsday Finder"; Desc="Finds Doomsday client artefacts";             Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/DoomsdayFinder.ps1')" },
    @{ Name="CommonDirectories";          Desc="Lists files in common suspicious dirs";      Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/CommonDirectories.ps1')" },
    @{ Name="HarddiskConverter";          Desc="Converts harddisk identifiers for review";   Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/HarddiskConverter.ps1')" },
    @{ Name="Services";                   Desc="Lists and analyzes running services";        Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Services.ps1')" },
    @{ Name="Service Enabler";            Desc="Service enabler by Praiselily";              Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Service-Enabler.ps1')" },
    @{ Name="SignedScheduledTasks";       Desc="Finds unsigned / suspicious scheduled tasks"; Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/SchedulesV2.ps1')" },

    @{ Name="P1aegg Mod Analyzer"; Desc="Analyzes Minecraft mods and files"; Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/p1aegg/powershell/refs/heads/main/modanalyzer.ps1')" },
    @{ Name="ClassLoader Dump";    Desc="Dumps ClassLoader data";            Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/p1aegg/powershell/refs/heads/main/ClassLoaderDump.ps1')" },
    @{ Name="P1AE Javaw";          Desc="Best Javaw scanner";                Category="Tools"; Type="GitHub"; URL="https://github.com/p1aegg/javaw/releases/latest" },
    @{ Name="Yarp Mod Analyzer";      Desc="Analyzes Minecraft mods for cheat indicators";   Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/YarpLetapStan/PowershellScripts/refs/heads/main/YarpsModAnalyzer6.0.ps1')" },
    @{ Name="Yumiko Mod Analyzer";    Desc="Analyzes Minecraft mods for suspicious content"; Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/veridondevvv/YumikoModAnalyzer/refs/heads/main/YumikoModAnalyzer.ps1')" },
    @{ Name="Habibi Mod Analyzer";    Desc="Analyzes Minecraft mods for suspicious content"; Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy Bypass -Scope Process; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/HadronCollision/PowershellScripts/refs/heads/main/HabibiModAnalyzer.ps1')" },
    @{ Name="Zedoon DoomsDay Detector"; Desc="Detects Doomsday client traces";               Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/zedoonvm1/powershell-scripts/refs/heads/main/DoomsDayDetector.ps1')" },
    @{ Name="CheesyDqrkisFucker";       Desc="Searches for Dqrkis-related traces";           Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/cheesecatlol/DQRKIS-FUCKER/refs/heads/main/DqrkisFucker.ps1')" },

    @{ Name="TeslaPro Doomsday Detector";   Desc="Launches the Doomsday client detection workflow"; Category="TeslaPro"; Type="Cmd"; Command="iex (irm 'https://raw.githubusercontent.com/TeslaPros/DoomsdayDetector/main/DoomsdayClientDetectorV3.ps1')" },
    @{ Name="TeslaPro GhostClientFinder";   Desc="Detects Ghost Client traces and modifications";   Category="TeslaPro"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/TeslaPros/GhostClientFucker/refs/heads/main/GhostClientFucker.ps1')" },
    @{ Name="TeslaPro Macro Finder Script"; Desc="TeslaPro macro finder";                          Category="TeslaPro"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/TeslaPros/TeslaProMacroFinder/main/TeslaProMacroFinder_V3.ps1')" },
    @{ Name="TeslaPro VPN Finder Script";   Desc="TeslaPro VPN finder";                            Category="TeslaPro"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/TeslaPros/VPNChecker/main/VPNFinder.ps1')" },
    @{ Name="TeslaPro MacroFinder";         Desc="Macro finder tool";                              Category="TeslaPro"; Type="GitHub"; URL="https://github.com/TeslaPros/TeslaProMacroFinder/releases/latest" },
    @{ Name="TeslaPro VPNFinder";           Desc="VPN finder";                                     Category="TeslaPro"; Type="GitHub"; URL="https://github.com/TeslaPros/VPNChecker/releases/latest" },
    @{ Name="TeslaPro GhostClientFucker";   Desc="Ghost client detector";                          Category="TeslaPro"; Type="GitHub"; URL="https://github.com/TeslaPros/GhostClientFucker/releases/latest" },
    @{ Name="RL ModAnalyzer";  Desc="Analyzes mod files for cheat indicators";     Category="RedLotus"; Type="GitHub"; URL="https://github.com/ItzIceHere/RedLotus-Mod-Analyzer/releases/latest" },
    @{ Name="RL TaskSentinel"; Desc="Monitors scheduled tasks for anomalies";      Category="RedLotus"; Type="GitHub"; URL="https://github.com/ItzIceHere/RedLotus-Task-Sentinel/releases/latest" },
    @{ Name="RL AltChecker";   Desc="Checks for alternate account indicators";     Category="RedLotus"; Type="GitHub"; URL="https://github.com/ItzIceHere/RedLotusAltChecker/releases/latest" },
    @{ Name="Prefetch Integrity Analyzer"; Desc="RedLotus prefetch integrity analyzer"; Category="RedLotus"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusPrefetchIntegrityAnalyzer.ps1')" },
    @{ Name="RedLotus BAM";               Desc="RedLotus BAM inspection";            Category="RedLotus"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/PureIntent/ScreenShare/main/RedLotusBam.ps1')" },
    @{ Name="File-Scanner-Powershell";    Desc="RedLotus file scanner";              Category="RedLotus"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/RedLotus-Development/File-Scanner-Powershell/refs/heads/Red-Lotus/REDLOTUS-AdminEXEs.ps1')" },
    @{ Name="RedLotus Collector";         Desc="RedLotus forensic collector";        Category="RedLotus"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/RedLotusForensics/tool/main/Collector.ps1')" },

    @{ Name="bstrings";              Desc="Searches strings with regex + YARA";      Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/bstrings.zip" },
    @{ Name="JLECmd";                Desc="Parses Jump List files (CLI)";            Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/JLECmd.zip" },
    @{ Name="JumpListExplorer";      Desc="GUI explorer for Jump List artefacts";    Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip" },
    @{ Name="MFTECmd";               Desc="Parses MFT, UsnJrnl, LogFile, Boot";     Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/MFTECmd.zip" },
    @{ Name="PECmd";                 Desc="Parses Windows prefetch files (CLI)";     Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/PECmd.zip" },
    @{ Name="RecentFileCacheParser"; Desc="Parses RecentFileCache.bcf artefact";     Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/RecentFileCacheParser.zip" },
    @{ Name="RegistryExplorer";      Desc="GUI explorer for registry hives";         Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip" },
    @{ Name="ShellBagsExplorer";     Desc="GUI explorer for ShellBags artefacts";    Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/ShellBagsExplorer.zip" },
    @{ Name="SrumECmd";              Desc="Parses SRUM database for usage data";     Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/SrumECmd.zip" },
    @{ Name="TimelineExplorer";      Desc="GUI viewer for CSV timeline output";      Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip" },
    @{ Name="AmcacheParser";         Desc="Parses AMCache with YARA + signatures";   Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net9/AmcacheParser.zip" },
    @{ Name="WxTCmd";                Desc="Windows Timeline database";                Category="Zimmerman";  Type="Web";    URL="https://download.ericzimmermanstools.com/net6/WxTCmd.zip" },

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

    @{ Name="Lily Services";         Desc="PraiseLily services checker";   Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Lafferrr/SSTools/refs/heads/main/LilysServices.ps1')" },
    @{ Name="Lily Services Enabler"; Desc="Services enabler";              Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Lafferrr/SSTools/refs/heads/main/LilysServicesEnabler.ps1')" },
    @{ Name="MacroScanner";          Desc="Lafferr Macro Scanner";         Category="Tools"; Type="GitHub"; URL="https://github.com/Lafferrr/MacroScanner/releases/latest" },
    @{ Name="StringChecker";         Desc="Lafferrs Strings Checker";      Category="Tools"; Type="GitHub"; URL="https://github.com/Lafferrr/SSTools/releases/latest" },
    @{ Name="Java Library Analyzer"; Desc="Lafferr Java Library Analyzer"; Category="Tools"; Type="GitHub"; URL="https://github.com/Lafferrr/SSTools/releases/latest" },

    @{ Name="Services Checker"; Desc="Nicc service checker";                    Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/NiccBlahh/ServiceChecker/refs/heads/main/ServiceChecker.ps1')" },
    @{ Name="MacroDetector";    Desc="Detects macro / clicker software traces"; Category="Scripts"; Type="Cmd"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/NiccBlahh/MacroDetector/refs/heads/main/MacroDetector.ps1')" },

    @{ Name="Zeezy Services";      Desc="Zeezyexe services checker"; Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/zeezyexe/services-checker/refs/heads/main/zeezyservices.psl')" },
    @{ Name="Zeezy Macro Scanner"; Desc="Zeezy macro scanner";         Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/zeezyexe/macro-scanner/refs/heads/main/catchmacro.ps1')" },

    @{ Name="All In One"; Desc="Enr1c0o all-in-one screenshare script"; Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Enr1c0o/Powershell-Scripts/refs/heads/main/All-in-one.ps1')" },

    @{ Name="JAR Parser Script";       Desc="L4rpsucks JAR parser";             Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/l4rpsucks/Scripts/refs/heads/main/JARParser.ps1')" },
    @{ Name="Fileless Bypass Detection"; Desc="Detects fileless bypass techniques"; Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/l4rpsucks/Scripts/refs/heads/main/FilelessBypassDetection.ps1')" },

    @{ Name="ComputerActivityView"; Desc="Timeline of computer activity events"; Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/computer_activity_view.html" },

    @{ Name="NET 8.0";    Desc="Microsoft .NET 8 SDK runtime";  Category="System"; Type="Web"; URL="https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-8.0.423-windows-x64-installer" },
    @{ Name="NET 9.0";    Desc="Microsoft .NET 9 SDK runtime";  Category="System"; Type="Web"; URL="https://download.visualstudio.microsoft.com/download/pr/92dba916-bc51-4e76-8b0e-d41d37ce5fa4/ab08f3e95bf7a3d3da336a7e8c8eca63/dotnet-sdk-9.0.203-win-x64.exe" },
    @{ Name="NET 10.0";   Desc="Microsoft .NET 10 runtime";     Category="System"; Type="Web"; URL="https://download.visualstudio.microsoft.com/download/pr/b3f93f0e-9e5e-4b4c-a4c4-36db0c4b0e3e/dotnet-runtime-10.0.0-win-x64.exe" },
    @{ Name="VSRedist";   Desc="Visual C++ redistributable (x64)"; Category="System"; Type="Web"; URL="https://aka.ms/vs/17/release/vc_redist.x64.exe" },

    @{ Name="Echo Journal";          Desc="Echo journal analysis tool";                           Category="Echo"; Type="GitHub"; URL="https://github.com/Echo-Anticheat/Echo-Journal/releases/latest" },
    @{ Name="Echo UserAssist";       Desc="Echo UserAssist registry viewer";                      Category="Echo"; Type="GitHub"; URL="https://github.com/Echo-Anticheat/Echo-Journal/releases/latest" },
    @{ Name="Echo UsbTool";          Desc="Echo USB record analysis";                             Category="Echo"; Type="GitHub"; URL="https://github.com/Echo-Anticheat/Echo-Journal/releases/latest" },

    @{ Name="PathDuzenleyicisiV2";   Desc="Path organizer v2";                                    Category="Tools"; Type="GitHub"; URL="https://github.com/trSScommunity/PathDuzenleyiciV2/releases/latest" },
    @{ Name="MzHunter";              Desc="MZ header scanner";                                    Category="Tools"; Type="GitHub"; URL="https://github.com/trSScommunity/MZHunter/releases/latest" },

    @{ Name="MagnetEncryptedDiskDetector"; Desc="Encrypted disk detector";                         Category="Tools"; Type="Web"; URL="https://go.magnetforensics.com/e/52162/MagnetEncryptedDiskDetector/kpt9bg/1663239667/h/LtXFtTL-Soawv5C1oL3BIEghi7e1Lx93yesZLR--Ok0" },
    @{ Name="MRCv120";               Desc="RAM dump tool";                                        Category="Tools"; Type="Web"; URL="https://go.magnetforensics.com/e/52162/mail-utm-campaign-UTMC-0000044/llr4bg/1663358653/h/4kZ9Y4i2yPRqBzuQMrywA_v5bfkpG3rG8gEiSWrYU70" },

    @{ Name="FTK Imager";            Desc="Disk imaging tool";                                    Category="Tools"; Type="Web"; URL="https://archive.org/download/access-data-ftk-imager-4.7.1/AccessData_FTK_Imager_4.7.1.exe" },

    @{ Name="SystemInformer"; Desc="Advanced system monitor";   Category="System"; Type="GitHub"; URL="https://github.com/winsiderss/si-builds/releases/latest" },
    @{ Name="Everything";     Desc="Instant filename search engine"; Category="System";  Type="Web";    URL="https://www.voidtools.com/Everything-1.4.1.1032.x64-Setup.exe" },
    @{ Name="ProcessHacker";  Desc="Process hacker";                Category="System"; Type="Web";   URL="https://sourceforge.net/projects/processhacker/files/latest/download" },

    @{ Name="InjGen v2";  Desc="Injection detection tool";       Category="Tools"; Type="GitHub"; URL="https://github.com/NotRequiem/InjGen/releases/latest" },
    @{ Name="Luyten";     Desc="Open source Java decompiler GUI"; Category="Tools"; Type="GitHub"; URL="https://github.com/deathmarine/Luyten/releases/latest" },
    @{ Name="DIE Engine"; Desc="Detect-It-Easy PE analyzer";         Category="Tools";     Type="GitHub"; URL="https://github.com/horsicq/DIE-engine/releases/latest" },

    @{ Name="Jarabel";            Desc="Locates .jar files with detailed checks"; Category="Tools";  Type="GitHub"; URL="https://github.com/nay-cat/Jarabel/releases/latest" },
    @{ Name="Unicode";            Desc="Unicode character analyzer";              Category="Tools";  Type="GitHub"; URL="https://github.com/RRancio/Exec/releases/latest" },
    @{ Name="CachedProgramsList"; Desc="Cache program list";                      Category="Tools";    Type="GitHub"; URL="https://github.com/ponei/CachedProgramsList/releases/latest" },
    @{ Name="TimeChangeDetect";   Desc="System time change detector";             Category="Tools"; Type="GitHub"; URL="https://github.com/santiagolin/TimeChangeDetect/releases/latest" },

    @{ Name="LastActivityView";      Desc="List recent user activity";                            Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/lastactivityview.zip" },
    @{ Name="UsbDriveLog";           Desc="Show USB drive history";                               Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/usbdrivelog.zip" },
    @{ Name="WinDefLogView";         Desc="Windows Defender log viewer";                          Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/windeflogview.zip" },
    @{ Name="UninstallView";         Desc="List installed programs";                              Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/uninstallview-x64.zip" },
    @{ Name="LoadedDllsView";        Desc="Loaded DLL list";                                      Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/loadeddllsview-x64.zip" },
    @{ Name="Clipboardic";           Desc="Clipboard history viewer";                             Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/clipboardic.zip" },
    @{ Name="FullEventLogView";      Desc="Views all Windows event log entries";         Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/fulleventlogview.zip" },
    @{ Name="NetworkUsageView";      Desc="Shows network usage per process";             Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/networkusageview.zip" },
    @{ Name="BrowserDownloadsView";  Desc="Lists all browser download history";          Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/browserdownloadsview.zip" },
    @{ Name="AlternateStreamView";   Desc="Reveals hidden NTFS alternate streams";       Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/alternatestreamview.zip" },
    @{ Name="USBDeview";             Desc="Lists all USB devices ever connected";        Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/usbdeview.zip" },
    @{ Name="OpenSaveFilesView";     Desc="Shows files opened/saved via dialogs";        Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/opensavefilesview.zip" },
    @{ Name="ExecutedProgramsList";  Desc="Lists programs run from various sources";     Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/executedprogramslist.zip" },
    @{ Name="TaskSchedulerView";     Desc="Views all scheduled tasks and history";       Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/taskschedulerview.zip" },
    @{ Name="JumpListsView";         Desc="Views Jump List recent/frequent files";       Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/jumplistsview.zip" },
    @{ Name="WinPrefetchView";       Desc="Views Windows prefetch file details";         Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/winprefetchview.zip" },
    @{ Name="RegScanner";            Desc="Scans registry for values / patterns";        Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/regscanner.zip" },
    @{ Name="ShellBagsView";         Desc="Views ShellBags folder access history";       Category="NirSoft"; Type="Web"; URL="https://www.nirsoft.net/utils/shellbagsview.zip" },

    @{ Name="BAM Robado Checker";     Desc="Check stolen BAM records"; Category="Scripts";   Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/IlleUco/ScreenShare/main/BamRobadoIlleUco.ps1')" },
    @{ Name="PrismScreenShareAnalyze"; Desc="PrismSSAnalyzer";            Category="Scripts";     Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/JustWolfeyy/PrismScreenShareAnalyzer/refs/heads/main/PrismSSAnalyzer.ps1')" },
    @{ Name="Javaw-Scanner";              Desc="Javaw scanner by DrakFlxme";  Category="Scripts"; Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/DrakFlxme/Javaw-Scanner.ps1/refs/heads/main/Javaw-Scanner.ps1')" },
    @{ Name="TeslaPro Prime Macro Detector"; Desc="Prime macro detector";    Category="Scripts";   Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Sellgui/Javamacrodetector/refs/heads/main/Macro%20Detector.ps1')" },
    @{ Name="Macro Detector (Nickk)";     Desc="Detect macro software";      Category="Scripts";  Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Nickk196/MacroDetector/main/MacroDetector.ps1')" },
    @{ Name="PJ Cheat Scanner Lite"; Desc="String Checker by gorbgallin"; Category="Tools"; Type="GitHub"; URL="https://github.com/gorbgallin/Pj-sCheatScannerLite/releases/latest" },

    @{ Name="VMAware";      Desc="Advanced VM detection library and tool";    Category="Tools";  Type="GitHub"; URL="https://github.com/kernelwernel/VMAware/releases/latest" },
    @{ Name="Velociraptor"; Desc="Endpoint DFIR and threat hunting agent";    Category="Tools";     Type="GitHub"; URL="https://github.com/Velocidex/velociraptor/releases/latest" },
    @{ Name="NTFS Parser";  Desc="NTFS forensics: MFT, Bitlocker, USN";      Category="Tools"; Type="GitHub"; URL="https://github.com/thewhiteninja/ntfstool/releases/latest" },
    @{ Name="Hayabusa";     Desc="Fast forensics timeline generator";         Category="Tools"; Type="GitHub"; URL="https://github.com/Yamato-Security/hayabusa/releases/latest" },
    @{ Name="HxD";          Desc="Fast hex editor with disk and RAM editing"; Category="System";      Type="Link";   URL="https://mh-nexus.de/en/hxd/" },

    # --- Imported from SSTool (tools/categories that were missing here) ---
    @{ Name="Amcache Parser";       Desc="Parses AMCache with YARA + signatures";          Category="Orbdiff";   Type="GitHub"; URL="https://github.com/Orbdiff/AmcacheParser/releases/latest" },
    @{ Name="Bam Check Restart";    Desc="Detects the date of creation of the BAM";        Category="Orbdiff";   Type="GitHub"; URL="https://github.com/Orbdiff/BAM-CheckRestart/releases/latest" },
    @{ Name="Recording Killer";     Desc="Kills recording / screen-share processes";       Category="Orbdiff";   Type="Cmd"; Command="Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Orbdiff/powershell/refs/heads/main/kill-screen-processes.ps1')" },
    @{ Name="EvtxECmd";             Desc="Parses Windows event log (evtx) files";          Category="Zimmerman"; Type="Web"; URL="https://download.ericzimmermanstools.com/net9/EvtxECmd.zip" },
    @{ Name="AppCompatCacheParser"; Desc="Parses AppCompatCache (ShimCache) artefact";      Category="Zimmerman"; Type="Web"; URL="https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip" },
    @{ Name="Running Processes";    Desc="Lists running processes sorted by CPU";          Category="Scripts";    Type="Cmd"; Command="Get-Process | Sort-Object CPU -Descending | Format-Table Name,ID,CPU,WorkingSet -AutoSize" },
    @{ Name="Collect System Info";  Desc="Dumps full computer / OS information";           Category="Scripts";    Type="Cmd"; Command="Get-ComputerInfo" }
)

#endregion


#region DISCLAIMER DIALOG

[xml]$disclaimerXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="ValyaRFuckHim" Width="520" Height="480" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" FontFamily="Segoe UI">
    <Window.Resources>
        <Style x:Key="CancelBtnStyle" TargetType="Button">
            <Setter Property="Background" Value="#D6D6D6"/>
            <Setter Property="Foreground" Value="#4E4E4E"/>
            <Setter Property="BorderBrush" Value="#909090"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Height" Value="40"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="#D6D6D6" CornerRadius="8" BorderBrush="#909090" BorderThickness="1">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#B0B0B0"/>
                                <Setter Property="Foreground" Value="#444444"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="AcceptBtnStyle" TargetType="Button">
            <Setter Property="Background" Value="#2E2E2E"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
            <Setter Property="BorderBrush" Value="#2E2E2E"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Height" Value="40"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="#2E2E2E" CornerRadius="8" BorderBrush="#2E2E2E" BorderThickness="1">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#4A4A4A"/>
                                <Setter TargetName="b" Property="BorderBrush" Value="#4A4A4A"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Border Background="#C4C4C4" BorderBrush="#A0A0A0" BorderThickness="1" Padding="28" CornerRadius="8">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="*"/>
                <RowDefinition Height="56"/>
            </Grid.RowDefinitions>
            <StackPanel Grid.Row="0">
                <TextBlock Text="ValyaRFuckHim" FontSize="22" FontWeight="Bold" Foreground="#1F1F1F" Margin="0,0,0,4"/>
                <TextBlock Text="ALL u want here" FontSize="11" Foreground="#2E2E2E" Margin="0,0,0,20"/>
                <Border Background="#A0A0A0" Height="1" Margin="0,0,0,20"/>
                <TextBlock TextWrapping="Wrap" Foreground="#444444" FontSize="12" Margin="0,0,0,14" Text="This toolkit was built and curated by ValyaR. Every tool included is open-source and fetched directly from its original GitHub repository. Your data is never collected, stored, or shared."/>
                <TextBlock TextWrapping="Wrap" Foreground="#444444" FontSize="12" Margin="0,0,0,14" Text="IMPORTANT: Before running any tool, take a moment to research what it does. GitHub repositories can be compromised at any time. ValyaR is not responsible for any damage caused by third-party tools. You are solely responsible for verifying and using them at your own risk."/>
                <TextBlock TextWrapping="Wrap" Foreground="#444444" FontSize="12" Margin="0,0,0,14" Text="By clicking Accept, you confirm that you understand these risks and agree to use this toolkit responsibly."/>
                <Border Background="#A0A0A0" Height="1" Margin="0,0,0,16"/>
                <TextBlock TextWrapping="Wrap" Foreground="#1F1F1F" FontSize="12" FontWeight="SemiBold" Text="You must agree to continue."/>
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

#endregion


#region MAIN WINDOW

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="ValyaRFuckHim" Width="1200" Height="800" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" FontFamily="Segoe UI">
    <Window.Resources>
        <SolidColorBrush x:Key="Bg" Color="#C4C4C4"/>
        <SolidColorBrush x:Key="Surface" Color="#CCCCCC"/>
        <SolidColorBrush x:Key="Surface2" Color="#D6D6D6"/>
        <SolidColorBrush x:Key="Border" Color="#A8A8A8"/>
        <SolidColorBrush x:Key="Accent" Color="#2E2E2E"/>
        <SolidColorBrush x:Key="Text" Color="#1F1F1F"/>
        <SolidColorBrush x:Key="TextSec" Color="#4E4E4E"/>
        <SolidColorBrush x:Key="TextDim" Color="#777777"/>
        <Style x:Key="TitleBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#777777"/>
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
                                <Setter TargetName="b" Property="Background" Value="#2E2E2E"/>
                                <Setter Property="Foreground" Value="#FFFFFF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="SideBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#5A5A5A"/>
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
                                <Setter TargetName="b" Property="Background" Value="#D8D8D8"/>
                                <Setter Property="Foreground" Value="#FFFFFF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="AppTextBox" TargetType="TextBox">
            <Setter Property="Background" Value="#CACACA"/>
            <Setter Property="Foreground" Value="#3A3A3A"/>
            <Setter Property="BorderBrush" Value="#A0A0A0"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CaretBrush" Value="#2E2E2E"/>
            <Setter Property="SelectionBrush" Value="#2E2E2E"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Padding" Value="10,6"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border x:Name="Bd"
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4">
                            <ScrollViewer x:Name="PART_ContentHost"
                                          Margin="{TemplateBinding Padding}"
                                          HorizontalScrollBarVisibility="{TemplateBinding HorizontalScrollBarVisibility}"
                                          VerticalScrollBarVisibility="{TemplateBinding VerticalScrollBarVisibility}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="BorderBrush" Value="#909090"/>
                            </Trigger>
                            <Trigger Property="IsKeyboardFocused" Value="True">
                                <Setter TargetName="Bd" Property="BorderBrush" Value="#2E2E2E"/>
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

            <!-- animated background: subtle red digital rain behind everything -->
            <Canvas x:Name="RainCanvas" Grid.RowSpan="3" IsHitTestVisible="False" ClipToBounds="True"/>

            <Border Grid.Row="0" Background="#B3C6C6C6" BorderBrush="{StaticResource Border}" BorderThickness="0,0,0,1">
                <Grid Margin="16,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <Border Background="#2E2E2E" Width="6" Height="6" CornerRadius="3" Margin="0,0,8,0" VerticalAlignment="Center"/>
                        <TextBlock Text="VALYAR" FontSize="12" FontWeight="Bold" Foreground="#1F1F1F" FontFamily="Consolas" VerticalAlignment="Center"/>
                        <Border Background="#B0B0B0" Width="1" Height="14" Margin="10,0" VerticalAlignment="Center"/>
                        <Border x:Name="StatusBadge" Background="#BFBFBF" Padding="8,2" VerticalAlignment="Center" CornerRadius="3">
                            <TextBlock x:Name="StatusBadgeText" Text="IDLE" FontSize="8" FontWeight="Bold" Foreground="#2E2E2E" FontFamily="Consolas"/>
                        </Border>
                        <TextBlock x:Name="StatusTitle" Text="Ready" FontSize="10" Foreground="#555555" VerticalAlignment="Center" Margin="8,0,0,0"/>
                        <TextBlock x:Name="StatusSub" Text="Select a tool to begin." FontSize="9" Foreground="#888888" VerticalAlignment="Center" Margin="6,0,0,0"/>
                    </StackPanel>
                    <StackPanel Grid.Column="1" Orientation="Horizontal">
                        <Grid Margin="0,0,2,0">
                            <Button x:Name="NoticeBtn" Style="{StaticResource TitleBtn}" FontFamily="Segoe MDL2 Assets" Content="&#xE7ED;" Width="44" Height="34" FontSize="19"/>
                            <Border x:Name="NoticeDot" Background="#2E2E2E" BorderBrush="#C6C6C6" BorderThickness="2" CornerRadius="10" Width="20" Height="20" HorizontalAlignment="Right" VerticalAlignment="Top" IsHitTestVisible="False">
                                <TextBlock Text="1" FontSize="10" FontWeight="Bold" Foreground="#FFFFFF" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                <Border.Triggers>
                                    <EventTrigger RoutedEvent="Border.Loaded">
                                        <BeginStoryboard>
                                            <Storyboard>
                                                <DoubleAnimation Storyboard.TargetProperty="Opacity" From="1" To="0.35" Duration="0:0:0.55" AutoReverse="True" RepeatBehavior="Forever"/>
                                            </Storyboard>
                                        </BeginStoryboard>
                                    </EventTrigger>
                                </Border.Triggers>
                            </Border>
                        </Grid>
                        <Button x:Name="RainBtn" Style="{StaticResource TitleBtn}" FontFamily="Segoe MDL2 Assets" Content="&#xE769;" Width="40" Height="34" FontSize="14" Margin="0,0,2,0"/>
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
                        <Border Grid.Row="0" Background="#CCCCCC" BorderBrush="#B0B0B0" BorderThickness="1" CornerRadius="6" Margin="2,0,2,6" Padding="10,0">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Text=">" Foreground="#2E2E2E" FontSize="12" FontWeight="Bold" FontFamily="Consolas" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                <TextBox x:Name="SearchBox" Grid.Column="1" Style="{StaticResource AppTextBox}" Background="Transparent" Foreground="#3A3A3A" CaretBrush="#2E2E2E" BorderThickness="0" FontFamily="Consolas" FontSize="11" Padding="0,8" VerticalAlignment="Center"/>
                            </Grid>
                        </Border>
                        <Grid Grid.Row="1">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <Border Grid.Row="0" Background="#CACACA" BorderBrush="#B0B0B0" BorderThickness="0,0,0,1" Padding="8,3,8,0" Margin="0,0,0,6">
                                <ScrollViewer HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Disabled" Focusable="False">
                                    <StackPanel x:Name="CatBar" Orientation="Horizontal"/>
                                </ScrollViewer>
                            </Border>
                            <TabControl x:Name="ToolsTab" Grid.Row="1" Background="Transparent" BorderThickness="0" Padding="2">
                                <TabControl.Resources>
                                    <Style TargetType="TabItem">
                                        <Setter Property="Visibility" Value="Collapsed"/>
                                    </Style>
                                </TabControl.Resources>
                            </TabControl>
                        </Grid>
                    </Grid>
                </Border>

                <Border Grid.Column="1" Background="#B3C6C6C6" BorderBrush="{StaticResource Border}" BorderThickness="1,0,0,0">
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
                            <Border Grid.Row="0" Background="#BCBCBC">
                                <Grid>
                                    <Image x:Name="LogoImage" Width="200" Height="140" Stretch="UniformToFill" ClipToBounds="True" Opacity="0.7"/>
                                    <Border VerticalAlignment="Bottom">
                                        <Border.Background>
                                            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
                                                <GradientStop Color="#00D2D2D2" Offset="0"/>
                                                <GradientStop Color="#FFD2D2D2" Offset="1"/>
                                            </LinearGradientBrush>
                                        </Border.Background>
                                    </Border>
                                </Grid>
                            </Border>
                            <Border Grid.Row="1" Background="#B3C6C6C6" Padding="14,8">
                                <StackPanel>
                                    <TextBlock Text="VALYAR" FontSize="13" FontWeight="Bold" Foreground="#1F1F1F" FontFamily="Consolas"/>
                                    <TextBlock Text="ALL u want here" FontSize="8" Foreground="#777777" Margin="0,1,0,0"/>
                                </StackPanel>
                            </Border>
                        </Grid>
                        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                            <StackPanel Margin="0,4,0,4">
                                <Border Background="{StaticResource Surface}" Margin="8,2" Padding="12,10" CornerRadius="8" BorderBrush="#D8D8D8" BorderThickness="1">
                                    <StackPanel>
                                        <TextBlock Text="CREDITS" FontSize="9" FontWeight="Bold" Foreground="#5A5A5A" FontFamily="Consolas" Margin="0,0,0,6"/>
                                        <TextBlock Text="_iaec" FontSize="15" FontWeight="Bold" Foreground="#2E2E2E" FontFamily="Consolas"/>
                                        <TextBlock FontSize="11" FontWeight="SemiBold" Foreground="#2E2E2E" FontFamily="Consolas" Margin="0,4,0,0">
                                            <Run Text="Discord: "/><Run Text="_iaec" FontWeight="Bold"/>
                                        </TextBlock>
                                        <TextBlock FontSize="10" Foreground="#4E4E4E" FontFamily="Consolas" Margin="0,2,0,0">
                                            <Run Text="GitHub: "/><Run Text="Va2lyR" FontWeight="SemiBold"/>
                                        </TextBlock>
                                    </StackPanel>
                                </Border>
                                <Border Background="{StaticResource Surface}" Margin="8,2" Padding="10,6" CornerRadius="8">
                                    <StackPanel>
                                        <TextBlock Text="ACTIONS" FontSize="7" FontWeight="SemiBold" Foreground="#888888" FontFamily="Consolas" Margin="0,0,0,4"/>
                                        <Button x:Name="OpenFolderBtn" Content="Open Install Folder" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="ClearCacheBtn" Content="Clear Downloaded Files" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="OpenCmdBtn" Content="Open Terminal" Style="{StaticResource SideBtn}"/>
                                        <Button x:Name="UpdateBtn" Content="Check for Updates" Style="{StaticResource SideBtn}"/>
                                        <TextBlock Text="SAVE TO" FontSize="7" FontWeight="SemiBold" Foreground="#888888" FontFamily="Consolas" Margin="0,8,0,2"/>
                                        <TextBlock x:Name="InstPathText" FontSize="8" Foreground="#6E6E6E" FontFamily="Consolas" TextWrapping="Wrap"/>
                                    </StackPanel>
                                </Border>
                                <Border Background="{StaticResource Surface}" Margin="8,2" Padding="10,6" CornerRadius="8">
                                    <StackPanel>
                                        <TextBlock Text="QUICK ACCESS" FontSize="7" FontWeight="SemiBold" Foreground="#888888" FontFamily="Consolas" Margin="0,0,0,4"/>
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
                            </StackPanel>
                        </ScrollViewer>
                    </Grid>
                </Border>
            </Grid>

            <Border Grid.Row="2" Background="#B3C6C6C6" BorderBrush="{StaticResource Border}" BorderThickness="0,1,0,0" Padding="14,8">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="110"/>
                    </Grid.RowDefinitions>
                    <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,6">
                        <Border Background="#2E2E2E" Width="6" Height="6" CornerRadius="3" Margin="0,0,8,0" VerticalAlignment="Center"/>
                        <TextBlock Text="LOG" FontSize="10" FontWeight="SemiBold" Foreground="#4E4E4E" FontFamily="Consolas" VerticalAlignment="Center"/>
                        <Border Background="#B0B0B0" Width="1" Height="12" Margin="10,0" VerticalAlignment="Center"/>
                        <TextBlock Text="VALYAR v1.0" FontSize="8" Foreground="#888888" FontFamily="Consolas" VerticalAlignment="Center"/>
                    </StackPanel>
                    <TextBox x:Name="LogBox" Grid.Row="1" Style="{StaticResource AppTextBox}" Background="#BCBCBC" Foreground="#2E2E2E" BorderBrush="#B0B0B0" BorderThickness="1" FontFamily="Consolas" FontSize="10" IsReadOnly="True" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap" Padding="8,6"/>
                </Grid>
            </Border>

            <!-- browser-style download shelf: one stacked row per active download (Chrome-like), auto-hides when empty -->
            <Border x:Name="DownloadPanel" Grid.RowSpan="3" Visibility="Collapsed" HorizontalAlignment="Right" VerticalAlignment="Bottom"
                    Margin="0,0,18,126" Width="330" MaxHeight="430" Background="#D6D6D6" BorderBrush="#A0A0A0" BorderThickness="1"
                    CornerRadius="10" Padding="12,10" Panel.ZIndex="40">
                <Border.Effect>
                    <DropShadowEffect BlurRadius="26" ShadowDepth="6" Opacity="0.30" Color="#000000"/>
                </Border.Effect>
                <DockPanel>
                    <Grid DockPanel.Dock="Top" Margin="0,0,2,8">
                        <TextBlock Text="DOWNLOADS" FontSize="9" FontWeight="Bold" Foreground="#5A5A5A" FontFamily="Consolas" VerticalAlignment="Center"/>
                        <TextBlock x:Name="DlCount" Text="" FontSize="9" Foreground="#8A8A8A" FontFamily="Consolas" HorizontalAlignment="Right" VerticalAlignment="Center"/>
                    </Grid>
                    <Border DockPanel.Dock="Top" Background="#B0B0B0" Height="1" Margin="0,0,0,8"/>
                    <ScrollViewer x:Name="DlScroll" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Padding="0,0,2,0">
                        <StackPanel x:Name="DlList"/>
                    </ScrollViewer>
                </DockPanel>
            </Border>

            <!-- in-window overlay hosting the source-check dialog (Esc / backdrop click closes) -->
            <Grid x:Name="LinkOverlay" Grid.RowSpan="3" Visibility="Collapsed" Focusable="True">
                <Border x:Name="LinkOverlayDim" Background="#B3000000"/>
                <ContentControl x:Name="LinkOverlayHost" HorizontalAlignment="Center" VerticalAlignment="Center" IsTabStop="False"/>
            </Grid>

            <!-- in-window overlay hosting the notification / disclaimer -->
            <Grid x:Name="NoticeOverlay" Grid.RowSpan="3" Visibility="Collapsed" Focusable="True">
                <Border x:Name="NoticeOverlayDim" Background="#B3000000"/>
                <Border Background="#C8C8C8" BorderBrush="#969696" BorderThickness="1" CornerRadius="14" Width="470" Padding="0" VerticalAlignment="Center" HorizontalAlignment="Center">
                    <Border.Effect>
                        <DropShadowEffect BlurRadius="30" ShadowDepth="10" Opacity="0.7" Color="#000000"/>
                    </Border.Effect>
                    <StackPanel>
                        <!-- header: red accent strip + bell + title -->
                        <Border Background="#D0D0D0" CornerRadius="14,14,0,0" Padding="16,11">
                            <Grid>
                                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                                    <Border Background="#2E2E2E" Width="24" Height="24" CornerRadius="12" Margin="0,0,10,0">
                                        <TextBlock Text="!" FontSize="14" FontWeight="Bold" Foreground="#FFFFFF" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Border>
                                    <StackPanel VerticalAlignment="Center">
                                        <TextBlock Text="تنبيه / NOTICE" FontSize="12" FontWeight="Bold" Foreground="#1F1F1F"/>
                                        <TextBlock Text="Read before using" FontSize="8" Foreground="#5A5A5A" FontFamily="Consolas" Margin="0,1,0,0"/>
                                    </StackPanel>
                                </StackPanel>
                                <Button x:Name="NoticeCloseBtn" HorizontalAlignment="Right" Width="26" Height="26" Cursor="Hand" Foreground="#5A5A5A" FontSize="9" Content="&#x2715;" Style="{StaticResource TitleBtn}"/>
                            </Grid>
                        </Border>
                        <Border Background="#969696" Height="1"/>

                        <!-- body: two compact cards, each with a red left accent -->
                        <StackPanel Margin="14,12">
                            <!-- Arabic card (RTL) -->
                            <Border Background="#CECECE" BorderBrush="#A0A0A0" BorderThickness="1" CornerRadius="8" Padding="0" Margin="0,0,0,9">
                                <Grid>
                                    <Border Grid.Column="0" Width="3" Background="#2E2E2E" CornerRadius="8,0,0,8" HorizontalAlignment="Left"/>
                                    <StackPanel Margin="13,9" FlowDirection="RightToLeft">
                                        <TextBlock Text="إخلاء مسؤولية" FontSize="12" FontWeight="Bold" Foreground="#2E2E2E" TextAlignment="Right" Margin="0,0,0,4"/>
                                        <TextBlock FontSize="10.5" Foreground="#4A4A4A" TextWrapping="Wrap" TextAlignment="Right" LineHeight="16">
                                            الاستخدام على مسؤوليتك، وأنا ما أتحمل مسؤولية أي أداة — كاتورجي الـ ValyaR حقي.
                                            قبل تشغيل أي أداة اضغط زر (!) على الكارت وراجع المصدر والملف اللي راح تحمله.
                                            وثبّت دائماً إنك تفحص كل أداة على موقع Virustotal قبل التشغيل.
                                        </TextBlock>
                                    </StackPanel>
                                </Grid>
                            </Border>

                            <!-- English card -->
                            <Border Background="#CECECE" BorderBrush="#A0A0A0" BorderThickness="1" CornerRadius="8" Padding="0">
                                <Grid>
                                    <Border Grid.Column="0" Width="3" Background="#2E2E2E" CornerRadius="8,0,0,8" HorizontalAlignment="Left"/>
                                    <StackPanel Margin="13,9">
                                        <TextBlock Text="DISCLAIMER" FontSize="11" FontWeight="Bold" Foreground="#2E2E2E" FontFamily="Consolas" Margin="0,0,0,4"/>
                                        <TextBlock FontSize="10.5" Foreground="#4A4A4A" TextWrapping="Wrap" LineHeight="16">
                                            Use at your own risk — I am not responsible for any tool. The ValyaR category is mine.
                                            Before running a tool, press the ! button on its card to review the source and the file you will download.
                                            Always scan every tool on VirusTotal before you run it.
                                        </TextBlock>
                                    </StackPanel>
                                </Grid>
                            </Border>
                        </StackPanel>

                        <!-- footer: Continue (launch) + Deny (cancel) -->
                        <Border Background="#CACACA" CornerRadius="0,0,14,14" Padding="14,10" BorderBrush="#B0B0B0" BorderThickness="0,1,0,0">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Button x:Name="NoticeDenyBtn" Grid.Column="0" Height="34" Padding="14,0" Cursor="Hand" FontSize="11" FontWeight="SemiBold" Content="رفض / Deny" Foreground="#3A3A3A"/>
                                <Button x:Name="NoticeContinueBtn" Grid.Column="2" Height="34" Padding="14,0" Cursor="Hand" FontSize="11" FontWeight="Bold" Content="متابعة / Continue" Foreground="#FFFFFF"/>
                            </Grid>
                        </Border>
                    </StackPanel>
                </Border>
            </Grid>
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
$SearchBox     = $window.FindName("SearchBox")
$InstPathText  = $window.FindName("InstPathText")
$NoticeBtn     = $window.FindName("NoticeBtn")
$NoticeDot     = $window.FindName("NoticeDot")
$NoticeOverlay = $window.FindName("NoticeOverlay")
$NoticeOverlayDim = $window.FindName("NoticeOverlayDim")
$NoticeCloseBtn   = $window.FindName("NoticeCloseBtn")
$NoticeContinueBtn = $window.FindName("NoticeContinueBtn")
$NoticeDenyBtn     = $window.FindName("NoticeDenyBtn")
$RainBtn        = $window.FindName("RainBtn")
$UpdateBtn      = $window.FindName("UpdateBtn")
$DownloadPanel  = $window.FindName("DownloadPanel")
$DlList         = $window.FindName("DlList")
$DlCount        = $window.FindName("DlCount")

# ---- download shelf: shared registry + ONE UI polling timer ----
# Download threads only write plain data into $DlRows (synchronized list; no UI marshalling).
# A single Background-priority DispatcherTimer on the UI thread syncs text/progress and removes
# finished rows. Marshalling a PowerShell [Action] across runspaces via $dispatcher.Invoke per
# progress update costs the UI thread ~50ms each, which starved the render/input pipeline and
# froze animations + controls. Writing data + one cheap timer tick avoids that entirely.
$script:DlRows = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$script:DlTimer = New-Object System.Windows.Threading.DispatcherTimer([System.Windows.Threading.DispatcherPriority]::Background)
$script:DlTimer.Interval = [TimeSpan]::FromMilliseconds(120)
$script:DlTimer.Add_Tick({
    $rows = $script:DlRows
    if ($rows.Count -eq 0) {
        if ($DownloadPanel.Visibility -ne "Collapsed") { $DownloadPanel.Visibility = "Collapsed" }
        if ($DlCount.Text -ne "") { $DlCount.Text = "" }
        return
    }
    for ($i = $rows.Count - 1; $i -ge 0; $i--) {
        $r = $rows[$i]
        if ($r.RemoveMe) {
            if ($r.Card -and $DlList.Children.Contains($r.Card)) { [void]$DlList.Children.Remove($r.Card) }
            $rows.RemoveAt($i)
            continue
        }
        # sync UI from data (only write when the value actually changed -> no render churn)
        $p = "$($r.Pct)%"
        if ($r.PctTb.Text -ne $p) { $r.PctTb.Text = $p }
        $sx = [double]$r.Pct / 100.0
        if ($r.Fill.RenderTransform.ScaleX -ne $sx) { $r.Fill.RenderTransform.ScaleX = $sx }
        if ($r.Total -gt 0) { $sz = ("{0:N1} MB / {1:N1} MB" -f ($r.Got/1MB),($r.Total/1MB)) }
        elseif ($r.Got -gt 0) { $sz = ("{0:N1} MB" -f ($r.Got/1MB)) }
        else { $sz = "" }
        if ($r.SizeTb.Text -ne $sz) { $r.SizeTb.Text = $sz }
        $st = [string]$r.StateText
        if ($r.StateTb.Text -ne $st) { $r.StateTb.Text = $st }
    }
    $DownloadPanel.Visibility = "Visible"
    $DlCount.Text = "$($rows.Count) active"
})
$script:DlTimer.Start()

# factory helper: builds a rounded plate button with hover/press triggers
function New-PlateButton {
    param($btn, [string]$bg, [string]$hover, [string]$press, [string]$border, [string]$name)
    if (-not $btn) { return }
    $bf = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
    $bf.Name = $name
    $bf.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($bg)))
    $bf.SetValue([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($border)))
    $bf.SetValue([System.Windows.Controls.Border]::BorderThicknessProperty, [System.Windows.Thickness]::new(1))
    $bf.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(8))
    $cp = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.ContentPresenter])
    $cp.SetValue([System.Windows.Controls.ContentPresenter]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
    $cp.SetValue([System.Windows.Controls.ContentPresenter]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
    $bf.AppendChild($cp)
    $tpl = [System.Windows.Controls.ControlTemplate]::new([System.Windows.Controls.Button])
    $tpl.VisualTree = $bf
    $hov = New-Object System.Windows.Trigger
    $hov.Property = [System.Windows.Controls.Control]::IsMouseOverProperty
    $hov.Value = $true
    $hov.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Border]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($hover)), $name)))
    $tpl.Triggers.Add($hov)
    $prs = New-Object System.Windows.Trigger
    $prs.Property = [System.Windows.Controls.Primitives.ButtonBase]::IsPressedProperty
    $prs.Value = $true
    $prs.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Border]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($press)), $name)))
    $tpl.Triggers.Add($prs)
    $btn.Template = $tpl
}

# Continue = red accent plate (launches the tool); Deny = dark plate (cancels)
New-PlateButton -btn $NoticeContinueBtn -bg "#2E2E2E" -hover "#4A4A4A" -press "#1A1A1A" -border "#2E2E2E" -name "ContBorder"
New-PlateButton -btn $NoticeDenyBtn     -bg "#D8D8D8" -hover "#9A9A9A" -press "#C2C2C2" -border "#888888" -name "DenyBorder"
if ($NoticeContinueBtn) { $NoticeContinueBtn.Add_Click({ Close-NoticeOverlay -Acknowledge }) }
if ($NoticeDenyBtn)     { $NoticeDenyBtn.Add_Click({ Close-NoticeOverlay }) }

# Close the notice overlay. With -Acknowledge ("Got it") any tool the user
# clicked earlier is launched; otherwise (X / Esc / backdrop) it is cancelled
# and the card button is re-enabled so nothing fires behind the user's back.
$script:pendingLaunchTimer = $null
function Close-NoticeOverlay {
    param([switch]$Acknowledge)
    if ($NoticeOverlay) { $NoticeOverlay.Visibility = "Collapsed" }
    $pending = $script:pendingLaunchTimer
    $script:pendingLaunchTimer = $null
    if ($Acknowledge -and $pending) {
        $pending.Start()
    } elseif ($pending -and $script:timerBtn) {
        $script:timerBtn.IsEnabled = $true
    }
}

# ---- animated background: red digital rain (matrix-style) on RainCanvas ----
# Perf note: each column is rendered ONCE into a bitmap and then only translated.
# Animating a TextBlock's position forces glyph re-rasterization every frame,
# and the old glyph-shuffling timer re-laid-out text constantly -> UI stutter.
$RainCanvas = $window.FindName("RainCanvas")
if ($RainCanvas) {
    $window.UseLayoutRounding = $true
    $rainChars = "013456789ABCDEF#$%&*+=<>/ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿ0101"
    $rng = [System.Random]::new()
    $rainTypeface = [System.Windows.Media.Typeface]::new([System.Windows.Media.FontFamily]::new("Segoe UI"), [System.Windows.FontStyles]::Normal, [System.Windows.FontWeights]::Normal, [System.Windows.FontStretches]::Normal)
    for ($ci = 0; $ci -lt 42; $ci++) {
        $len = $rng.Next(16, 32)
        $sb = [System.Text.StringBuilder]::new()
        for ($k = 0; $k -lt $len; $k++) { if ($k -gt 0) { [void]$sb.Append([char]10) }; [void]$sb.Append($rainChars[$rng.Next($rainChars.Length)]) }

        # measure the column once, then draw it into a small bitmap
        # trail: transparent above, dim red mid, bright head + white spark at the bottom (leading edge)
        $brush = New-Object System.Windows.Media.LinearGradientBrush
        $brush.MappingMode = [System.Windows.Media.BrushMappingMode]::Absolute
        $brush.StartPoint = [System.Windows.Point]::new(0, 0)
        $brush.EndPoint   = [System.Windows.Point]::new(0, ([double]$len * 17.5) + 4)
        [void]$brush.GradientStops.Add((New-Object System.Windows.Media.GradientStop(([System.Windows.Media.Color]$([System.Windows.Media.ColorConverter]::ConvertFromString("#002E2E2E"))), 0)))
        [void]$brush.GradientStops.Add((New-Object System.Windows.Media.GradientStop(([System.Windows.Media.Color]$([System.Windows.Media.ColorConverter]::ConvertFromString("#402E2E2E"))), 0.35)))
        [void]$brush.GradientStops.Add((New-Object System.Windows.Media.GradientStop(([System.Windows.Media.Color]$([System.Windows.Media.ColorConverter]::ConvertFromString("#B32E2E2E"))), 0.85)))
        [void]$brush.GradientStops.Add((New-Object System.Windows.Media.GradientStop(([System.Windows.Media.Color]$([System.Windows.Media.ColorConverter]::ConvertFromString("#FF1A1A1A"))), 1)))
        $ft = [System.Windows.Media.FormattedText]::new($sb.ToString(), [System.Globalization.CultureInfo]::InvariantCulture, [System.Windows.FlowDirection]::LeftToRight, $rainTypeface, 13.0, $brush)
        $colW = [int][Math]::Ceiling($ft.Width) + 4
        $colH = [int][Math]::Ceiling($ft.Height) + 4

        $dv = [System.Windows.Media.DrawingVisual]::new()
        $dc = $dv.RenderOpen()
        $dc.DrawText($ft, [System.Windows.Point]::new(2, 2))
        $dc.Close()
        $rtb = [System.Windows.Media.Imaging.RenderTargetBitmap]::new($colW, $colH, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
        $rtb.Render($dv)

        $img = [System.Windows.Controls.Image]::new()
        $img.Source = $rtb
        $img.Opacity = 0.55 + ($rng.NextDouble() * 0.4)
        [System.Windows.Controls.Canvas]::SetLeft($img, ($ci * 28) + $rng.Next(-6, 7))
        # spread initial positions across the screen so the rain is visible right away
        $startY = $rng.Next(-$colH, 500)
        [System.Windows.Controls.Canvas]::SetTop($img, $startY)
        $anim = New-Object System.Windows.Media.Animation.DoubleAnimation
        $anim.From = $startY
        $anim.To = 830
        $dist = 830.0 - $startY
        $speed = 55.0 + ($rng.NextDouble() * 75.0)   # px per second
        $anim.Duration = [System.Windows.Duration]::new([TimeSpan]::FromSeconds($dist / $speed))
        $anim.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
        [void]$RainCanvas.Children.Add($img)
        $img.BeginAnimation([System.Windows.Controls.Canvas]::TopProperty, $anim)

        # shimmer: cheap opacity pulse (compositor-level, no re-rasterization)
        $op = New-Object System.Windows.Media.Animation.DoubleAnimation
        $op.From = $img.Opacity
        $op.To = [Math]::Max(0.25, $img.Opacity - 0.28)
        $op.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(500 + $rng.Next(900)))
        $op.AutoReverse = $true
        $op.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
        $op.BeginTime = [TimeSpan]::FromMilliseconds($rng.Next(0, 2000))
        $img.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $op)
    }
}

# notification bell: opens the in-window disclaimer overlay; red dot hides once read
if ($NoticeBtn) {
    $NoticeBtn.ToolTip = "Notice - read before using"
    $NoticeBtn.Add_Click({
        $NoticeOverlay.Visibility = "Visible"
        if ($NoticeDot) { $NoticeDot.Visibility = "Collapsed" }
        $null = $NoticeOverlay.Focus()
    })
}
if ($NoticeOverlayDim) { $NoticeOverlayDim.Add_MouseLeftButtonDown({ Close-NoticeOverlay }) }
if ($NoticeCloseBtn)   { $NoticeCloseBtn.Add_Click({ Close-NoticeOverlay }) }
if ($NoticeOverlay) {
    $NoticeOverlay.Add_KeyDown({
        if ($_.Key -eq "Escape") { Close-NoticeOverlay; $_.Handled = $true }
    })
}

if ($InstPathText) { $InstPathText.Text = $installDir }

# ---- rain background toggle (performance / accessibility) ----
$script:rainOn = $true
if ($RainBtn) {
    $RainBtn.ToolTip = "Toggle background animation"
    $RainBtn.Add_Click({
        $script:rainOn = -not $script:rainOn
        if ($RainCanvas) {
            if ($script:rainOn) {
                $RainCanvas.Visibility = "Visible"
                $RainBtn.Content = [string][System.Char]::ConvertFromUtf32(0xE769)  # pause
                Write-Log "Background animation ON."
            } else {
                $RainCanvas.Visibility = "Collapsed"
                $RainBtn.Content = [string][System.Char]::ConvertFromUtf32(0xE768)  # play
                Write-Log "Background animation OFF (performance)."
            }
        }
    })
}

# ---- check for updates: compare local script to GitHub raw copy ----
if ($UpdateBtn) {
    $UpdateBtn.ToolTip = "Compare this script with the copy on GitHub"
    $UpdateBtn.Add_Click({
        $UpdateBtn.IsEnabled = $false
        Write-Log "Checking for updates on GitHub..."
        Set-Status "Update" "Checking GitHub for a newer version..." "BUSY"
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = "STA"; $rs.ThreadOptions = "ReuseThread"; $rs.Open()
        $rs.SessionStateProxy.SetVariable("dispatcher", $window.Dispatcher)
        $rs.SessionStateProxy.SetVariable("localPath", $PSCommandPath)
        $rs.SessionStateProxy.SetVariable("LogBox", $LogBox)
        $rs.SessionStateProxy.SetVariable("StatusTitle", $StatusTitle)
        $rs.SessionStateProxy.SetVariable("StatusSub", $StatusSub)
        $rs.SessionStateProxy.SetVariable("StatusBadge", $StatusBadge)
        $rs.SessionStateProxy.SetVariable("UpdateBtn", $UpdateBtn)
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        $null = $ps.AddScript({
            function Lg { param($m) $dispatcher.Invoke([Action]{ $LogBox.AppendText("[$(Get-Date -f 'HH:mm:ss')] $m`n"); $LogBox.ScrollToEnd() }) }
            function St { param($t,$s,$b) $dispatcher.Invoke([Action]{ $StatusTitle.Text=$t; $StatusSub.Text=$s; $StatusBadge.Text=$b }) }
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $remoteUrl = "https://raw.githubusercontent.com/Va2lyR/ValyaRFuckHim/main/ValyaRFuckHim.ps1"
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("User-Agent","ValyaRFuckHim")
                $remoteText = $wc.DownloadString($remoteUrl)
                if (-not $localPath -or -not (Test-Path -LiteralPath $localPath)) { throw "Local script path unknown." }
                $localText = [System.IO.File]::ReadAllText($localPath)
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $lh = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($localText)) | ForEach-Object { $_.ToString("x2") }) -join ""
                $rh = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($remoteText)) | ForEach-Object { $_.ToString("x2") }) -join ""
                if ($lh -eq $rh) {
                    Lg "You are up to date - local matches GitHub."
                    St "Up to date" "No newer version found on GitHub." "IDLE"
                } else {
                    Lg "Update available - GitHub has a different version."
                    St "Update found" "Opening GitHub repository..." "IDLE"
                    Start-Process "https://github.com/Va2lyR/ValyaRFuckHim"
                }
            } catch {
                Lg "Update check failed: $($_.Exception.Message)"
                St "Update" "Could not check for updates." "ERR"
            }
            $dispatcher.Invoke([Action]{ $UpdateBtn.IsEnabled = $true })
            $rs.Close()
        })
        $null = $ps.BeginInvoke()
    })
}

# Search placeholder
$script:searchHint = "Search tools..."
$SearchBox.Text = $script:searchHint
$SearchBox.Foreground = "#888888"
$SearchBox.Add_GotFocus({
    if ($SearchBox.Text -eq $script:searchHint) {
        $SearchBox.Text = ""
        $SearchBox.Foreground = "#3A3A3A"
    }
})
$SearchBox.Add_LostFocus({
    if ([string]::IsNullOrWhiteSpace($SearchBox.Text)) {
        $SearchBox.Text = $script:searchHint
        $SearchBox.Foreground = "#888888"
    }
})

# ---- in-window overlay (source-check dialog host) ----
$LinkOverlay    = $window.FindName("LinkOverlay")
$LinkOverlayDim = $window.FindName("LinkOverlayDim")
$LinkOverlayHost = $window.FindName("LinkOverlayHost")
$LinkOverlayDim.Add_MouseLeftButtonDown({ $LinkOverlay.Visibility = "Collapsed" })
$LinkOverlay.Add_KeyDown({
    if ($_.Key -eq "Escape") { $LinkOverlay.Visibility = "Collapsed"; $_.Handled = $true }
})

# Load logo image - GitHub SS.jpg is the primary source, local logo.jpg is fallback
$logoLoaded = $false
try {
    $logoUrl = "https://github.com/Va2lyR/ValyaRFuckHim/blob/main/SS.jpg?raw=true"
    $tempLogo = "$env:TEMP\vrfh_logo_ss.jpg"
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
        $logoLoaded = $true
    }
} catch {}
if (-not $logoLoaded) {
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


#endregion

#region HELPERS

# HELPERS

function Write-Log {
    param([string]$msg)
    $time = Get-Date -Format "HH:mm:ss"
    $LogBox.Dispatcher.Invoke([Action]{
        $LogBox.AppendText("[$time] $msg`r`n")
        # keep the log light: trim old lines so the box never slows the UI down
        try {
            if ($LogBox.LineCount -gt 300) {
                $cutIdx = $LogBox.GetCharacterIndexFromLineIndex($LogBox.LineCount - 250)
                $nl = $LogBox.Text.IndexOf("`r`n", $cutIdx)
                if ($nl -ge 0) { $LogBox.Text = $LogBox.Text.Substring($nl + 2) }
            }
        } catch {}
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

    $script:SrcWin = New-Object System.Windows.Window
    $srcWin = $script:SrcWin
    $srcWin.Title = "Source - $ToolName"
    $srcWin.Width = 800
    $srcWin.Height = 600
    $srcWin.WindowStartupLocation = "CenterScreen"
    $srcWin.ResizeMode = "CanResize"
    $srcWin.WindowStyle = "None"
    $srcWin.AllowsTransparency = $true
    $srcWin.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#C8C8C8"))
    $srcWin.FontFamily = [System.Windows.Media.FontFamily]::new("Segoe UI")

    $mainBorder = New-Object System.Windows.Controls.Border
    $mainBorder.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#C8C8C8"))
    $mainBorder.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#A0A0A0"))
    $mainBorder.BorderThickness = 1
    $mainBorder.CornerRadius = 12

    $rootGrid = New-Object System.Windows.Controls.Grid
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(42) }))
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(1) }))
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }))

    $header = New-Object System.Windows.Controls.Border
    $header.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#CACACA"))
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
    $titleIcon.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
    $titleIcon.Margin = "0,0,8,0"
    $titleIcon.VerticalAlignment = "Center"
    $titleText = New-Object System.Windows.Controls.TextBlock
    $titleText.Text = $ToolName
    $titleText.FontSize = 12
    $titleText.FontWeight = "SemiBold"
    $titleText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1F1F1F"))
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
    $closeBtn.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#6E6E6E"))
    $closeBtn.FontFamily = [System.Windows.Media.FontFamily]::new("Segoe MDL2 Assets")
    $closeBtn.FontSize = 10
    $closeBtn.Content = "X"
    $closeBtnTemplate = New-Object System.Windows.Controls.ControlTemplate([System.Windows.Controls.Button])
    $closeBtnBdrF = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
    $closeBtnBdrF.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.Brushes]::Transparent)
    $closeBtnBdrF.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(6))
    $closeBtnCPF = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.ContentPresenter])
    $closeBtnCPF.SetValue([System.Windows.Controls.ContentPresenter]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
    $closeBtnCPF.SetValue([System.Windows.Controls.ContentPresenter]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
    $closeBtnBdrF.AppendChild($closeBtnCPF)
    $closeBtnTemplate.VisualTree = $closeBtnBdrF
    $closeBtn.Template = $closeBtnTemplate
    $closeBtn.Add_Click({ $script:SrcWin.Close() })
    [System.Windows.Controls.Grid]::SetColumn($closeBtn, 1)
    $headerGrid.Children.Add($closeBtn) | Out-Null
    [System.Windows.Controls.Grid]::SetRow($header, 0)
    $header.Child = $headerGrid
    $rootGrid.Children.Add($header) | Out-Null

    $sep = New-Object System.Windows.Controls.Border
    $sep.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#A0A0A0"))
    [System.Windows.Controls.Grid]::SetRow($sep, 1)
    $rootGrid.Children.Add($sep) | Out-Null

    $contentArea = New-Object System.Windows.Controls.Grid
    $contentArea.Margin = "16,12"
    [System.Windows.Controls.Grid]::SetRow($contentArea, 2)

    $loadingText = New-Object System.Windows.Controls.TextBlock
    $loadingText.Text = "Loading source code..."
    $loadingText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#6E6E6E"))
    $loadingText.FontSize = 12
    $loadingText.HorizontalAlignment = "Center"
    $loadingText.VerticalAlignment = "Center"
    $contentArea.Children.Add($loadingText) | Out-Null

    $rootGrid.Children.Add($contentArea) | Out-Null
    $mainBorder.Child = $rootGrid
    $srcWin.Content = $mainBorder

    $srcWin.Add_MouseLeftButtonDown({ try { $script:SrcWin.DragMove() } catch {} })

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
    $urlBar.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#D2D2D2"))
    $urlBar.CornerRadius = 6
    $urlBar.Padding = "10,6"
    $urlBar.Margin = "0,0,0,10"

    $urlGrid = New-Object System.Windows.Controls.Grid
    $urlGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::Auto }))
    $urlGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }))

    $urlIcon = New-Object System.Windows.Controls.TextBlock
    $urlIcon.Text = "@"
    $urlIcon.FontSize = 11
    $urlIcon.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#6E6E6E"))
    $urlIcon.Margin = "0,0,8,0"
    $urlIcon.VerticalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($urlIcon, 0)
    $urlGrid.Children.Add($urlIcon) | Out-Null

    $urlText = New-Object System.Windows.Controls.TextBlock
    $urlText.Text = $srcUrl
    $urlText.FontSize = 11
    $urlText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
    $urlText.TextTrimming = "CharacterEllipsis"
    $urlText.VerticalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($urlText, 1)
    $urlGrid.Children.Add($urlText) | Out-Null

    $urlBar.Child = $urlGrid
    $contentArea.Children.Add($urlBar) | Out-Null

    $codeBox = New-Object System.Windows.Controls.TextBox
    $codeBox.Style = $window.FindResource("AppTextBox")
    $codeBox.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#CACACA"))
    $codeBox.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
    $codeBox.FontFamily = [System.Windows.Media.FontFamily]::new("Consolas")
    $codeBox.FontSize = 11
    $codeBox.TextWrapping = "NoWrap"
    $codeBox.AcceptsReturn = $true
    $codeBox.AcceptsTab = $true
    $codeBox.IsReadOnly = $true
    $codeBox.Text = $srcCode
    $codeBox.BorderThickness = 1
    $codeBox.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#A0A0A0"))
    $codeBox.VerticalScrollBarVisibility = "Auto"
    $codeBox.HorizontalScrollBarVisibility = "Auto"
    $codeBox.Padding = "12,8"
    $codeBox.CaretBrush = "Transparent"
    $contentArea.Children.Add($codeBox) | Out-Null

    $mainBorder.ClipToBounds = $true
}


# ---- Source verification helpers ("!" button on every card) ----
# Cache of resolved GitHub asset URLs (populated lazily, saved to disk)

$script:urlCachePath = Join-Path $installDir "_urlcache.json"
$script:urlCache = @{}
if (Test-Path -LiteralPath $script:urlCachePath) {
    try {
        $obj = Get-Content -Raw -LiteralPath $script:urlCachePath | ConvertFrom-Json
        foreach ($p in $obj.PSObject.Properties) { $script:urlCache[[string]$p.Name] = [string]$p.Value }
        Write-Log "URL cache loaded: $($script:urlCache.Count) entries"
    } catch { Write-Log "URL cache load failed: $($_.Exception.Message)" }
}

function Save-UrlCache {
    try {
        if (-not (Test-Path -LiteralPath $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }
        ($script:urlCache | ConvertTo-Json) | Set-Content -LiteralPath $script:urlCachePath -Encoding UTF8
    } catch { Write-Log "URL cache save failed: $($_.Exception.Message)" }
}

# ---- click-to-copy on a read-only link box (green border flash as feedback) ----
$script:flashBox = $null
$script:flashOrig = $null
$script:flashTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:flashTimer.Interval = [TimeSpan]::FromMilliseconds(1200)
$script:flashTimer.Add_Tick({
    if ($script:flashBox) {
        $script:flashBox.BorderBrush = $script:flashOrig
        $script:flashBox = $null
    }
    $script:flashTimer.Stop()
})

function Copy-BoxLink {
    param($box, [string]$what)
    if (-not $box) { return }
    if ($box.SelectionLength -gt 0) { return }  # user is dragging a selection: don't fight them
    $txt = [string]$box.Text
    if (-not $txt -or $txt -notmatch '^https?://') { return }
    try {
        [System.Windows.Clipboard]::SetText($txt)
        $script:flashOrig = $box.BorderBrush
        $script:flashBox = $box
        $box.BorderBrush = [System.Windows.Media.Brushes]::ForestGreen
        $script:flashTimer.Stop()
        $script:flashTimer.Start()
        Write-Log "$what copied to clipboard"
    } catch { Write-Log "Copy failed: $($_.Exception.Message)" }
}

# "Copied!" label reset for the popup's Copy file link button
$script:DlgCopyTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:DlgCopyTimer.Interval = [TimeSpan]::FromMilliseconds(1500)
$script:DlgCopyTimer.Add_Tick({
    if ($script:DlgCopyBtn) { $script:DlgCopyBtn.Content = $script:DlgCopyLabel }
    $script:DlgCopyTimer.Stop()
})

# what file type this tool will download/launch
function Get-FileExtLabel {
    param($t)
    switch ([string]$t.Type) {
        "Cmd"    { return "ps1" }
        "GitHub" { return "exe/zip" }
        "Link"   { return "page" }
        default  {
            $url = [string]$t.URL
            if ($url -match '\.([A-Za-z0-9]{1,6})(\?|#|$)') { return $Matches[1].ToLower() }
            return "file"
        }
    }
}

# the site the file is downloaded from, e.g. https://github.com/
function Get-ToolSourceUrl {
    param($t)
    $link = ""
    if ($t.URL) { $link = [string]$t.URL }
    elseif ($t.Command) {
        $m = [regex]::Match([string]$t.Command, 'https?://[^\s''"]+')
        if ($m.Success) { $link = $m.Value }
    }
    if (-not $link) { return "" }
    try { return ([Uri]$link).GetLeftPart([UriPartial]::Authority) + "/" } catch { return $link }
}

# the full file URL that will be downloaded (GitHub repos are resolved via API/cache)
function Get-ToolFileUrl {
    param($t)
    switch ([string]$t.Type) {
        "GitHub" {
            $key = ([string]$t.URL).TrimEnd('/')
            if ($script:urlCache.ContainsKey($key)) { return [string]$script:urlCache[$key] }
            if ($key.EndsWith("/releases/latest")) { return $key }
            return "$key/releases/latest"
        }
        "Cmd" {
            $m = [regex]::Match([string]$t.Command, 'https?://[^\s''"]+')
            if ($m.Success) { return $m.Value }
            return ""
        }
        default { return ([string]$t.URL).TrimEnd('/') }
    }
}

function Show-ToolLinks {
    param($t)

    $mainBorder = New-Object System.Windows.Controls.Border
    $mainBorder.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#C8C8C8"))
    $mainBorder.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#A0A0A0"))
    $mainBorder.BorderThickness = 1
    $mainBorder.CornerRadius = 12
    $mainBorder.Width = 660
    $shadow = New-Object System.Windows.Media.Effects.DropShadowEffect
    $shadow.BlurRadius = 24
    $shadow.ShadowDepth = 8
    $shadow.Opacity = 0.6
    $shadow.Color = [System.Windows.Media.Color]::FromRgb(0, 0, 0)
    $mainBorder.Effect = $shadow

    $rootGrid = New-Object System.Windows.Controls.Grid
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(42) }))
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(1) }))
    $rootGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }))

    # header: icon badge + tool name + close
    $header = New-Object System.Windows.Controls.Border
    $header.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#CACACA"))
    $headerGrid = New-Object System.Windows.Controls.Grid
    $headerGrid.Margin = "16,0"
    $headerGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star) }))
    $headerGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Auto) }))

    $titlePanel = New-Object System.Windows.Controls.StackPanel
    $titlePanel.Orientation = "Horizontal"
    $titlePanel.VerticalAlignment = "Center"
    $titleIconBadge = New-Object System.Windows.Controls.Border
    $titleIconBadge.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#D0D0D0"))
    $titleIconBadge.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#CCCCCC"))
    $titleIconBadge.BorderThickness = [System.Windows.Thickness]::new(1)
    $titleIconBadge.CornerRadius = [System.Windows.CornerRadius]::new(9)
    $titleIconBadge.Width = 18
    $titleIconBadge.Height = 18
    $titleIconBadge.Margin = "0,0,9,0"
    $titleIconBadge.VerticalAlignment = "Center"
    $titleIcon = New-Object System.Windows.Controls.TextBlock
    $titleIcon.Text = "!"
    $titleIcon.FontSize = 11
    $titleIcon.FontWeight = "Bold"
    $titleIcon.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
    $titleIcon.HorizontalAlignment = "Center"
    $titleIcon.VerticalAlignment = "Center"
    $titleIconBadge.Child = $titleIcon
    $titleText = New-Object System.Windows.Controls.TextBlock
    $titleText.Text = $t.Name
    $titleText.FontSize = 12
    $titleText.FontWeight = "SemiBold"
    $titleText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1F1F1F"))
    $titleText.VerticalAlignment = "Center"
    $titleText.TextTrimming = "CharacterEllipsis"
    $titlePanel.Children.Add($titleIconBadge) | Out-Null
    $titlePanel.Children.Add($titleText) | Out-Null
    [System.Windows.Controls.Grid]::SetColumn($titlePanel, 0)
    $headerGrid.Children.Add($titlePanel) | Out-Null

    $closeBtn = New-Object System.Windows.Controls.Button
    $closeBtn.Width = 36
    $closeBtn.Height = 28
    $closeBtn.Cursor = "Hand"
    $closeBtn.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#6E6E6E"))
    $closeBtn.FontSize = 10
    $closeBtn.Content = "X"
    $closeBtnTemplate = New-Object System.Windows.Controls.ControlTemplate([System.Windows.Controls.Button])
    $closeBtnBdrF = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
    $closeBtnBdrF.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.Brushes]::Transparent)
    $closeBtnBdrF.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(6))
    $closeBtnCPF = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.ContentPresenter])
    $closeBtnCPF.SetValue([System.Windows.Controls.ContentPresenter]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
    $closeBtnCPF.SetValue([System.Windows.Controls.ContentPresenter]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
    $closeBtnBdrF.AppendChild($closeBtnCPF)
    $closeBtnTemplate.VisualTree = $closeBtnBdrF
    $closeBtn.Template = $closeBtnTemplate
    $closeBtn.Add_Click({ $LinkOverlay.Visibility = "Collapsed" })
    [System.Windows.Controls.Grid]::SetColumn($closeBtn, 1)
    $headerGrid.Children.Add($closeBtn) | Out-Null
    [System.Windows.Controls.Grid]::SetRow($header, 0)
    $header.Child = $headerGrid
    $rootGrid.Children.Add($header) | Out-Null

    $sep = New-Object System.Windows.Controls.Border
    $sep.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#A0A0A0"))
    [System.Windows.Controls.Grid]::SetRow($sep, 1)
    $rootGrid.Children.Add($sep) | Out-Null

    # body
    $body = New-Object System.Windows.Controls.StackPanel
    $body.Margin = "16,12"
    [System.Windows.Controls.Grid]::SetRow($body, 2)

    $mkLabel = {
        param([string]$txt)
        $l = New-Object System.Windows.Controls.TextBlock
        $l.Text = $txt
        $l.FontSize = 9
        $l.FontFamily = [System.Windows.Media.FontFamily]::new("Consolas")
        $l.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#6E6E6E"))
        $l.Margin = "0,0,0,4"
        return $l
    }

    $mkBox = {
        param([bool]$wrap, [double]$h)
        $tb = New-Object System.Windows.Controls.TextBox
        $tb.Style = $window.FindResource("AppTextBox")
        $tb.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#CACACA"))
        $tb.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
        $tb.FontFamily = [System.Windows.Media.FontFamily]::new("Consolas")
        $tb.FontSize = 11
        $tb.IsReadOnly = $true
        $tb.IsReadOnlyCaretVisible = $false
        $tb.Cursor = "Hand"
        $tb.ToolTip = "Click to copy"
        $tb.BorderThickness = 1
        $tb.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#A0A0A0"))
        $tb.Padding = "10,6"
        $tb.CaretBrush = [System.Windows.Media.Brushes]::Transparent
        $tb.VerticalScrollBarVisibility = "Auto"
        if ($wrap) {
            $tb.TextWrapping = "Wrap"
            $tb.Height = $h
            $tb.HorizontalScrollBarVisibility = "Disabled"
        } else {
            $tb.TextWrapping = "NoWrap"
            $tb.HorizontalAlignment = "Stretch"
            $tb.HorizontalScrollBarVisibility = "Auto"
        }
        return $tb
    }

    $srcLabel = & $mkLabel "SOURCE SITE (where the file is downloaded from) - click the box to copy"
    $body.Children.Add($srcLabel) | Out-Null
    $srcBox = & $mkBox $false 0
    $script:DlgSrcBox = $srcBox
    $body.Children.Add($srcBox) | Out-Null

    $fileLabel = & $mkLabel "FILE LINK (the exact file that will be downloaded) - click the box to copy"
    $fileLabel.Margin = "0,12,0,4"
    $body.Children.Add($fileLabel) | Out-Null
    $fileBox = & $mkBox $true 62
    $script:DlgFileBox = $fileBox
    $body.Children.Add($fileBox) | Out-Null

    # click a link box (without dragging a selection) to copy its URL
    $srcBox.Add_MouseLeftButtonUp({ Copy-BoxLink -box $script:DlgSrcBox -what "Source site" })
    $fileBox.Add_MouseLeftButtonUp({ Copy-BoxLink -box $script:DlgFileBox -what "File link" })

    # button factory: flat dark plate with hover + per-button accent border
    $mkBtn = {
        param([string]$txt, [string]$fg, [string]$hoverBg)
        $b = New-Object System.Windows.Controls.Button
        $b.Content = $txt
        $b.Height = 30
        $b.Padding = "14,0"
        $b.Margin = "0,0,8,0"
        $b.Cursor = "Hand"
        $b.FontSize = 11
        $b.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($fg))
        $bf = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
        $bf.Name = "BtnBorder"
        $bf.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#D2D2D2")))
        $bf.SetValue([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#969696")))
        $bf.SetValue([System.Windows.Controls.Border]::BorderThicknessProperty, [System.Windows.Thickness]::new(1))
        $bf.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(6))
        $cp = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.ContentPresenter])
        $cp.SetValue([System.Windows.Controls.ContentPresenter]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
        $cp.SetValue([System.Windows.Controls.ContentPresenter]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
        $cp.SetValue([System.Windows.Controls.ContentPresenter]::MarginProperty, [System.Windows.Thickness]::new(14,0,14,0))
        $bf.AppendChild($cp)
        $tpl = [System.Windows.Controls.ControlTemplate]::new([System.Windows.Controls.Button])
        $tpl.VisualTree = $bf
        $hovTrg = New-Object System.Windows.Trigger
        $hovTrg.Property = [System.Windows.Controls.Control]::IsMouseOverProperty
        $hovTrg.Value = $true
        $hovTrg.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Border]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($hoverBg)), "BtnBorder")))
        $hovTrg.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($fg)), "BtnBorder")))
        $tpl.Triggers.Add($hovTrg)
        $prsTrg = New-Object System.Windows.Trigger
        $prsTrg.Property = [System.Windows.Controls.Primitives.ButtonBase]::IsPressedProperty
        $prsTrg.Value = $true
        $prsTrg.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Border]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#C8C8C8")), "BtnBorder")))
        $tpl.Triggers.Add($prsTrg)
        $b.Template = $tpl
        return $b
    }

    $btnRow = New-Object System.Windows.Controls.StackPanel
    $btnRow.Orientation = "Horizontal"
    $btnRow.Margin = "0,14,0,0"
    $openSrcBtn = & $mkBtn "Open site" "#555555" "#C8D0D8"
    $openFileBtn = & $mkBtn "Open file link" "#3A3A3A" "#C8D0C8"
    $copyBtn = & $mkBtn "Copy file link" "#444444" "#A0A0A0"
    $vtBtn = & $mkBtn "VirusTotal" "#6A6A6A" "#DADADA"
    $btnRow.Children.Add($openSrcBtn) | Out-Null
    $btnRow.Children.Add($openFileBtn) | Out-Null
    $btnRow.Children.Add($copyBtn) | Out-Null
    $btnRow.Children.Add($vtBtn) | Out-Null
    $body.Children.Add($btnRow) | Out-Null

    $mainBorder.Child = $rootGrid
    $rootGrid.Children.Add($body) | Out-Null
    $LinkOverlayHost.Content = $mainBorder

    # ---- fill values ----
    $srcUrl = Get-ToolSourceUrl $t
    $fileUrl = Get-ToolFileUrl $t
    if (-not $srcUrl) {
        $srcUrl = "(built-in PowerShell command - nothing is downloaded)"
        $openSrcBtn.IsEnabled = $false
    }
    $srcBox.Text = $srcUrl
    $script:DlgSrcUrl = $srcUrl

    if ($t.Type -eq "Cmd" -and -not $fileUrl) {
        $fileBox.Text = [string]$t.Command
        $openFileBtn.IsEnabled = $false
        $copyBtn.IsEnabled = $false
        $vtBtn.IsEnabled = $false
    } else {
        $fileBox.Text = $fileUrl
    }
    $script:DlgFileUrl = $fileBox.Text

    $script:DlgOpenSrcBtn = $openSrcBtn
    $script:DlgOpenFileBtn = $openFileBtn
    $script:DlgCopyBtn = $copyBtn
    $script:DlgCopyLabel = "Copy file link"

    $openSrcBtn.Add_Click({
        if ($script:DlgSrcUrl -match '^https?://') { try { Start-Process $script:DlgSrcUrl } catch { Write-Log "Open failed: $($_.Exception.Message)" } }
    })
    $openFileBtn.Add_Click({
        if ($script:DlgFileUrl -match '^https?://') { try { Start-Process $script:DlgFileUrl } catch { Write-Log "Open failed: $($_.Exception.Message)" } }
    })
    $copyBtn.Add_Click({
        try {
            [System.Windows.Clipboard]::SetText($script:DlgFileUrl)
            $script:DlgCopyBtn.Content = "Copied!"
            $script:DlgCopyTimer.Stop()
            $script:DlgCopyTimer.Start()
            Write-Log "File link copied to clipboard"
        } catch { Write-Log "Copy failed: $($_.Exception.Message)" }
    })
    # VirusTotal: open the URL scanner page in the default browser
    $vtBtn.Add_Click({
        try { Start-Process "https://www.virustotal.com/gui/home/url" } catch { Write-Log "VirusTotal open failed: $($_.Exception.Message)" }
    })

    $LinkOverlay.Visibility = "Visible"
    $null = $LinkOverlay.Focus()

    # GitHub repos: resolve the exact asset URL in the background (once, then cached)
    $repoKey = ([string]$t.URL).TrimEnd('/')
    if ($t.Type -eq "GitHub" -and -not $script:urlCache.ContainsKey($repoKey)) {
        # a previous resolve may still be ticking: stop it so it can't write into this dialog
        if ($script:ResolveTimer -and $script:ResolveTimer.IsEnabled) { $script:ResolveTimer.Stop() }
        $fileBox.Text = "(resolving the exact file link via GitHub API...)"
        $openFileBtn.IsEnabled = $false
        $repoUrl = $repoKey

        $rs = [runspacefactory]::CreateRunspace()
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        $null = $ps.AddScript({
            param($repoUrl)
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            if ($repoUrl -match 'github\.com/([^/]+)/([^/]+)') {
                $api = "https://api.github.com/repos/$($Matches[1])/$($Matches[2])/releases/latest"
                try {
                    $rel = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "ValyaRFuckHim" } -TimeoutSec 10
                    $asset = $rel.assets | Where-Object { $_.name -match '\.(zip|exe)$' } | Select-Object -First 1
                    if ($asset) { return [string]$asset.browser_download_url }
                } catch { }
            }
            return $null
        }).AddArgument($repoUrl)
        $handle = $ps.BeginInvoke()

        # (script-scope state so the timer handler can see it after this function returns)
        $script:ResolveTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:ResolveTimer.Interval = [TimeSpan]::FromMilliseconds(400)
        $script:ResolveHandle = $handle
        $script:ResolvePs = $ps
        $script:ResolveRs = $rs
        $script:ResolveKey = $repoKey
        $script:ResolveTimer.Add_Tick({
            if (-not $script:ResolveHandle.IsCompleted) { return }
            $script:ResolveTimer.Stop()
            $assetUrl = ""
            try {
                foreach ($r in $script:ResolvePs.EndInvoke($script:ResolveHandle)) { if ($r) { $assetUrl = [string]$r; break } }
            } catch { Write-Log "URL resolve error: $($_.Exception.Message)" }
            try { $script:ResolvePs.Dispose() } catch {}
            try { $script:ResolveRs.Close(); $script:ResolveRs.Dispose() } catch {}
            if (-not $assetUrl) { $assetUrl = "$($script:ResolveKey)/releases/latest" }
            $script:urlCache[$script:ResolveKey] = $assetUrl
            Save-UrlCache
            Write-Log "Resolved file URL: $assetUrl"
            if ($script:DlgFileBox) {
                $script:DlgFileBox.Text = $assetUrl
                $script:DlgFileUrl = $assetUrl
                try { $script:DlgFileBox.ScrollToHome() } catch {}
                $script:DlgOpenFileBtn.IsEnabled = $true
            }
        })
        $script:ResolveTimer.Start()
    }
}

#endregion

#region TOOL CARDS

# TABS

$AllCategories = @("ValyaR","Tonynoh","Spokwn","TeslaPro","RedLotus","Zimmerman","Orbdiff","DetectAC","NirSoft","Echo","System","Scripts","Tools")

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
        $btn.Width = 196; $btn.Height = 120; $btn.FontSize = 12; $btn.Margin = "6"; $btn.Cursor = "Hand"; $btn.Foreground = "#2E2E2E"

        $btnStack = New-Object System.Windows.Controls.StackPanel
        $btnStack.Margin = "14,10"

        # row 1: type label + file-extension badge
        $typeRow = New-Object System.Windows.Controls.StackPanel
        $typeRow.Orientation = "Horizontal"
        $typeRow.Margin = "0,0,0,4"
        $typeBlock = New-Object System.Windows.Controls.TextBlock
        $typeBlock.FontSize = 8; $typeBlock.FontFamily = "Consolas"; $typeBlock.VerticalAlignment = "Center"
        switch ($t.Type) {
            "Cmd"    { $typeBlock.Text = "SCRIPT";   $typeBlock.Foreground = "#2E2E2E" }
            "GitHub" { $typeBlock.Text = "DOWNLOAD"; $typeBlock.Foreground = "#3A3A3A" }
            "Web"    { $typeBlock.Text = "WEB FILE"; $typeBlock.Foreground = "#555555" }
            "Link"   { $typeBlock.Text = "LINK";     $typeBlock.Foreground = "#6A6A6A" }
            default  { $typeBlock.Text = $t.Type.ToUpper(); $typeBlock.Foreground = "#4E4E4E" }
        }
        $extColors = @{ "ps1" = "#2E2E2E"; "exe" = "#3A3A3A"; "zip" = "#555555"; "7z" = "#555555"; "msi" = "#6A6A6A"; "html" = "#6A6A6A"; "htm" = "#6A6A6A"; "exe/zip" = "#3A3A3A"; "page" = "#6A6A6A" }
        $extLabel = Get-FileExtLabel $t
        $extFg = "#555555"
        if ($extColors.ContainsKey($extLabel.ToLower())) { $extFg = $extColors[$extLabel.ToLower()] }
        $extBadge = New-Object System.Windows.Controls.Border
        $extBadge.CornerRadius = [System.Windows.CornerRadius]::new(3)
        $extBadge.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#B0B0B0"))
        $extBadge.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#969696"))
        $extBadge.BorderThickness = [System.Windows.Thickness]::new(1)
        $extBadge.Padding = [System.Windows.Thickness]::new(5,1,5,1)
        $extBadge.Margin = [System.Windows.Thickness]::new(6,0,0,0)
        $extBadge.VerticalAlignment = "Center"
        $extText = New-Object System.Windows.Controls.TextBlock
        $extText.Text = ".$extLabel"
        $extText.FontSize = 8
        $extText.FontFamily = "Consolas"
        $extText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($extFg))
        $extBadge.Child = $extText
        $typeRow.Children.Add($typeBlock) | Out-Null
        $typeRow.Children.Add($extBadge) | Out-Null

        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $t.Name; $nameBlock.FontSize = 12; $nameBlock.FontWeight = "SemiBold"; $nameBlock.TextWrapping = "Wrap"; $nameBlock.Foreground = "#1F1F1F"
        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $t.Desc; $descBlock.FontSize = 10; $descBlock.Opacity = 0.4; $descBlock.TextWrapping = "Wrap"; $descBlock.TextTrimming = "CharacterEllipsis"; $descBlock.MaxHeight = 36; $descBlock.Margin = "0,4,0,0"; $descBlock.Foreground = "#4A4A4A"

        # row 4: "!" button (source + file link verification)
        $infoRow = New-Object System.Windows.Controls.StackPanel
        $infoRow.Orientation = "Horizontal"
        $infoRow.HorizontalAlignment = "Right"
        $infoRow.Margin = "0,6,0,0"
        $markBtn = New-Object System.Windows.Controls.Button
        $markBtn.Width = 20; $markBtn.Height = 20
        $markBtn.Padding = "0"
        $markBtn.FontSize = 11; $markBtn.FontWeight = "Bold"
        $markBtn.Cursor = "Hand"
        $markBtn.Foreground = "#2E2E2E"
        $markBtn.VerticalContentAlignment = "Center"
        $markBtn.HorizontalAlignment = "Center"
        $markBtn.ToolTip = "Show source site + file download link"
        $markBtn.Tag = $t
        # centered "!" textblock (optically nudged up 1px for the glyph)
        $markTxt = New-Object System.Windows.Controls.TextBlock
        $markTxt.Text = "!"
        $markTxt.FontSize = 11
        $markTxt.FontWeight = "Bold"
        $markTxt.Foreground = "#2E2E2E"
        $markTxt.HorizontalAlignment = "Center"
        $markTxt.VerticalAlignment = "Center"
        $markTxt.Margin = "0,-1,0,0"
        $markBtn.Content = $markTxt
        $mBdr = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
        $mBdr.Name = "MarkBorder"
        $mBdr.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#D6D6D6")))
        $mBdr.SetValue([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#909090")))
        $mBdr.SetValue([System.Windows.Controls.Border]::BorderThicknessProperty, [System.Windows.Thickness]::new(1))
        $mBdr.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(10))
        $mBdr.SetValue([System.Windows.Controls.Border]::PaddingProperty, [System.Windows.Thickness]::new(0))
        $mCp = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.ContentPresenter])
        $mCp.SetValue([System.Windows.Controls.ContentPresenter]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
        $mCp.SetValue([System.Windows.Controls.ContentPresenter]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
        $mBdr.AppendChild($mCp)
        $mTpl = [System.Windows.Controls.ControlTemplate]::new([System.Windows.Controls.Button])
        $mTpl.VisualTree = $mBdr
        # hover: red-tinted border + background
        $mHov = New-Object System.Windows.Trigger
        $mHov.Property = [System.Windows.Controls.Control]::IsMouseOverProperty
        $mHov.Value = $true
        $mHov.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Border]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#D4D4D4")), "MarkBorder")))
        $mHov.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E")), "MarkBorder")))
        $mTpl.Triggers.Add($mHov)
        $mPrs = New-Object System.Windows.Trigger
        $mPrs.Property = [System.Windows.Controls.Primitives.ButtonBase]::IsPressedProperty
        $mPrs.Value = $true
        $mPrs.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Border]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#CCCCCC")), "MarkBorder")))
        $mTpl.Triggers.Add($mPrs)
        $markBtn.Template = $mTpl
        $markBtn.Add_Click({
            $_.Handled = $true
            Show-ToolLinks -t $_.Source.Tag
        })
        $infoRow.Children.Add($markBtn) | Out-Null

        $btnStack.Children.Add($typeRow) | Out-Null
        $btnStack.Children.Add($nameBlock) | Out-Null
        $btnStack.Children.Add($descBlock) | Out-Null
        $btnStack.Children.Add($infoRow) | Out-Null

        $btn.Content = $btnStack
        $btn.Tag = $t

        $borderFactory = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
        $borderFactory.Name = "BtnBorder"
        $borderFactory.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#D6D6D6")))
        $borderFactory.SetValue([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#A0A0A0")))
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
            $b.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom("#1F1F1F")
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
            $b.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom("#2E2E2E")
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
                    $tName = ($clickedBtn.Content.Children[1]).Text
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
                $script:timerBtn.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom("#2E2E2E")

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
                    $rs.SessionStateProxy.SetVariable("DownloadPanel", $DownloadPanel)
                    $rs.SessionStateProxy.SetVariable("DlList", $DlList)
                    $rs.SessionStateProxy.SetVariable("DlCount", $DlCount)
                    $rs.SessionStateProxy.SetVariable("DlRows", $script:DlRows)
                    $ps = [powershell]::Create(); $ps.Runspace = $rs
                    $null = $ps.AddScript({
                        function Set-StatusBg { param($title,$sub,$badge)
                            $dispatcher.Invoke([Action]{ $StatusTitle.Text=$title; $StatusSub.Text=$sub; $StatusBadge.Text=$badge })
                        }
                        function Write-LogBg { param($msg)
                            $dispatcher.Invoke([Action]{ $LogBox.AppendText("[$(Get-Date -f 'HH:mm:ss')] $msg`n"); $LogBox.ScrollToEnd() })
                        }
                        # ---- download shelf: one stacked row per active download (Chrome-like) ----
                        function New-DownloadRow { param($name,[long]$totalBytes)
                            $row = [hashtable]::Synchronized(@{})
                            $dispatcher.Invoke([Action]{
                                $card = New-Object System.Windows.Controls.Border
                                $card.CornerRadius = New-Object System.Windows.CornerRadius(8)
                                $card.Background = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.ColorConverter]::ConvertFromString("#E2E2E2"))
                                $card.BorderBrush = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.ColorConverter]::ConvertFromString("#B0B0B0"))
                                $card.BorderThickness = New-Object System.Windows.Thickness(1)
                                $card.Padding = New-Object System.Windows.Thickness(10,8,10,8)
                                $card.Margin = New-Object System.Windows.Thickness(0,0,0,8)

                                $g = New-Object System.Windows.Controls.Grid
                                foreach ($rn in 1..3) { $rd = New-Object System.Windows.Controls.RowDefinition; $rd.Height = [System.Windows.GridLength]::Auto; [void]$g.RowDefinitions.Add($rd) }

                                # row 0: name (left, ellipsis) + pct (right)
                                $g0 = New-Object System.Windows.Controls.Grid
                                $nameTb = New-Object System.Windows.Controls.TextBlock
                                $nameTb.Text = [string]$name
                                $nameTb.FontSize = 11; $nameTb.FontWeight = "SemiBold"
                                $nameTb.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.ColorConverter]::ConvertFromString("#1F1F1F"))
                                $nameTb.TextTrimming = "CharacterEllipsis"
                                $nameTb.VerticalAlignment = "Center"
                                $nameTb.Margin = New-Object System.Windows.Thickness(0,0,48,0)
                                [void]$g0.Children.Add($nameTb)
                                $pctTb = New-Object System.Windows.Controls.TextBlock
                                $pctTb.Text = "0%"
                                $pctTb.FontSize = 11; $pctTb.FontWeight = "Bold"
                                $pctTb.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
                                $pctTb.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
                                $pctTb.HorizontalAlignment = "Right"; $pctTb.VerticalAlignment = "Center"
                                [void]$g0.Children.Add($pctTb)
                                [System.Windows.Controls.Grid]::SetRow($g0,0)
                                [void]$g.Children.Add($g0)

                                # row 1: progress track + fill
                                $track = New-Object System.Windows.Controls.Border
                                $track.CornerRadius = New-Object System.Windows.CornerRadius(3)
                                $track.Height = 6
                                $track.Background = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.ColorConverter]::ConvertFromString("#B0B0B0"))
                                $track.HorizontalAlignment = "Stretch"
                                $track.ClipToBounds = $true
                                $track.Margin = New-Object System.Windows.Thickness(0,9,0,0)
                                $fill = New-Object System.Windows.Controls.Border
                                $fill.CornerRadius = New-Object System.Windows.CornerRadius(3)
                                $fill.Height = 6
                                $fill.HorizontalAlignment = "Stretch"
                                $fill.Background = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
                                $fill.RenderTransformOrigin = New-Object System.Windows.Point(0,0.5)
                                $st = New-Object System.Windows.Media.ScaleTransform
                                $st.ScaleX = 0.0
                                $fill.RenderTransform = $st
                                $track.Child = $fill
                                [System.Windows.Controls.Grid]::SetRow($track,1)
                                [void]$g.Children.Add($track)

                                # row 2: size (left) + state (right)
                                $g2 = New-Object System.Windows.Controls.Grid
                                $sizeTb = New-Object System.Windows.Controls.TextBlock
                                $sizeTb.FontSize = 9
                                $sizeTb.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
                                $sizeTb.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.ColorConverter]::ConvertFromString("#5A5A5A"))
                                [void]$g2.Children.Add($sizeTb)
                                $stateTb = New-Object System.Windows.Controls.TextBlock
                                $stateTb.Text = "Starting..."
                                $stateTb.FontSize = 9
                                $stateTb.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
                                $stateTb.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.ColorConverter]::ConvertFromString("#5A5A5A"))
                                $stateTb.HorizontalAlignment = "Right"
                                [void]$g2.Children.Add($stateTb)
                                [System.Windows.Controls.Grid]::SetRow($g2,2)
                                [void]$g.Children.Add($g2)

                                $card.Child = $g

                                if ($totalBytes -gt 0) { $sizeTb.Text = ("{0:N1} MB" -f ($totalBytes/1MB)) } else { $sizeTb.Text = "" }

                                # newest download on top
                                [void]$DlList.Children.Insert(0, $card)
                                $DownloadPanel.Visibility = "Visible"

                                # UI element refs (read by the UI polling timer)
                                $row.Card = $card; $row.NameTb = $nameTb; $row.PctTb = $pctTb
                                $row.Fill = $fill; $row.SizeTb = $sizeTb; $row.StateTb = $stateTb
                            })
                            # data fields (written by this download thread; rendered by the UI timer)
                            $row.Name = [string]$name
                            $row.Total = [long]$totalBytes
                            $row.Pct = 0
                            $row.Got = [long]0
                            $row.StateText = "Starting..."
                            $row.RemoveMe = $false
                            [void]$DlRows.Add($row)
                            return $row
                        }
                        function Update-DownloadRow { param($row,[int]$pct,[long]$got,[long]$total,[string]$stateText)
                            # write plain data only (free) -- the UI timer renders it on the UI thread
                            if (-not $row) { return }
                            $row.Pct = $pct
                            $row.Got = $got
                            $row.Total = $total
                            $row.StateText = $stateText
                        }
                        function Remove-DownloadRow { param($row)
                            # flag for removal -- the UI timer removes the card on its next tick
                            if (-not $row) { return }
                            $row.RemoveMe = $true
                        }
                        # stream the download in chunks so we can report live % (WebClient hides progress)
                        function Get-FileWithProgress { param($url,$outPath)
                            $req = [System.Net.HttpWebRequest]::Create($url)
                            $req.AllowAutoRedirect = $true
                            $req.UserAgent = "ValyaRFuckHim"
                            $req.Timeout = 30000
                            $resp = $req.GetResponse()
                            $total = $resp.ContentLength
                            $row = New-DownloadRow -name ([System.IO.Path]::GetFileName($outPath)) -totalBytes $total
                            $stream = $resp.GetResponseStream()
                            $fs = [System.IO.File]::Create($outPath)
                            $buffer = New-Object byte[] 65536
                            $done = [long]0
                            $lastPct = -1
                            $lastUi = [DateTime]::MinValue
                            try {
                                while (($read = $stream.Read($buffer,0,$buffer.Length)) -gt 0) {
                                    $fs.Write($buffer,0,$read)
                                    $done += $read
                                    if ($total -gt 0) {
                                        $pct = [int](($done / $total) * 100)
                                        $now = [DateTime]::UtcNow
                                        if (($pct -ne $lastPct -and ($now - $lastUi).TotalMilliseconds -ge 100) -or $pct -ge 100) {
                                            $lastPct = $pct; $lastUi = $now
                                            Update-DownloadRow -row $row -pct $pct -got $done -total $total -stateText "Downloading"
                                        }
                                    } else {
                                        $now = [DateTime]::UtcNow
                                        if (($now - $lastUi).TotalMilliseconds -ge 200) {
                                            $lastUi = $now
                                            Update-DownloadRow -row $row -pct 0 -got $done -total $total -stateText "Downloading"
                                        }
                                    }
                                }
                            } finally {
                                $fs.Close(); $stream.Close(); $resp.Close()
                            }
                            if ($total -gt 0) { Update-DownloadRow -row $row -pct 100 -got $done -total $total -stateText "Done" }
                            else { Update-DownloadRow -row $row -pct 0 -got $done -total 0 -stateText "Done" }
                            return $row
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
                            $dlRow = $null
                            if (Test-Path $destFile) {
                                Write-LogBg "Cached: $fileName - skipping download."
                                $cachedLen = [long](Get-Item -LiteralPath $destFile).Length
                                $dlRow = New-DownloadRow -name $fileName -totalBytes $cachedLen
                                Update-DownloadRow -row $dlRow -pct 100 -got $cachedLen -total $cachedLen -stateText "Cached"
                            } else {
                                Write-LogBg "Downloading $fileName..."
                                $dlRow = Get-FileWithProgress -url $dlUrl -outPath $destFile
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
                            if ($dlRow) { Update-DownloadRow -row $dlRow -pct 100 -got 0 -total 0 -stateText "Failed" }
                        }
                        $dispatcher.Invoke([Action]{ $btn.IsEnabled = $true })
                        # keep this row on "Done" for a moment, then remove just it (other downloads stay)
                        if ($dlRow) { Start-Sleep -Milliseconds 1600; Remove-DownloadRow -row $dlRow }
                        $rs.Close()
                    })
                    $null = $ps.BeginInvoke()
                }
            })
            # instead of launching right away, show the notice overlay first;
            # the tool launches only when the user clicks "Got it"
            $script:pendingLaunchTimer = $script:timer
            if ($NoticeOverlay) {
                $NoticeOverlay.Visibility = "Visible"
                $null = $NoticeOverlay.Focus()
            } else {
                $timer.Start()
            }
        })

        $wrap.Children.Add($btn) | Out-Null
    }

    $scroll.Content = $wrap
    $tab.Content = $scroll
    $ToolsTab.Items.Add($tab) | Out-Null
}


#endregion

#region SIDEBAR & SEARCH

# CATEGORY SIDEBAR (flat list: author categories first, then Scripts & Tools)

# tab index per category (tabs were built in $AllCategories order)
$script:catIndex = @{}
for ($i = 0; $i -lt $ToolsTab.Items.Count; $i++) { $script:catIndex[[string]$ToolsTab.Items[$i].Header] = $i }

function Get-SearchQuery {
    $q = $SearchBox.Text.Trim().ToLower()
    if ($q -eq $script:searchHint.ToLower()) { return "" }
    return $q
}

# Filter only the ACTIVE tab - sidebar rows never disappear while searching
function Apply-SearchFilter {
    $q = Get-SearchQuery
    if (-not $script:toolsTabRef -or $script:toolsTabRef.Items.Count -eq 0) { return 0 }
    $idx = $script:toolsTabRef.SelectedIndex
    if ($idx -lt 0) { return 0 }
    $wp = $script:toolsTabRef.Items[$idx].Content.Content
    $shown = 0
    foreach ($btn in $wp.Children) {
        if ($btn -is [System.Windows.Controls.Button] -and $btn.Content -is [System.Windows.Controls.StackPanel] -and $btn.Content.Children.Count -ge 3) {
            $nm = [string]$btn.Content.Children[1].Text
            $ds = [string]$btn.Content.Children[2].Text
            $cat = ""; $url = ""
            if ($btn.Tag -is [hashtable]) {
                $cat = [string]$btn.Tag.Category
                if ($btn.Tag.URL) { $url = [string]$btn.Tag.URL }
                elseif ($btn.Tag.Command) { $url = [string]$btn.Tag.Command }
            }
            $isMatch = ($q -eq "" -or $nm.ToLower().Contains($q) -or $ds.ToLower().Contains($q) -or $cat.ToLower().Contains($q) -or $url.ToLower().Contains($q))
            if ($isMatch) { $btn.Visibility = "Visible"; $shown++ } else { $btn.Visibility = "Collapsed" }
        }
    }
    return $shown
}

# Count matches across every tab (for the status line + jump target)
function Get-GlobalMatchCount {
    param([string]$q)
    $count = 0
    $first = -1
    for ($ti = 0; $ti -lt $script:toolsTabRef.Items.Count; $ti++) {
        $wp = $script:toolsTabRef.Items[$ti].Content.Content
        $tabHasMatch = $false
        foreach ($btn in $wp.Children) {
            if ($btn -is [System.Windows.Controls.Button] -and $btn.Content -is [System.Windows.Controls.StackPanel] -and $btn.Content.Children.Count -ge 3) {
                $nm = [string]$btn.Content.Children[1].Text
                $ds = [string]$btn.Content.Children[2].Text
                $cat = ""; $url = ""
                if ($btn.Tag -is [hashtable]) {
                    $cat = [string]$btn.Tag.Category
                    if ($btn.Tag.URL) { $url = [string]$btn.Tag.URL }
                    elseif ($btn.Tag.Command) { $url = [string]$btn.Tag.Command }
                }
                if ($q -eq "" -or $nm.ToLower().Contains($q) -or $ds.ToLower().Contains($q) -or $cat.ToLower().Contains($q) -or $url.ToLower().Contains($q)) { $count++; $tabHasMatch = $true }
            }
        }
        if ($first -eq -1 -and $tabHasMatch) { $first = $ti }
    }
    return @{ Count = $count; First = $first }
}


# CATEGORY TABS (horizontal SSTool-style bar: icon + name, active tab underlined red)
$script:toolsTabRef = $ToolsTab
$script:catButtons = @()
$script:activeCatIdx = 0

$script:catIcons = [ordered]@{
    "ValyaR"    = "★"
    "Tonynoh"   = "🐜"
    "Spokwn"    = "≡"
    "TeslaPro"  = "⚡"
    "RedLotus"  = "❀"
    "Zimmerman" = "👤"
    "Orbdiff"   = "●"
    "DetectAC"  = "🔒"
    "NirSoft"   = "⊛"
    "Echo"      = "🔊"
    "System"    = "▣"
    "Scripts"   = "</>"
    "Tools"     = "⬇"
}

$sectionDone = $false
foreach ($c in $script:usedCats) {
    # thin vertical divider before the generic section (Scripts/Tools)
    if (-not $sectionDone -and ($c -eq "Scripts" -or $c -eq "Tools")) {
        $sectionDone = $true
        $div = New-Object System.Windows.Controls.Border
        $div.Width = 1
        $div.Height = 16
        $div.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#969696"))
        $div.Margin = [System.Windows.Thickness]::new(6,0,6,0)
        $div.VerticalAlignment = "Center"
        $CatBar.Children.Add($div) | Out-Null
    }

    $cnt = @($ToolData | Where-Object { $_.Category -eq $c }).Count
    $icon = "•"
    if ($script:catIcons.Contains($c)) { $icon = [string]$script:catIcons[$c] }

    $pill = New-Object System.Windows.Controls.Button
    $pill.Height = 32
    $pill.Padding = "0"
    $pill.Margin = "0,0,1,0"
    $pill.Cursor = "Hand"
    $pill.Foreground = "#555555"
    $pill.FontSize = 10.5
    $pill.Tag = $script:catIndex[$c]
    $pill.ToolTip = "$c - $cnt tools"

    # content: icon + category name
    $tabContent = New-Object System.Windows.Controls.StackPanel
    $tabContent.Orientation = "Horizontal"
    $iconBlock = New-Object System.Windows.Controls.TextBlock
    $iconBlock.Text = $icon
    $iconBlock.FontSize = 10.5
    $iconBlock.Margin = "0,0,5,0"
    $iconBlock.VerticalAlignment = "Center"
    $nameBlock = New-Object System.Windows.Controls.TextBlock
    $nameBlock.Text = $c
    $nameBlock.VerticalAlignment = "Center"
    $tabContent.Children.Add($iconBlock) | Out-Null
    $tabContent.Children.Add($nameBlock) | Out-Null
    $pill.Content = $tabContent

    # template: transparent plate, bottom border doubles as the active underline
    $pBorder = [System.Windows.FrameworkElementFactory]::new([System.Windows.Controls.Border])
    $pBorder.SetValue([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.Brushes]::Transparent)
    $pBorder.SetValue([System.Windows.Controls.Border]::BorderBrushProperty, [System.Windows.Media.Brushes]::Transparent)
    $pBorder.SetValue([System.Windows.Controls.Border]::BorderThicknessProperty, [System.Windows.Thickness]::new(0,0,0,2))
    $pBorder.SetValue([System.Windows.Controls.Border]::PaddingProperty, [System.Windows.Thickness]::new(9,0,9,2))
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
                $lbrd.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
                $lbrd.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
            }
        }
    })
    $pill.Add_MouseEnter({
        $hb = $_.Source
        if ($null -eq $hb.Tag) { $hb = $this }
        if ($hb.Tag -ne $script:activeCatIdx -and [Windows.Media.VisualTreeHelper]::GetChildrenCount($hb) -gt 0) {
            $hbrd = [Windows.Media.VisualTreeHelper]::GetChild($hb, 0)
            if ($hbrd -and $hbrd -is [System.Windows.Controls.Border]) {
                $hbrd.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#B0B0B0"))
            }
        }
    })
    $pill.Add_MouseLeave({
        $hb = $_.Source
        if ($null -eq $hb.Tag) { $hb = $this }
        if ($hb.Tag -ne $script:activeCatIdx -and [Windows.Media.VisualTreeHelper]::GetChildrenCount($hb) -gt 0) {
            $hbrd = [Windows.Media.VisualTreeHelper]::GetChild($hb, 0)
            if ($hbrd -and $hbrd -is [System.Windows.Controls.Border]) {
                $hbrd.Background = [System.Windows.Media.Brushes]::Transparent
            }
        }
    })
    $pill.Add_Click({
        $clicked = $_.Source
        if ($null -eq $clicked.Tag) { $clicked = $this }
        $script:toolsTabRef.SelectedIndex = $clicked.Tag
        $script:activeCatIdx = $clicked.Tag
        Update-CatPills
        Apply-SearchFilter
    })

    $script:catButtons += $pill
    $CatBar.Children.Add($pill) | Out-Null
}
if ($ToolsTab.Items.Count -gt 0) {
    $ToolsTab.SelectedIndex = 0
}

# smooth category switch: quick fade-in of the newly shown tab content
$ToolsTab.Add_SelectionChanged({
    try {
        $item = $ToolsTab.SelectedItem
        if ($item -and $item.Content) {
            $fade = New-Object System.Windows.Media.Animation.DoubleAnimation
            $fade.From = 0.0
            $fade.To = 1.0
            $fade.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(140))
            $fade.EasingFunction = [System.Windows.Media.Animation.QuadraticEase]::new()
            $item.Content.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)
        }
    } catch {}
})

function Update-CatPills {
    foreach ($b in $script:catButtons) {
        $cbrd = $null
        if ([Windows.Media.VisualTreeHelper]::GetChildrenCount($b) -gt 0) {
            $cbrd = [Windows.Media.VisualTreeHelper]::GetChild($b, 0)
        }
        if ($b.Tag -eq $script:activeCatIdx) {
            $b.Foreground = [Windows.Media.Brushes]::White
            if ($cbrd) {
                $cbrd.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
                $cbrd.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#2E2E2E"))
            }
        } else {
            $b.Foreground = "#555555"
            if ($cbrd) {
                $cbrd.Background = [System.Windows.Media.Brushes]::Transparent
                $cbrd.BorderBrush = [System.Windows.Media.Brushes]::Transparent
            }
        }
    }
}

# Live search across all categories
$SearchBox.Add_TextChanged({
    $q = $SearchBox.Text.Trim().ToLower()
    if ($q -eq $script:searchHint.ToLower()) { $q = "" }

    # find first tab that contains a match (regardless of group expansion)
    $firstMatch = -1
    $matchCount = 0
    for ($ti = 0; $ti -lt $script:toolsTabRef.Items.Count; $ti++) {
        $wp = $script:toolsTabRef.Items[$ti].Content.Content
        $tabHasMatch = $false
        foreach ($btn in $wp.Children) {
            if ($btn -is [System.Windows.Controls.Button] -and $btn.Content -is [System.Windows.Controls.StackPanel] -and $btn.Content.Children.Count -ge 3) {
                $nm = [string]$btn.Content.Children[1].Text
                $ds = [string]$btn.Content.Children[2].Text
                $cat = ""; $url = ""
                if ($btn.Tag -is [hashtable]) {
                    $cat = [string]$btn.Tag.Category
                    if ($btn.Tag.URL) { $url = [string]$btn.Tag.URL }
                    elseif ($btn.Tag.Command) { $url = [string]$btn.Tag.Command }
                }
                if ($q -eq "" -or $nm.ToLower().Contains($q) -or $ds.ToLower().Contains($q) -or $cat.ToLower().Contains($q) -or $url.ToLower().Contains($q)) {
                    $matchCount++
                    $tabHasMatch = $true
                }
            }
        }
        if ($firstMatch -eq -1 -and $tabHasMatch) { $firstMatch = $ti }
    }

    if ($q -ne "" -and $firstMatch -ge 0) {
        $script:toolsTabRef.SelectedIndex = $firstMatch
        $script:activeCatIdx = $firstMatch
        Update-CatPills
    }
    Apply-SearchFilter            # filter only the active tab (sidebar rows stay)

    if ($q -ne "") {
        Set-Status "Search" "$matchCount result(s) for '$q'." "IDLE"
    } else {
        Set-Status "Ready" "Select a tool to launch or download it." "IDLE"
    }
})


# EVENTS

$window.Add_MouseLeftButtonDown({ try { $window.DragMove() } catch {} })
$CloseBtn.Add_Click({ $window.Close() })
$MinBtn.Add_Click({ $window.WindowState = "Minimized" })

#endregion

#region EVENTS

# switch to a category tab by index (used by clicks + keyboard shortcuts)
function Select-CategoryIndex {
    param([int]$idx)
    if ($idx -lt 0 -or $idx -ge $script:toolsTabRef.Items.Count) { return }
    $script:toolsTabRef.SelectedIndex = $idx
    $script:activeCatIdx = $idx
    Update-CatPills
    Apply-SearchFilter
}

# keyboard shortcuts: Ctrl+1..9 jump to a tab, Ctrl+Left/Right cycle tabs.
# Arrow handling is skipped while a TextBox has focus so caret movement still works.
$window.Add_PreviewKeyDown({
    $e = $_
    $ctrl = ($e.KeyboardDevice.Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -ne 0
    if (-not $ctrl) { return }
    $key = $e.Key
    $isText = ($e.OriginalSource -is [System.Windows.Controls.TextBox])
    if ($key -ge [System.Windows.Input.Key]::D1 -and $key -le [System.Windows.Input.Key]::D9) {
        $n = ([int]$key - [int][System.Windows.Input.Key]::D1) + 1
        if ($n -lt $script:toolsTabRef.Items.Count) { Select-CategoryIndex $n; $e.Handled = $true }
    }
    elseif ($key -eq [System.Windows.Input.Key]::Left) {
        if (-not $isText) { Select-CategoryIndex ($script:activeCatIdx - 1); $e.Handled = $true }
    }
    elseif ($key -eq [System.Windows.Input.Key]::Right) {
        if (-not $isText) { Select-CategoryIndex ($script:activeCatIdx + 1); $e.Handled = $true }
    }
})

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
Set-Status "Ready" "$($ToolData.Count) tools in $($script:usedCats.Count) categories - search or pick one." "IDLE"

#endregion

#region STARTUP

$window.ShowDialog() | Out-Null

#endregion
