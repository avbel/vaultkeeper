; Per-user installer for Vaultkeeper. Build: iscc /DAppVersion=<x.y.z> [/DStageDir=<dir>] vaultkeeper.iss
; (scripts/bundle-windows.ps1 -Package does this).

#ifndef AppVersion
  #error Pass the version: iscc /DAppVersion=x.y.z
#endif
#ifndef StageDir
  #define StageDir "..\..\out\stage"
#endif

#define AppName "Vaultkeeper"
#define AppExe "vaultkeeper.exe"

[Setup]
; Identifies the app for upgrades and the uninstall entry. It must never change.
AppId={{42228218-E4F1-48E2-8B25-B8EEEE0BD8D6}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=avbel
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.26100
LicenseFile=..\..\LICENSE
SetupIconFile=vaultkeeper.ico
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=..\..\out
OutputBaseFilename=Vaultkeeper-v{#AppVersion}-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#StageDir}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Parameters: "--tray"

[Run]
; No skipifsilent: a silent self-update must bring the tray back.
Filename: "{app}\{#AppExe}"; Parameters: "--tray"; Description: "Start {#AppName}"; Flags: nowait postinstall runasoriginaluser

[Code]
function SendMessageTimeoutW(hWnd: LongWord; Msg: LongWord; wParam: LongInt; lParam: String;
  fuFlags: LongWord; uTimeout: LongWord; var lpdwResult: LongWord): LongInt;
  external 'SendMessageTimeoutW@user32.dll stdcall';

const
  EnvironmentKey = 'Environment';
  RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run';
  StartupApprovedKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run';
  RunValueName = 'Vaultkeeper';
  WM_SETTINGCHANGE = $001A;
  SMTO_ABORTIFHUNG = $0002;

var
  PurgeUserData: Boolean;

procedure BroadcastEnvironmentChange;
var
  Res: LongWord;
begin
  SendMessageTimeoutW($FFFF, WM_SETTINGCHANGE, 0, 'Environment', SMTO_ABORTIFHUNG, 5000, Res);
end;

function NormalizeDir(const Dir: String): String;
begin
  Result := Lowercase(Dir);
  while (Length(Result) > 0) and (Result[Length(Result)] = '\') do begin
    Delete(Result, Length(Result), 1);
  end;
end;

function PathContainsDir(const Path, Dir: String): Boolean;
var
  Rest, Entry: String;
  P: Integer;
begin
  Result := False;
  Rest := Path;
  while Rest <> '' do begin
    P := Pos(';', Rest);
    if P = 0 then begin
      Entry := Rest;
      Rest := '';
    end else begin
      Entry := Copy(Rest, 1, P - 1);
      Rest := Copy(Rest, P + 1, Length(Rest));
    end;
    if NormalizeDir(ExpandConstant(Entry)) = NormalizeDir(Dir) then begin
      Result := True;
      Exit;
    end;
  end;
end;

function PathWithoutDir(const Path, Dir: String): String;
var
  Rest, Entry: String;
  P: Integer;
begin
  Result := '';
  Rest := Path;
  while Rest <> '' do begin
    P := Pos(';', Rest);
    if P = 0 then begin
      Entry := Rest;
      Rest := '';
    end else begin
      Entry := Copy(Rest, 1, P - 1);
      Rest := Copy(Rest, P + 1, Length(Rest));
    end;
    if (Entry <> '') and (NormalizeDir(Entry) <> NormalizeDir(Dir)) then begin
      if Result <> '' then begin
        Result := Result + ';';
      end;
      Result := Result + Entry;
    end;
  end;
end;

procedure AddToUserPath(const Dir: String);
var
  Current: String;
begin
  if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', Current) then begin
    Current := '';
  end;
  if PathContainsDir(Current, Dir) then begin
    Exit;
  end;
  if (Current <> '') and (Current[Length(Current)] <> ';') then begin
    Current := Current + ';';
  end;
  RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', Current + Dir);
  BroadcastEnvironmentChange;
end;

procedure RemoveFromUserPath(const Dir: String);
var
  Current: String;
begin
  if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', Current) then begin
    Exit;
  end;
  if not PathContainsDir(Current, Dir) then begin
    Exit;
  end;
  RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', PathWithoutDir(Current, Dir));
  BroadcastEnvironmentChange;
end;

procedure QuitRunningApp(const AppDir: String);
var
  Exe: String;
  Code: Integer;
begin
  Exe := AddBackslash(AppDir) + '{#AppExe}';
  if FileExists(Exe) then begin
    Exec(Exe, '--quit', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  QuitRunningApp(ExpandConstant('{app}'));
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    AddToUserPath(ExpandConstant('{app}'));
  end;
end;

function HasParam(const Name: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do begin
    if CompareText(ParamStr(I), Name) = 0 then begin
      Result := True;
      Exit;
    end;
  end;
end;

function InitializeUninstall(): Boolean;
begin
  QuitRunningApp(ExpandConstant('{app}'));
  PurgeUserData := HasParam('/PURGEDATA');
  if (not PurgeUserData) and (not UninstallSilent) then begin
    PurgeUserData := SuppressibleMsgBox(
      'Also delete your Vaultkeeper data (vault, settings, logs) in %LOCALAPPDATA%\vaultkeeper?'#13#10#13#10 +
      'Choose No to keep it for a later reinstall.',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;
  end;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Browsers: array of String;
  I: Integer;
begin
  if CurUninstallStep <> usPostUninstall then begin
    Exit;
  end;
  RemoveFromUserPath(ExpandConstant('{app}'));
  RegDeleteValue(HKCU, RunKey, RunValueName);
  RegDeleteValue(HKCU, StartupApprovedKey, RunValueName);

  Browsers := ['Google\Chrome', 'Chromium', 'BraveSoftware\Brave-Browser', 'Microsoft\Edge', 'Mozilla'];
  for I := 0 to GetArrayLength(Browsers) - 1 do begin
    RegDeleteKeyIncludingSubkeys(HKCU,
      'Software\' + Browsers[I] + '\NativeMessagingHosts\org.vaultkeeper.browser');
  end;

  if PurgeUserData then begin
    // Holds data\ (vault, settings) and the logs (the app writes them as ...\Vaultkeeper\logs;
    // the path is case-insensitive).
    DelTree(ExpandConstant('{localappdata}\vaultkeeper'), True, True, True);
  end;
end;
