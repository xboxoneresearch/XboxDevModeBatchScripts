﻿<#
.SYNOPSIS
This script populates a local Xbox console user with fake XBL metadata.


.DESCRIPTION
The script takes a user-id "uid", system account name "winuser" and "email" parameter and populates metadata.

.PARAMETER uid
The user-id received from user-creation.

.PARAMETER winuser
The username from the windows accounts, f.e. "UserMgr0"

.PARAMETER email
The email address to populate for the user.

.PARAMETER gamertag
The gamertag to assign to the user.

.PARAMETER firstname
The first name to assign to the user.

.PARAMETER lastname
The last name to assign to the user.

.EXAMPLE
.\setuserdata.ps1 -uid 16 -winuser "UserMgr0" -email "john@doe.com" -gamertag "xXJohnXx" -firstname "John" -lastname "Doe" 
This example demonstrates how to call the script with the required parameters.

.NOTES
This script needs to be executed in an elevated session.
Use at your own risk!
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [int]$uid,
    [Parameter(Mandatory=$true)]
    [string]$winuser,
    [Parameter(Mandatory=$true)]
    [mailAddress]$email,
    [Parameter(Mandatory=$true)]
    [string]$gamertag,
    [Parameter(Mandatory=$true)]
    [string]$firstname,
    [Parameter(Mandatory=$true)]
    [string]$lastname
)

Set-StrictMode -Version latest
$ErrorActionPreference = "Stop"


$code = @'
using System;
using System.Runtime.InteropServices;

public class RegistryInterop
{
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegLoadKey(uint hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegUnLoadKey(uint hKey, string lpSubKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

	const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
	const int SE_PRIVILEGE_ENABLED = 0x00000002;
	const int TOKEN_QUERY = 0x00000008;

	const uint HCR =  0x80000000;
	const uint HCU =  0x80000001;
	const uint HKLM = 0x80000002;
	const uint HKU =  0x80000003;

	static string SE_BACKUP_NAME = "SeBackupPrivilege";
	static string SE_RESTORE_NAME = "SeRestorePrivilege";

    static RegistryInterop()
    {
        LUID RestoreLuid = new LUID();
        LUID BackupLuid = new LUID();

        TOKEN_PRIVILEGES TP = new TOKEN_PRIVILEGES();
        TOKEN_PRIVILEGES TP2 = new TOKEN_PRIVILEGES();

        IntPtr token = IntPtr.Zero;
        int retval = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref token);
        retval = LookupPrivilegeValue(null, SE_RESTORE_NAME, ref RestoreLuid);
        retval = LookupPrivilegeValue(null, SE_BACKUP_NAME, ref BackupLuid);

        TP.PrivilegeCount = 1;
        TP.Attributes = SE_PRIVILEGE_ENABLED;
        TP.Luid = RestoreLuid;
        TP2.PrivilegeCount = 1;
        TP2.Attributes = SE_PRIVILEGE_ENABLED;
        TP2.Luid = BackupLuid;

        retval = AdjustTokenPrivileges(token, false, ref TP, 0, IntPtr.Zero, IntPtr.Zero);
        retval = AdjustTokenPrivileges(token, false, ref TP2, 0, IntPtr.Zero, IntPtr.Zero);
    }

    public static int LoadHive(string targetHiveName, string hiveFilePath)
    {
        return RegLoadKey(HKLM, targetHiveName, hiveFilePath);
    }

    public static int UnloadHive(string targetHiveName)
    {
        return RegUnLoadKey(HKLM, targetHiveName);
    }
}
'@

Write-Host "[+] Loading managed code"
Add-Type -TypeDefinition $code

# Load Hive into HKLM
[RegistryInterop]::LoadHive("USR", "U:\Users\$winuser\NTUSER.DAT")
# reg.exe LOAD HKLM\USR U:\Users\$winuser\NTUSER.DAT

# Set XboxLive metadata
New-Item -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Force
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "AccountId" -Value "0003BFFFFFFFFFFF" -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "Xuid" -Value "2535401234567890" -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "UserName" -Value $email -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "Gamertag" -Value $gamertag -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "AgeGroup" -Value "Adult" -Type String

# Unload Hive from HKLM
[RegistryInterop]::UnloadHive("USR")
#reg.exe UNLOAD HKLM\USR

# Additional registry operations
New-Item -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Force
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "lastSigninResult" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "MigrationRequired" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "Gamertag" -Value $gamertag -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "UserData" -Value "1234567890123456789" -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "XboxUserId" -Value "2535401234567890" -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "AgeGroup" -Value "Adult" -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "SignInCaller" -Value 5 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "SignInTimestamp" -Value 0x1CF068469F2C000 -Type QWord

Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "ACL Set" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "xuid" -Type String -Value 2535401234567890
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "DoNotDisturbEnabled" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "gamerTag" -Type String -Value $gamertag
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "ageGroup" -Type DWord -Value 0x3
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "ChallengeUserPurchase" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "ChallengeUserSettings" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "SignInTimestamp" -Type String -Value 130330080000000000
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "Reputation" -Type String -Value 70
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayName" -Type String -Value $gamertag
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayName" -Type String -Value $gamertag
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "Gamerscore" -Type String -Value 5
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw" -Type String -Value "https://images-eds-ssl.xboxlive.com/image?url=base64Here&format=png"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw" -Type String -Value "https://images-eds-ssl.xboxlive.com/image?url=base64Here&format=png"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "TenureLevel" -Type String -Value 0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "PublicGamerpic" -Type String -Value "https://images-eds-ssl.xboxlive.com/image?url=base64Here"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "Background" -Type String -Value ""
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "TileOpacity" -Type String -Value 256
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "HomePanelOpacity" -Type String -Value 256
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "ShowUserAsAvatar" -Type String -Value 2
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "CommunicateUsingTextAndVoice" -Type String -Value Everyone
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "CommunicateUsingVideo" -Type String -Value PeopleOnMyList
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AllowUserCreatedContentViewing" -Type String -Value Everyone
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw208" -Type String -Value "n:\usersettings\$uid\public\GameDisplayPicRaw208"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw208_Hash" -Type String -Value d0347a567415581cf08f2953ecfc39c7
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw64" -Type String -Value "n:\usersettings\$uid\public\GameDisplayPicRaw64"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw64_Hash" -Type String -Value 2742d8c397be7c2ac79a6ded402225be
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw208" -Type String -Value "n:\usersettings\$uid\public\AppDisplayPicRaw208"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw64" -Type String -Value "n:\usersettings\$uid\public\AppDisplayPicRaw64"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw64_Hash" -Type String -Value 2742d8c397be7c2ac79a6ded402225be
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw208_Hash" -Type String -Value d0347a567415581cf08f2953ecfc39c7
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "primaryColor" -Type DWord -Value 0x1073D6
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "secondaryColor" -Type DWord -Value 0x133157
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "tertiaryColor" -Type DWord -Value 0x134E8A
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw424" -Type String -Value "n:\usersettings\$uid\public\AppDisplayPicRaw424"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw424_Hash" -Type String -Value 6dfdf83c3659285ba290a5c1cf14eb68
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw424" -Type String -Value "n:\usersettings\$uid\public\GameDisplayPicRaw424"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw424_Hash" -Type String -Value 6dfdf83c3659285ba290a5c1cf14eb68
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw1080" -Type String -Value "n:\usersettings\$uid\public\AppDisplayPicRaw1080"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw1080_Hash" -Type String -Value 011277f06d3d28b7461cd47b44ca5672
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw1080" -Type String -Value "n:\usersettings\$uid\public\GameDisplayPicRaw1080"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw1080_Hash" -Type String -Value 011277f06d3d28b7461cd47b44ca5672
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "activityReporting" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "allowPurchaseAndDownloads" -Type String -Value FreeAndPaid
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "canViewRestrictedContent" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "canViewTVAdultContent" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "imageUrl" -Type String -Value "https://cid-0123456789012345.users.storage.live.com/users/0x0123456789012345/myprofile/expressionprofile/profilephoto:Win8Static/UserTile?ck=1&ex=24"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "maturityLevel" -Type DWord -Value 0xFF
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "restrictPromotionalContent" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "role" -Type String -Value Admin
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "webFilteringLevel" -Type String -Value Off
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AvatarManifest" -Type String -Value ""
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "firstName" -Type String -Value $firstname
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "isAdult" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "lastName" -Type String -Value $lastname
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "legalCountry" -Type String -Value US
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "locale" -Type String -Value en-US
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "requirePasskeyForPurchase" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "requirePasskeyForSignIn" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "userKey" -Type String -Value 0000000000000000000000000000000000000000000000000000000000000000
New-Item -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid\TitleExceptions" -Force