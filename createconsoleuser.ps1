<#
.SYNOPSIS
This script creates a local Xbox console user via provided email address, gamertag, first- and lastname.

.DESCRIPTION
The script creates a local console useraccount.

.PARAMETER email
The email address to use for the new user. This parameter is required.

.PARAMETER gamertag
Desired gamertag name (without the #1234 suffix).

.PARAMETER firstname
First name.

.PARAMETER lastname
Last name.

.EXAMPLE
.\createconsoleuser.ps1 -email "john@doe.com" -gamertag JohnDoe -firstname John -lastname Doe
This example demonstrates how to call the script.

.NOTES
This script needs to be executed in an elevated session.
Use at your own risk!
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$email,
    [Parameter(Mandatory=$true)]
    [string]$gamertag,
    [Parameter(Mandatory=$true)]
    [string]$firstname,
    [Parameter(Mandatory=$true)]
    [string]$lastname
)

$stage1 = @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Security.Principal;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public static class WinRT
{
    public enum RO_INIT_TYPE
    {
        RO_INIT_SINGLETHREADED = 0,
        RO_INIT_MULTITHREADED = 1,
    }

    [DllImport("api-ms-win-core-winrt-l1-1-0.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr RoInitialize(RO_INIT_TYPE initType);

    [DllImport("api-ms-win-core-winrt-l1-1-0.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr RoUninitialize();

    [DllImport("api-ms-win-core-winrt-l1-1-0.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr RoGetActivationFactory(IntPtr activatableClassId, byte[] iid, out IntPtr factory);

    [DllImport("api-ms-win-core-winrt-string-l1-1-0.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr WindowsCreateString([MarshalAs(UnmanagedType.LPWStr)] string sourceString, int length, out IntPtr hstring);

    [DllImport("api-ms-win-core-winrt-string-l1-1-0.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr WindowsDeleteString(IntPtr hstring);

    // A helper to read the virtual function pointer from virtual table of the instance.
    public static T GetVirtualMethodPointer<T>(IntPtr instance, int index)
    {
        var table = Marshal.ReadIntPtr(instance);
        var pointer = Marshal.ReadIntPtr(table, index * IntPtr.Size);
        return Marshal.GetDelegateForFunctionPointer<T>(pointer);
    }
}

public class UserManager : IDisposable
{
    private static readonly string RuntimeClass_Windows_Xbox_System_Internal_UserManager = "Windows.Xbox.System.Internal.UserManager";

    // Interface is a part of the implementation of type Windows.Xbox.System.Internal.UserManager
    private static readonly byte[] IID_IConsoleUserManagement = Guid.Parse("D65AE869-659F-4AF9-8393-99FB0CF7F22C").ToByteArray();

    /*
    // Windows.Xbox.System.Internal.IConsoleUserManagement::get_ConsoleUsers, method index: 6
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementGetConsoleUsersDelegate(IntPtr instance, out IntPtr consoleUsers);
    */

    // Windows.Xbox.System.Internal.IConsoleUserManagement::CreateConsoleUser, method index: 7
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementCreateConsoleUserDelegate(IntPtr instance, IntPtr emailAddress, byte persistCredentials, out uint retval);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::DeleteConsoleUser, method index: 8
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementDeleteConsoleUserDelegate(IntPtr instance, uint consoleUserId);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::UpdateConsoleUser, method index: 9
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementUpdateConsoleUserDelegate(IntPtr instance, uint consoleUserId, IntPtr emailAddress, byte persistCredentials, byte enableKinectSignin);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::ClearNewUserStatus, method index: 10
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementClearNewUserStatusDelegate(IntPtr instance, uint consoleUserId);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::AllocateSponsoredUserId, method index: 11
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementAllocateSponsoredUserIdDelegate(IntPtr instance, out uint retval);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::FreeSponsoredUserId, method index: 12
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementFreeSponsoredUserIdDelegate(IntPtr instance, uint consoleUserId);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::IsUserIdValidForLocalStorage, method index: 13
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementIsUserIdValidForLocalStorageDelegate(IntPtr instance, uint consoleUserId);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::UpdateConsoleUserSignIn, method index: 16
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementUpdateConsoleUserSignInDelegate(IntPtr instance, uint consoleUserId, byte persistCredentials, byte enableKinectSignIn, byte challengeSignIn, byte signOutSpopForKinectSignIn);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::UpdateConsoleUserEmail, method index: 17
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementUpdateConsoleUserEmailDelegate(IntPtr instance, uint consoleUserId, IntPtr emailAddress);

    // Windows.Xbox.System.Internal.IConsoleUserManagement::UpdateConsoleUserAutoSignIn, method index: 18
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr IConsoleUserManagementUpdateConsoleUserAutoSignInDelegate(IntPtr instance, uint consoleUserId, byte autoSignIn);


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsSucceeded(IntPtr result) => (long)result >= 0L;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte BoolToByte(bool value) => value ? (byte)1 : (byte)0;

    private static bool _roInitialized = false;
    private static IntPtr _classId = IntPtr.Zero;
    private static IntPtr _instance = IntPtr.Zero;

    static UserManager()
    {
        if (!IsSucceeded(WinRT.RoInitialize(WinRT.RO_INIT_TYPE.RO_INIT_SINGLETHREADED)))
        {
            throw new Exception("RoInitialize failed");
        }
        _roInitialized = true;

        if (!IsSucceeded(WinRT.WindowsCreateString(RuntimeClass_Windows_Xbox_System_Internal_UserManager, RuntimeClass_Windows_Xbox_System_Internal_UserManager.Length, out _classId)))
        {
            throw new Exception("WindowsCreateString (classID) failed");
        }

        if (!IsSucceeded(WinRT.RoGetActivationFactory(_classId, IID_IConsoleUserManagement, out _instance)))
        {
            throw new Exception("RoGetActivationFactory failed");
        }
    }

    /*
    public static IReadOnlyList<ConsoleUser> GetConsoleUsers()
    {
        throw new NotImplementedException();
    }
    */

    public static uint CreateConsoleUser(string emailAddress, bool persistCredentials)
    {
        if (!IsSucceeded(WinRT.WindowsCreateString(emailAddress, emailAddress.Length, out IntPtr emailAddrPtr)))
        {
            throw new Exception("Failed to initialize email HSTRING");
        }

        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementCreateConsoleUserDelegate>(_instance, 7);
        method.Invoke(_instance, emailAddrPtr, BoolToByte(persistCredentials), out uint ret);
        WinRT.WindowsDeleteString(emailAddrPtr);
        return ret;
    }

    public static void DeleteConsoleUser(uint consoleUserId)
    {
        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementDeleteConsoleUserDelegate>(_instance, 8);
        method.Invoke(_instance, consoleUserId);
    }

    public static void UpdateConsoleUser(uint consoleUserId, string emailAddress, bool persistCredentials, bool enableKinectSignin)
    {
        if (!IsSucceeded(WinRT.WindowsCreateString(emailAddress, emailAddress.Length, out IntPtr emailAddrPtr)))
        {
            throw new Exception("Failed to initialize email HSTRING");
        }

        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementUpdateConsoleUserDelegate>(_instance, 9);
        method.Invoke(_instance, consoleUserId, emailAddrPtr, BoolToByte(persistCredentials), BoolToByte(enableKinectSignin));

        WinRT.WindowsDeleteString(emailAddrPtr);
    }

    public static void ClearNewUserStatus(uint consoleUserId)
    {
        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementClearNewUserStatusDelegate>(_instance, 10);
        method.Invoke(_instance, consoleUserId);
    }

    public static uint AllocateSponsoredUserId()
    {
        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementAllocateSponsoredUserIdDelegate>(_instance, 11);
        method.Invoke(_instance, out uint ret);
        return ret;
    }

    public static void FreeSponsoredUserId(uint consoleUserId)
    {
        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementFreeSponsoredUserIdDelegate>(_instance, 12);
        method.Invoke(_instance, consoleUserId);
    }

    public static void IsUserIdValidForLocalStorage(uint consoleUserId)
    {
        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementIsUserIdValidForLocalStorageDelegate>(_instance, 13);
        method.Invoke(_instance, consoleUserId);
    }

	public static void UpdateConsoleUserSignIn(uint consoleUserId, bool persistCredentials, bool enableKinectSignIn, bool challengeSignIn, bool signOutSpopForKinectSignIn)
    {
        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementUpdateConsoleUserSignInDelegate>(_instance, 16);
        method.Invoke(_instance, consoleUserId, BoolToByte(persistCredentials), BoolToByte(enableKinectSignIn), BoolToByte(challengeSignIn), BoolToByte(signOutSpopForKinectSignIn));
    }

	public static void UpdateConsoleUserEmail(uint consoleUserId, string emailAddress)
    {
        if (!IsSucceeded(WinRT.WindowsCreateString(emailAddress, emailAddress.Length, out IntPtr emailAddrPtr)))
        {
            throw new Exception("Failed to initialize email HSTRING");
        }

        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementUpdateConsoleUserEmailDelegate>(_instance, 17);
        method.Invoke(_instance, consoleUserId, emailAddrPtr);

        WinRT.WindowsDeleteString(emailAddrPtr);
    }

	public static void UpdateConsoleUserAutoSignIn(uint consoleUserId, bool autoSignIn)
    {
        var method = WinRT.GetVirtualMethodPointer<IConsoleUserManagementUpdateConsoleUserAutoSignInDelegate>(_instance, 18);
        method.Invoke(_instance, consoleUserId, BoolToByte(autoSignIn));
    }

    public void Dispose()
    {
        if (_instance != IntPtr.Zero)
            Marshal.Release(_instance);
        if (_classId != IntPtr.Zero)
            WinRT.WindowsDeleteString(_classId);
        if (_roInitialized)
            WinRT.RoUninitialize();
    }
}
'@

Write-Host "[+] Loading stage 1 managed code"
Add-Type -TypeDefinition $stage1

#Write-Host "[+] Deleting old user (uid: 16)"
#[UserManager]::DeleteConsoleUser(16)

Write-Host "[+] Calling CreateConsoleUser"
$uid = [UserManager]::CreateConsoleUser($email, $true)

Write-Host "[+] Console user $uid created"

Write-Host "[+] Clearing new-user flag"
[UserManager]::ClearNewUserStatus($uid)

Write-Host "[+] Enabling auto-signin"
[UserManager]::UpdateConsoleUserAutoSignIn($uid, $true)

Write-Host "[+] Verifying User Directory"
$userpath = (get-itemproperty HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid -Name ProfileName).ProfileName

if (!(Test-Path "U:\Users\$userpath\NTUSER.DAT"))
{
  Write-Host "[-] User Creation Failed!"

  Write-Host "[-] File U:\Users\$userpath\NTUSER.DAT does not exist!"
  Exit 1
}

$stage2 = @'
using System;
using System.Runtime.InteropServices;

public class RegistryInterop
{
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError = true)]
    public static extern int RegLoadKeyW(IntPtr hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError = true)]
    public static extern int RegUnLoadKeyW(IntPtr hKey, string lpSubKey);

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
	const uint SE_PRIVILEGE_DISABLED = 0x00000000;
	const uint SE_PRIVILEGE_ENABLED = 0x00000002;
	const uint SE_PRIVILEGE_REMOVED = 0x00000004;
	const int TOKEN_QUERY = 0x00000008;

	const uint HCR =  0x80000000;
	const uint HCU =  0x80000001;
	const uint HKLM = 0x80000002;
	const uint HKU =  0x80000003;

	static string SE_BACKUP_NAME = "SeBackupPrivilege";
	static string SE_RESTORE_NAME = "SeRestorePrivilege";

  static LUID _restoreLuid = new LUID();
  static LUID _backupLuid = new LUID();

	static IntPtr _processToken = IntPtr.Zero;
	static bool _initialized = false;

    static RegistryInterop()
    {
        int retval = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref _processToken);
        if (retval == 0) {
          Console.WriteLine("OpenProcess Error: {0}", retval);
          return;
        }

        retval = LookupPrivilegeValue(null, SE_RESTORE_NAME, ref _restoreLuid);
        if (retval == 0) {
          Console.WriteLine("LookupPrivs: SE_RESTORE_NAME - Error: {0}", Marshal.GetLastWin32Error());
          return;
        }
        retval = LookupPrivilegeValue(null, SE_BACKUP_NAME, ref _backupLuid);
        if (retval == 0) {
	        Console.WriteLine("LookupPrivs: SE_BACKUP_NAME - Error: {0}", Marshal.GetLastWin32Error());
          return;
        }
        _initialized = true;
    }

    public static void AdjustPrivs(bool enable)
    {
	if (!_initialized) {
	  Console.WriteLine("[-] Precondition failed, cannot adjust privs");
	  return;
	}

      TOKEN_PRIVILEGES TP = new TOKEN_PRIVILEGES();
      TOKEN_PRIVILEGES TP2 = new TOKEN_PRIVILEGES();

      TP.PrivilegeCount = 1;
      TP.Attributes = enable ? SE_PRIVILEGE_ENABLED: SE_PRIVILEGE_DISABLED;
      TP.Luid = _restoreLuid;
      TP2.PrivilegeCount = 1;
      TP2.Attributes = enable ? SE_PRIVILEGE_ENABLED: SE_PRIVILEGE_DISABLED;
      TP2.Luid = _backupLuid;

      int retval = AdjustTokenPrivileges(_processToken, false, ref TP, 0, IntPtr.Zero, IntPtr.Zero);
      if (retval == 0) {
        Console.WriteLine("AdjustTokenPrivs: SE_RESTORE - Error: {0}", Marshal.GetLastWin32Error());
        return;
      }
      retval = AdjustTokenPrivileges(_processToken, false, ref TP2, 0, IntPtr.Zero, IntPtr.Zero);
      if (retval == 0)
        Console.WriteLine("AdjustTokenPrivs: SE_BACKUP - Error: {0}", Marshal.GetLastWin32Error());
    }

    public static int LoadHive(string targetHiveName, string hiveFilePath)
    {
        return RegLoadKeyW(new IntPtr(HKLM), targetHiveName, hiveFilePath);
    }

    public static int UnloadHive(string targetHiveName)
    {
        return RegUnLoadKeyW(new IntPtr(HKLM), targetHiveName);
    }
}
'@

Write-Host "[+] Loading stage 2 managed code"
Add-Type -TypeDefinition $stage2

Write-Host "[+] Acquiring token privileges"
[RegistryInterop]::AdjustPrivs($true)

# Load Hive into HKLM
$hiveFile = "U:\Users\$userpath\NTUSER.DAT"
Write-Host "[*] Attempting to load Hive: $hiveFile"
$ret = [RegistryInterop]::LoadHive("USR", $hiveFile)
if ( $ret -ne 0 )
{
  Write-Host "[-] Failed to mount user registry hive, code $ret"
  Exit 1
}

Write-Host "[-] User Hive mounted to HKLM:\USR"

# Set XboxLive metadata
New-Item -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Force
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "AccountId" -Value "0003BFFFFFFFFFFF" -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "Xuid" -Value "2535401234567890" -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "UserName" -Value $email -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "Gamertag" -Value $gamertag -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "AgeGroup" -Value "Adult" -Type String
# NEW VALUES START
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "ModernGamertag" -Value $gamertag -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "ModernGamertagSuffix" -Value "2345" -Type String
Set-ItemProperty -Path "HKLM:\USR\Software\Microsoft\XboxLive" -Name "UniqueModernGamertag" -Value "$gamertag#2354" -Type String
# NEW VALUES END

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
# NEW VALUES START
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "IsBiometricSigninEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "ChallengeSignin" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "TwitterSignInEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "UniqueModernGamertag" -Value "$gamertag#2354" -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "ModernGamertag" -Value $gamertag -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "ModernGamertagSuffix" -Value "2354" -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "DisplayName" -Value "$firstname $lastname" -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "FirstName" -Value $firstname -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "UserPicture" -Value "U:\Users\$userpath\Documents\UserImage.jpg" -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "LastName" -Value $lastname -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "AllowNewUserFlow" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "BypassPinControllerSignIn" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "hasSeenControllerSignInToast" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "QuickSettingsHelpBubbleCount" -Value 0xA -Type DWord
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "lastSeenHomeHeroPromptTimeframeId" -Value "11/30/2022_02:00:00_AM_TO_11/30/2035_02:00:00_AM" -Type String
Set-ItemProperty -Path "HKLM:\OSDATA\CurrentControlSet\Control\UserManager\Users\$uid" -Name "XboxAssistHelpBubbleCount" -Value 2 -Type DWord
# NEW VALUES END

New-Item -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Force
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
# NEW VALUES START
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AcknowledgedHowWeUseData" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AcknowledgedInFlight" -Type DWord -Value 0x3
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AcknowledgedCrashDumps" -Type DWord -Value 0x3
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AcknowledgedOptionalDataCollection" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AcknowledgedGDPRConsent" -Type DWord -Value 0x3
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "uniqueModernGamerTag" -Type String -Value "$gamertag#2354"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "UtilityOfEngagement" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "SpeechAccessibility" -Type String -Value '{"GameChatSTT":false,"GameChatTTS":false,"GameTextSS":false,"PersonaId":"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech_OneCore\\Voices\\Tokens\\MSTTS_V110_enUS_DavidM","PersonaName":"Microsoft David","PersonaGender":0,"PersonaLang":"en-US"}'
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "WebColorTheme" -Type String -Value "gamerpicblur"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "backgroundType" -Type DWord -Value 0x3
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "backgroundTitle" -Type String -Value ""
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "backgroundDescription" -Type String -Value ""
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "backgroundLink" -Type String -Value ""
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "userId" -Type String -Value "9b6d3cce-9522-4b20-9707-1f5028dd6e6d"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "V3AvatarManifest" -Type String -Value '<?xml version="1.0" encoding="utf-16"?><Manifest Version="0.18" Gender="Female" Height="0.90"><SkinColor Slot="0" H="0.1174" S="0.0043" L="1.0000" /><OuterIrisColor Slot="0" H="0.0000" S="0.0000" L="1.0000" /><Mood>154700</Mood><Items><Item Id="139700" Slot="Top"><Colors><Color Slot="0" H="0.1361" S="1.0000" L="0.4940" /><Color Slot="1" H="0.0000" S="0.0000" L="0.1843" /></Colors></Item><Item Id="104800" Slot="Bottom"><Colors><Color Slot="0" H="0.0000" S="0.0000" L="1.0000" /></Colors></Item><Item Id="201000" Slot="Mount"><Colors><Color Slot="0" H="0.0000" S="0.0000" L="1.0000" /><Color Slot="1" H="0.0000" S="0.0000" L="1.0000" /><Color Slot="2" H="0.0000" S="0.0000" L="1.0000" /><Color Slot="3" H="0.0000" S="1.0000" L="1.0000" /></Colors></Item><Item Id="134800" Slot="Hair"><Colors><Color Slot="0" H="0.0000" S="0.0000" L="1.0000" /><Color Slot="1" H="0.3847" S="1.0000" L="0.7646" /></Colors></Item><Item Id="" Slot="Eyebrows"><Colors><Color Slot="0" H="0.0555" S="0.4283" L="0.1509" /></Colors></Item><Item Id="122700" Slot="FacialHair"><Colors><Color Slot="0" H="0.0726" S="1.0000" L="0.5195" /></Colors></Item><Item Id="108600" Slot="Fingernails"><Colors><Color Slot="0" H="0.3659" S="0.9951" L="0.3957" /><Color Slot="1" H="0.6356" S="0.7156" L="0.4137" /><Color Slot="2" H="0.0286" S="1.0000" L="0.5293" /></Colors></Item></Items><Textures /><Features><Feature Slot="BodyShape" Id="000500" /><Feature Slot="Jaw" Id="958300" /><Feature Slot="Nose" Id="960300" /><Feature Slot="Ears" Id="962800" /><Feature Slot="Mouth" Id="950500" /><Feature Slot="Eyes" Id="955700" /></Features></Manifest>'
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw1080" -Type String -Value "n:\usersettings\$uid\public\GameDisplayPicRaw1080"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw1080_Hash" -Type String -Value "92ea3a50a7c8fa53665e36f9d1366fbc"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw424" -Type String -Value "n:\usersettings\$uid\public\GameDisplayPicRaw424"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "GameDisplayPicRaw424_Hash" -Type String -Value "2df84f5cb390625b05cbbe2e8440ff88"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw424" -Type String -Value "n:\usersettings\$uid\public\AppDisplayPicRaw424"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw424_Hash" -Type String -Value "2df84f5cb390625b05cbbe2e8440ff88"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw1080" -Type String -Value "n:\usersettings\$uid\public\AppDisplayPicRaw1080"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AppDisplayPicRaw1080_Hash" -Type String -Value "92ea3a50a7c8fa53665e36f9d1366fbc"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "dateCreated" -Type String -Value "2016-01-08T03:24:48.827"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "FailedPasskeyAttempts" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "IsXbox360Gamerpic" -Type String -Value "0"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "Xbox360Gamerpic" -Type String -Value "fffe07d10002000400010004"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "childFamilyMembers" -Type String -Value ""
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "HasDoneFirstFamilySettingsSync" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "JumpHelpBubbleCount" -Type DWord -Value 0xA 
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "AccessoryEnrollment" -Type String -Value "E48E75143E08D942A5D6723C8096B80AF1A8821CCB4ED8DEAB911048621B1B9C,1DA01E0F72DFFE0;0ADC7CAE69AD0E57B274BEBC86F80EA3D7906DA440A9949525CAADC8869A1A51,1DABBBA4AAE77B0"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "ConsoleStreamingTestResults" -Type String -Value "00000000000000B0"
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "ConsoleStreamingV2Enabled" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "CommunityRewardsProgramAvailable" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "CommunityRewardsPointBalance" -Type DWord -Value 0x4EE
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "CommunityRewardsIsMSRewardsMember" -Type DWord -Value 0x1
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "OptionalDataCollectionSettingLastSetDate" -Type QWord -Value 133631398703464426
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "OptionalDataCollection" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "PersonalizedPurchaseUpsellLastSetDate" -Type QWord -Value 133631398703614421
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "PersonalizedPurchaseUpsell" -Type DWord -Value 0x0
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid" -Name "ShowSelectedGameArtBackground" -Type DWord -Value 0x0
New-Item -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid\RecommendedSettings" -Force
New-Item -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid\RecommendedSettings\FamilySafety" -Force
Set-ItemProperty -Path "HKLM:\OSDATA\Software\Microsoft\Durango\UserSettings\$uid\RecommendedSettings\FamilySafety" -Name "state" -Type DWord -Value 0
# NEW VALUES END

# Unload Hive from HKLM
#reg.exe UNLOAD HKLM\USR
$ret = [RegistryInterop]::UnloadHive("USR")
if ( $ret -ne 0 )
{
  Write-Host "[-] Failed to unload user registry hive"
}

Write-Host "[+] Restoring token privileges"
[RegistryInterop]::AdjustPrivs($false)
