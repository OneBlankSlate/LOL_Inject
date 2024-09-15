#include <Windows.h>
#include <iostream>
#include<tchar.h>
#include<fstream>
#include<TlHelp32.h>
#include <Psapi.h>   
#include<vector>
#include<string>
#pragma comment(lib,"Psapi.lib")
using namespace std;
#define DLL_HIJACK 0
#define SET_WINDOWS_HOOK_EX 1
DWORD get_processid_by_imagename(const TCHAR* ProcessImageName);
BOOL get_thread_id(DWORD ProcessIdentify, vector<DWORD>& ThreadIdentifyV);
BOOL copy_data_to_file(TCHAR* MyFilePath, TCHAR* TargetFilePath);
VOID inject(TCHAR* Flag, TCHAR* TargetFileDirectory, TCHAR* TargetDllName, TCHAR* MyDllPath);
void inject_by_hijack(wstring TargetFileDirectory, wstring TargetFileName, wstring MyFilePath);
void inject_by_hook(HANDLE ProcessHandle, DWORD ProcessIdentity, wstring DllPath);
