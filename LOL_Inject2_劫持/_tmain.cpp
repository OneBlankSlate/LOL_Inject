#include"_tmain.h"

int _tmain(int argc,TCHAR* argv[])
{
	inject(argv[1], argv[2], argv[3], argv[4]);//注入方式  imagename TargetFileDirectory TargetDllName MyDllPath
	return 0;                                  //如果是windows消息钩子注入时，第二第三参数均传0即可
}
//将我们dll的数据拷贝到指定文件中
BOOL copy_data_to_file(wstring MyFilePath,wstring TargetFilePath)
{
	ifstream source_file(MyFilePath, ios::binary);
	if (!source_file) {
		return FALSE;
	}
	// 打开目标文件
	ofstream target_file(TargetFilePath, ios::binary);
	if (!target_file) {
		return FALSE;
	}
	// 复制文件内容
	target_file << source_file.rdbuf();
	// 关闭文件
	source_file.close();
	target_file.close();
	return TRUE;
}

VOID inject(TCHAR* Flag, TCHAR* TargetFileDirectory, TCHAR* TargetDllName, TCHAR* MyDllPath)
{
	int flag = stoi(Flag);

	wstring target_file_directory;
	target_file_directory.assign(TargetFileDirectory);

	wstring target_dll_name;
	target_dll_name.assign(TargetDllName);

	wstring my_dll_path;
	my_dll_path.assign(MyDllPath);

	DWORD process_id = get_processid_by_imagename(_T("League of Legends.exe"));
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	switch (flag)
	{
	case DLL_HIJACK:
		inject_by_hijack(target_file_directory, TargetDllName, MyDllPath);
		break;
	case SET_WINDOWS_HOOK_EX:
		inject_by_hook(process_handle, process_id, MyDllPath);
		break;
	
	}
}
void inject_by_hijack(wstring TargetFileDirectory, wstring TargetFileName, wstring MyFilePath)
{
	TCHAR* target_file_directory = _tcsdup(TargetFileDirectory.c_str());
	TCHAR* my_file_path = _tcsdup(MyFilePath.c_str());
	wstring target_file_path = TargetFileDirectory + L"\\" + TargetFileName;
	if (CreateDirectory((LPCWSTR)target_file_directory, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
		// 复制 DLL 文件
		if (copy_data_to_file(my_file_path, target_file_path))
		{
			cout << "File copied successfully" << endl;
		}
		else {
			cerr << "Failed to copy file" << endl;
		}
	}
	else {
		cerr << "Failed to create target directory" << endl;
	}
}
BOOL get_thread_id(DWORD ProcessIdentify, vector<DWORD>& ThreadIdentifyV) {
	HANDLE thread_snap_handle = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	thread_snap_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (thread_snap_handle == INVALID_HANDLE_VALUE)  return FALSE;
	te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(thread_snap_handle, &te32)) {
		CloseHandle(thread_snap_handle);
		return FALSE;
	}
	do {
		if (te32.th32OwnerProcessID == ProcessIdentify) {
			ThreadIdentifyV.push_back(te32.th32ThreadID);
		}
	} while (Thread32Next(thread_snap_handle, &te32));
	CloseHandle(thread_snap_handle);
	return TRUE;
}
void inject_by_hook(HANDLE ProcessHandle, DWORD ProcessIdentity, wstring DllPath)
{
	TCHAR* dll_path = _tcsdup(DllPath.c_str());
	int    last_error = 0;
	std::vector<DWORD>   thread_identity;
	HHOOK hook_handle = NULL;
	FARPROC Sub_1 = NULL;
	HMODULE module_base = NULL;
	if (get_thread_id(ProcessIdentity, thread_identity) == FALSE) {
		last_error = GetLastError();
		goto Exit;
	}
	
	module_base = LoadLibrary((LPCWSTR)dll_path);
	if (module_base == NULL) {
		last_error = GetLastError();
		goto Exit;
	}
	Sub_1 = GetProcAddress(module_base, "Sub_1");
	if (Sub_1 == NULL) {
		last_error = GetLastError();
		goto Exit;
	}
	for (int i = 0; i < thread_identity.size(); ++i) {
		hook_handle = SetWindowsHookEx(WH_MOUSE, (HOOKPROC)Sub_1, module_base, (DWORD)thread_identity[i]);
		if (hook_handle != NULL) {
			break;
		}
	}
	_gettchar();
Exit:
	if (hook_handle != NULL) {
		UnhookWindowsHookEx(hook_handle);  //Remove Dll 
		hook_handle = NULL;
	}
	if (thread_identity.empty() == false) {
		std::vector<DWORD>().swap(thread_identity);    //vector<>stl  
	}
	if (!!(thread_identity.size())) {
		std::vector<DWORD>().swap(thread_identity);
	}
	if (module_base != NULL) {
		FreeLibrary(module_base);
		module_base = NULL;
	}
}
DWORD get_processid_by_imagename(const TCHAR* ProcessImageName)
{
	DWORD process_identity = 0;
	HANDLE snap_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap_handle == INVALID_HANDLE_VALUE)
	{
		_tprintf(_T("CreateToolhelp Failed!ErrorCode:%s"), GetLastError());
		return 0;
	}
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snap_handle, &pe32))
	{
		_tprintf(_T("Process32First Failed!ErrorCode:%s"), GetLastError());
		return 0;
	}
	do {
		if (_wcsicmp(pe32.szExeFile, ProcessImageName) == 0) {    //两个变量相等时_wcsicmp返回0
			process_identity = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(snap_handle, &pe32));

	CloseHandle(snap_handle);

	return process_identity;
}
