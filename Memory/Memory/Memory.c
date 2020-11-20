#include "pch.h"
#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <TlHelp32.h>

//[PROCESS STATE]
enum procState
{
	found = 0x1ui8,
	notFound = 0x0ui8
};
//[PROCESS STATE STRUCT]
typedef struct _processInfo
{
	__vcrt_bool state;
	HANDLE hproc;
	int pid;
	long long int module;
}_processInfo;
//[PTR READ FUNCTIONS]
typedef void (*ptr_read_byte)(_processInfo pi, long long int addr, unsigned char* var);
typedef void (*ptr_read_short)(_processInfo pi, long long int addr, short int* var);
typedef void (*ptr_read_int)(_processInfo pi, long long int addr, int* var);
typedef void (*ptr_read_long)(_processInfo pi, long long int addr, long long int* var);
typedef void (*ptr_read_float)(_processInfo pi, long long int addr, float* var);
typedef void (*ptr_read_double)(_processInfo pi, long long int addr, double* var);
typedef void (*ptr_read_bytes)(_processInfo pi, long long int addr, unsigned char* ref, int size);
//[PTR WRITE FUNCTIONS]
typedef void (*ptr_write_byte)(_processInfo pi, long long int addr, unsigned char val);
typedef void (*ptr_write_short)(_processInfo pi, long long int addr, short int val);
typedef void (*ptr_write_int)(_processInfo pi, long long int addr, int val);
typedef void (*ptr_write_long)(_processInfo pi, long long int addr, long long int val);
typedef void (*ptr_write_float)(_processInfo pi, long long int addr, float val);
typedef void (*ptr_write_double)(_processInfo pi, long long int addr, double val);
typedef void (*ptr_write_bytes)(_processInfo pi, long long int addr, unsigned char* ref, int size);
//[READ FUNCTIONS]
void func_read_byte(_processInfo pi, long long int addr, unsigned char* var);
void func_read_short(_processInfo pi, long long int addr, short int* var);
void func_read_int(_processInfo pi, long long int addr, int* var);
void func_read_long(_processInfo pi, long long int addr, long long int* var);
void func_read_float(_processInfo pi, long long int addr, float* var);
void func_read_double(_processInfo pi, long long int addr, double* var);
void func_read_bytes(_processInfo pi, long long int addr, unsigned char* ref, int size);
//[WRITE FUNCTIONS]
void func_write_byte(_processInfo pi, long long int addr, unsigned char val);
void func_write_short(_processInfo pi, long long int addr, short int val);
void func_write_int(_processInfo pi, long long int addr, int val);
void func_write_long(_processInfo pi, long long int addr, long long int val);
void func_write_float(_processInfo pi, long long int addr, float val);
void func_write_double(_processInfo pi, long long int addr, double val);
void func_write_bytes(_processInfo pi, long long int addr, unsigned char* ref, int size);
//[PROCESS INFO FUNCTION]
_processInfo getProcInfo(wchar_t* procName, wchar_t* moduleName);
//[READ STRUCT]
typedef struct _memoryReader
{
	ptr_read_byte typeof_byte;
	ptr_read_short typeof_short;
	ptr_read_int typeof_int;
	ptr_read_long typeof_long;
	ptr_read_float typeof_float;
	ptr_read_double typeof_double;
	ptr_read_bytes typeof_bytes;
}_memoryReader;
//[WRITE STRUCT]
typedef struct _memoryWriter
{
	ptr_write_byte typeof_byte;
	ptr_write_short typeof_short;
	ptr_write_int typeof_int;
	ptr_write_long typeof_long;
	ptr_write_float typeof_float;
	ptr_write_double typeof_double;
	ptr_write_bytes typeof_bytes;
}_memoryWriter;
//[MEMORY STRUCT]
typedef struct _memory
{
	_memoryReader* read;
	_memoryWriter* write;
}_memory;
//[INITIALIZE READ STRUCT]
_memoryReader mr =
{
	&func_read_byte,
	&func_read_short,
	&func_read_int,
	&func_read_long,
	&func_read_float,
	&func_read_double,
	&func_read_bytes
};
//[INITIALIZE WRITE STRUCT]
_memoryWriter mw =
{
	&func_write_byte,
	&func_write_short,
	&func_write_int,
	&func_write_long,
	&func_write_float,
	&func_write_double,
	&func_write_bytes
};
//[INITIALIZE MEMORY]
_memory mem =
{
	&mr,
	&mw
};
//[GET PROCESS INFO]
_processInfo getProcInfo(wchar_t* procName, wchar_t* moduleName)
{
	_processInfo _pi = { 0,NULL,0,0ui64 };
	PROCESSENTRY32W pEntry = { sizeof(PROCESSENTRY32W) };
	MODULEENTRY32W mEntry = { sizeof(MODULEENTRY32W) };
	HANDLE hSnapProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE hSnapM;

	if (hSnapProc == INVALID_HANDLE_VALUE) return _pi;

	if (Process32FirstW(hSnapProc, &pEntry))
	{
		do
		{
			if (!lstrcmpW(procName, pEntry.szExeFile))
			{
				_pi.state = found;
				_pi.pid = pEntry.th32ProcessID;
				_pi.hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _pi.pid);
				CloseHandle(hSnapProc);
				break;
			}
		} while (Process32NextW(hSnapProc, &pEntry));
	}

	if (moduleName != NULL && _pi.state == found)
	{
		hSnapM = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pi.pid);
		if (Module32FirstW(hSnapM, &mEntry))
		{
			do
			{
				if (!lstrcmpW((wchar_t*)mEntry.szModule, moduleName))
				{
					CloseHandle(hSnapM);
					_pi.module = (long long int) mEntry.modBaseAddr;
					break;
				}

			} while (Module32NextW(hSnapM, &mEntry));
		}
	}

	return _pi;
}
//[INITIALIZE READ FUNCTIONS]
void func_read_byte(_processInfo pi, long long int addr, unsigned char* var)
{
	if (pi.state == found) ReadProcessMemory(pi.hproc, (LPCVOID)addr, var, sizeof(unsigned char), 0);
}
void func_read_short(_processInfo pi, long long int addr, short int* var)
{
	if (pi.state == found) ReadProcessMemory(pi.hproc, (LPCVOID)addr, var, sizeof(short int), 0);
}
void func_read_int(_processInfo pi, long long int addr, int* var)
{
	if (pi.state == found) ReadProcessMemory(pi.hproc, (LPCVOID)addr, var, sizeof(int), 0);
}
void func_read_long(_processInfo pi, long long int addr, long long int* var)
{
	if (pi.state == found) ReadProcessMemory(pi.hproc, (LPCVOID)addr, var, sizeof(long long int), 0);
}
void func_read_float(_processInfo pi, long long int addr, float* var)
{
	if (pi.state == found) ReadProcessMemory(pi.hproc, (LPCVOID)addr, var, sizeof(float), 0);
}
void func_read_double(_processInfo pi, long long int addr, double* var)
{
	if (pi.state == found) ReadProcessMemory(pi.hproc, (LPCVOID)addr, var, sizeof(double), 0);
}
void func_read_bytes(_processInfo pi, long long int addr, unsigned char* ref, int size)
{
	if (pi.state == found) ReadProcessMemory(pi.hproc, (LPCVOID)addr, ref, size, 0);
}
//[INITIALIZE WRITE FUNCTIONS]
void func_write_byte(_processInfo pi, long long int addr, unsigned char val)
{
	if (pi.state == found) WriteProcessMemory(pi.hproc, (LPVOID)addr, &val, sizeof(unsigned char), 0);
}
void func_write_short(_processInfo pi, long long int addr, short int val)
{
	if (pi.state == found) WriteProcessMemory(pi.hproc, (LPVOID)addr, &val, sizeof(short int), 0);
}
void func_write_int(_processInfo pi, long long int addr, int val)
{
	if (pi.state == found) WriteProcessMemory(pi.hproc, (LPVOID)addr, &val, sizeof(int), 0);
}
void func_write_long(_processInfo pi, long long int addr, long long int val)
{
	if (pi.state == found) WriteProcessMemory(pi.hproc, (LPVOID)addr, &val, sizeof(long long int), 0);
}
void func_write_float(_processInfo pi, long long int addr, float val)
{
	if (pi.state == found) WriteProcessMemory(pi.hproc, (LPVOID)addr, &val, sizeof(float), 0);
}
void func_write_double(_processInfo pi, long long int addr, double val)
{
	if (pi.state == found) WriteProcessMemory(pi.hproc, (LPVOID)addr, &val, sizeof(double), 0);
}
void func_write_bytes(_processInfo pi, long long int addr, unsigned char* ref, int size)
{
	if (pi.state == found) WriteProcessMemory(pi.hproc, (LPVOID)addr, ref, size, 0);
}