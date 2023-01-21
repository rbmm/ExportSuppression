#define WIN32_LEAN_AND_MEAN
#define DECLSPEC_DEPRECATED_DDK

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _NO_CRT_STDIO_INLINE
#define _CRT_SECURE_CPP_OVERLOAD_SECURE_NAMES 0
#include <sdkddkver.h>
#include <windows.h>

#include <stdlib.h>
//#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#pragma warning(disable : 4706)

template <typename T>
T ToError(ULONG& dwError, T v)
{
	dwError = v ? NOERROR : GetLastError();
	return v;
}

#define GLE(x) ToError(dwError, x)

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

ULONG StartProcessWithES(PWSTR lpApplicationName)
{
	ULONG dwError;
	STARTUPINFOEXW si = { { sizeof(si)} };

	SIZE_T s = 0;
__c:
	switch (dwError = BOOL_TO_ERROR(InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &s)))
	{
	case ERROR_INSUFFICIENT_BUFFER:
		if (!si.lpAttributeList)
		{
			si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)alloca(s);
			goto __c;
		}
		break;
	case NOERROR:
		if (si.lpAttributeList)
		{
			ULONG64 mp = PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_EXPORT_SUPPRESSION;
			if (GLE(UpdateProcThreadAttribute(si.lpAttributeList, 0, 
				PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mp, sizeof(mp), 0, 0)))
			{
				PROCESS_INFORMATION pi;
				if (GLE(CreateProcessW(lpApplicationName, 0, 0, 0, 0, EXTENDED_STARTUPINFO_PRESENT, 0, 0, &si.StartupInfo, &pi)))
				{
					CloseHandle(pi.hThread);

					::PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY p;
					if (GLE(GetProcessMitigationPolicy(pi.hProcess, ::ProcessControlFlowGuardPolicy, &p, sizeof(p))))
					{
						WCHAR sz[128];

						if (0 < swprintf_s(sz, _countof(sz), L"CFG = %x\r\nES = %x\r\nSM = %x", 
							p.EnableControlFlowGuard, p.EnableExportSuppression, p.StrictMode))
						{
							WaitForInputIdle(pi.hProcess, INFINITE);
							MessageBoxW(0, sz, lpApplicationName, MB_ICONINFORMATION);
						}

						if (pi.hThread = GLE(CreateRemoteThread(pi.hProcess, 0, 0, (PTHREAD_START_ROUTINE)ExitThread, 0, 0, 0)))
						{
							CloseHandle(pi.hThread);
						}
					}

					CloseHandle(pi.hProcess);
				}
			}
		}
		break;
	}

	return dwError;
}

void WINAPI ep(void*)
{
	ULONG cch = 0;
	PWSTR lpApplicationName = 0;

	while (cch = ExpandEnvironmentStringsW(L"%systemroot%\\notepad.exe", lpApplicationName, cch))
	{
		if (lpApplicationName)
		{
			StartProcessWithES(lpApplicationName);
			break;
		}

		lpApplicationName = (PWSTR)alloca(cch * sizeof(WCHAR));
	}

	ExitProcess(0);
}