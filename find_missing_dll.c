#include <windows.h>
#include <stdio.h>

int main() {
    const char* dlls[] = {
        "bcrypt.dll",
        "libiconv-2.dll",
        "KERNEL32.dll",
        "msvcrt.dll",
        "libwinpthread-1.dll",
        "USER32.dll",
        NULL
    };
    
    for (int i = 0; dlls[i] != NULL; i++) {
        HMODULE h = LoadLibraryA(dlls[i]);
        if (h == NULL) {
            DWORD err = GetLastError();
            printf("FAIL: LoadLibrary(%s) = NULL, error = %lu (0x%08lX)\n", dlls[i], err, err);
        } else {
            printf("OK:   LoadLibrary(%s) = %p\n", dlls[i], h);
            FreeLibrary(h);
        }
    }
    
    printf("\nNow trying to load the fuzzer executable...\n");
    
    // Try to create process
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    char cmdLine[] = "target_dec_h264_fuzzer_v4.exe";
    
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        printf("Process exit code: %lu (0x%08lX)\n", exitCode, exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        DWORD err = GetLastError();
        printf("CreateProcess failed: error = %lu (0x%08lX)\n", err, err);
    }
    
    return 0;
}