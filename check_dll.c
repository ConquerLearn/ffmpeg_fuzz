#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: check_dll.exe <program.exe>\n");
        return 1;
    }
    
    // Disable the error dialog
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    
    // Try to load the executable as a DLL to check its dependencies
    HMODULE hMod = LoadLibraryExA(argv[1], NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hMod == NULL) {
        DWORD err = GetLastError();
        printf("LoadLibraryEx failed: error %lu (0x%08lX)\n", err, err);
        
        // Try to get more specific error info
        LPSTR msgBuf = NULL;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msgBuf, 0, NULL);
        if (msgBuf) {
            printf("Error message: %s\n", msgBuf);
            LocalFree(msgBuf);
        }
        return 1;
    }
    
    printf("LoadLibraryEx succeeded: handle = %p\n", hMod);
    FreeLibrary(hMod);
    return 0;
}