@echo off
setlocal
set "CHERE_INVOKING=yes"
set "MSYSTEM=UCRT64"
"%~dp0.tools\msys64\usr\bin\bash.exe" -lc "export PATH=/ucrt64/bin:/usr/bin:$PATH; cd .codeql-build-full; make -j4"
exit /b %ERRORLEVEL%
