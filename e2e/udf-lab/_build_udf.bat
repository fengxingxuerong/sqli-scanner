@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /LD /I "D:\mysql\include" udf_sys.c /link /OUT:udf_sys.dll
