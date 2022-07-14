# iscsiscsicpl autoelevate DLL Search Order hijacking UAC Bypass 0day

The iscsicpl.exe binary is vulnerable to a DLL Search Order hijacking
vulnerability when running 32bit Microsoft binary on a 64bit host via
SysWOW64. The 32bit binary, will perform a search within user %Path%
for the DLL iscsiexe.dll. This can be exploited using a Proxy DLL to
execute code via "iscsicpl.exe" as autoelevate is enabled. This exploit
has been tested against the following versions of Windows desktop:

* Windows 11 Enterprise x64 (Version 10.0.22000.739).  
* Windows 8.1 Professional x64 (Version 6.3.9600).
