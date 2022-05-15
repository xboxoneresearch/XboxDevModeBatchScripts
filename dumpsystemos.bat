::Get and parse current SystemOS version to create root dump folder.
for /f "tokens=2 delims=[]" %%x in ('ver') do set WINVER=%%x
set WINVER=%WINVER:Version =%
mkdir D:\DevelopmentFiles\%WINVER%

::Dump SystemOS from select drives, excluding things like the user xvd.
mkdir D:\DevelopmentFiles\%WINVER%\CDrive
mkdir D:\DevelopmentFiles\%WINVER%\XDrive
mkdir D:\DevelopmentFiles\%WINVER%\YDrive
mkdir D:\DevelopmentFiles\%WINVER%\SDrive
mkdir D:\DevelopmentFiles\%WINVER%\JDrive
mkdir D:\DevelopmentFiles\%WINVER%\MDrive
mkdir D:\DevelopmentFiles\%WINVER%\NDrive
xcopy C:\ D:\DevelopmentFiles\%WINVER%\CDrive /s /e /h /y
xcopy X:\ D:\DevelopmentFiles\%WINVER%\XDrive /s /e /h /y
xcopy Y:\ D:\DevelopmentFiles\%WINVER%\YDrive /s /e /h /y
xcopy S:\ D:\DevelopmentFiles\%WINVER%\SDrive /s /e /h /y
xcopy J:\ D:\DevelopmentFiles\%WINVER%\JDrive /s /e /h /y
xcopy M:\ D:\DevelopmentFiles\%WINVER%\MDrive /s /e /h /y
xcopy N:\ D:\DevelopmentFiles\%WINVER%\NDrive /s /e /h /y
