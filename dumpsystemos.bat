rmdir D:\DevelopmentFiles\sysosdump /s /q
mkdir D:\DevelopmentFiles\sysosdump
mkdir D:\DevelopmentFiles\sysosdump\CDrive
mkdir D:\DevelopmentFiles\sysosdump\XDrive
mkdir D:\DevelopmentFiles\sysosdump\YDrive
mkdir D:\DevelopmentFiles\sysosdump\SDrive
mkdir D:\DevelopmentFiles\sysosdump\JDrive
mkdir D:\DevelopmentFiles\sysosdump\MDrive
mkdir D:\DevelopmentFiles\sysosdump\NDrive
xcopy C:\ D:\DevelopmentFiles\sysosdump\CDrive /s /e /h /y
xcopy X:\ D:\DevelopmentFiles\sysosdump\XDrive /s /e /h /y
xcopy Y:\ D:\DevelopmentFiles\sysosdump\YDrive /s /e /h /y
xcopy S:\ D:\DevelopmentFiles\sysosdump\SDrive /s /e /h /y
xcopy J:\ D:\DevelopmentFiles\sysosdump\JDrive /s /e /h /y
xcopy M:\ D:\DevelopmentFiles\sysosdump\MDrive /s /e /h /y
xcopy N:\ D:\DevelopmentFiles\sysosdump\NDrive /s /e /h /y