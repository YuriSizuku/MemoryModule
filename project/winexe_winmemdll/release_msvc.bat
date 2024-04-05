msbuild %~dp0\winmemdll.sln -t:winmemdll:rebuild -p:configuration=release -p:Platform=x86 
msbuild %~dp0\winmemdll.sln -t:winmemdll:rebuild -p:configuration=release -p:Platform=x64