Sample Plugin: sample_hit_logger

What it does
- Demonstrates the DBI plugin ABI (`DBI/plugin_api.h`)
- Logs a message on load/unload and on some instruction hits

How to build (Visual Studio)
1. Create a new project: "Dynamic-Link Library (DLL)" (C++).
2. Add `sample_hit_logger.cpp` to the project.
3. Add include path so `DBI/plugin_api.h` is found:
   - C/C++ -> Additional Include Directories:
     `C:\Users\Acer\source\repos\DBI\DBI`
4. Build for the same architecture as the host (x64 or Win32).
5. Copy the built DLL next to the host EXE in a `plugins\` folder:
   - Debug x64: `C:\Users\Acer\source\repos\DBI\x64\Debug\plugins\`
   - Debug Win32: `C:\Users\Acer\source\repos\DBI\Win32\Debug\plugins\`
   - Release x64: `C:\Users\Acer\source\repos\DBI\x64\Release\plugins\`
   - Release Win32: `C:\Users\Acer\source\repos\DBI\Win32\Release\plugins\`

How to run
- Default: host loads `<exe_dir>\plugins\*.dll` automatically.
- Or explicit: `DBI.exe -p path\to\your.dll C:\Windows\System32\whoami.exe`
- Plugin command demo: `DBI.exe -c sample.ping`
