**This repo is no longer maintained,** and I'm unlikely to come back to it in the future.

-------

# ghidra-snes-loader
Loader for SNES ROMs.  Works with Ghidra v9.1 or later only.

## To Build and Install

Builds are done via Gradle, with the `GHIDRA_INSTALL_DIR` environment variable set to the path of
Ghidra installation.

Linux:
1. `cd` to the `SnesLoader` directory.
2. Run `GHIDRA_INSTALL_DIR='/some/absolute/path' ./gradlew buildExtension`.

Windows:
1. `cd` to the `SnesLoader` directory.
2. Run `set GHIDRA_INSTALL_DIR="C:\some\absolute\path" && gradlew.bat buildExtension`.

The built extension is in the `dist` directory.
Copy it into `GHIDRA_INSTALL_DIR/Extensions/Ghidra/`.

## To Develop with Eclipse

The repo doesn't contain any Eclipse project files, but we can generate them with Gradle.
If you have an Eclipse workspace with an older version of the project, remove the project from the
workspace before doing this.

Linux:
1. `cd` to the `SnesLoader` directory.
2. Run `GHIDRA_INSTALL_DIR='/some/absolute/path' ./gradlew cleanEclipse`.
3. Run `GHIDRA_INSTALL_DIR='/some/absolute/path' ./gradlew eclipse`.

Windows:
1. `cd` to the `SnesLoader` directory.
2. Run `set GHIDRA_INSTALL_DIR="C:\some\absolute\path" && gradlew.bat cleanEclipse`.
3. Run `set GHIDRA_INSTALL_DIR="C:\some\absolute\path" && gradlew.bat eclipse`.

Then in Eclipse: File --> Import --> Existing Projects into Workspace.
Select the `SnesLoader` directory.

Right-click the SnesLoader project in the project explorer, choose
GhidraDev --> Link Ghidra...
