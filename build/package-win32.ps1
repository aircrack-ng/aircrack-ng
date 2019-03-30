#######################################################################
#
# Copyright (C) 2018 Joseph Benden <joe@benden.us>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.
# 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#######################################################################
#
# Requirements:
#   - Microsoft Visual Studio 2017 Community is installed.
#   - Cygwin; both 32-bit and 64-bit.
#   - All Cygwin dependencies are installed in both 32-bit and in
#     64-bit versions.
#   - Airpcap is extracted in the root of the project.
#   - The working directory is the root of the project.
#   - Assumes utilities are installed in AppVeyor-specific
#     locations. (Mostly default installation locations.)
#
# Running the script:
#
#   powershell -File package-win32.ps1
#
#######################################################################

$env:CHERE_INVOKING = 1

$env:AIRPCAP = c:\cygwin\bin\bash.exe -e -l -c "/bin/cygpath -u `'$(Get-Location)`'"
$env:MSBUILD = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\MSBuild.exe"

$REV = c:\cygwin\bin\bash.exe -e -l -c "./evalrev"
$env:DIST = "aircrack-ng-$REV-win"

Write-Host -ForegroundColor Blue "Creating dist folder: $env:DIST"

if ((Test-Path -Path "src\.deps")) {
    Write-Host -ForegroundColor Blue "Running distclean"
    c:\cygwin\bin\bash.exe -e -l -c "/bin/make distclean"
}

if ((Test-Path -Path "$env:DIST")) {
    Write-Host -ForegroundColor Blue "Removing existing dist folder."
    Remove-Item -Recurse -Force $env:DIST
}

Write-Host -ForegroundColor Blue "Creating pristine sources"
c:\cygwin\bin\bash.exe -e -l -c "git archive --format=tar --prefix=`"$env:DIST/`" HEAD | /bin/tar xf -"
if ($LASTEXITCODE -ne 0) {
    Write-Host -ForegroundColor Red "Failed to create pristine sources!"
    Break
}

Write-Host -ForegroundColor Blue "Running autoreconf"
c:\cygwin\bin\bash.exe -e -l -c "/bin/autoreconf -vi" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host -ForegroundColor Red "Failed to run autoreconf!"
    Break
}

Write-Host -ForegroundColor Blue "Building 32-bit binaries"
$b32 = @"
#!/bin/bash
set -eufx
[ -d 32bit ] && rm -fr 32bit
mkdir 32bit
cd 32bit
env CFLAGS="-O3 -mtune=i686 -DNDEBUG" LDFLAGS="-Wl,--enable-auto-image-base" ../configure --host=i686-pc-cygwin --target=i686-pc-cygwin --with-experimental --with-airpcap=$env:AIRPCAP --enable-win32-portable
/bin/make V=1
"@
$b32.Replace("`r`n","`n") | Set-Content -Path 32build.sh -Force
c:\cygwin\bin\bash.exe -e -l -c "/bin/chmod +x 32build.sh && ./32build.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host -ForegroundColor Red "Failed to build 32-bit binaries!"
    Break
}

Write-Host -ForegroundColor Blue "Building 64-bit binaries"
$b64 = @"
#!/bin/bash
set -eufx
[ -d 64bit ] && rm -fr 64bit
mkdir 64bit
cd 64bit
env CFLAGS="-O3 -mtune=opteron -DNDEBUG" LDFLAGS="-Wl,--enable-auto-image-base" ../configure --host=x86_64-pc-cygwin --target=x86_64-pc-cygwin --with-experimental --with-airpcap=$env:AIRPCAP --enable-win32-portable
/bin/make V=1
"@
$b64.Replace("`r`n","`n") | Set-Content -Path 64build.sh -Force
c:\cygwin64\bin\bash.exe -e -l -c "/bin/chmod +x 64build.sh && ./64build.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host -ForegroundColor Red "Failed to build 64-bit binaries!"
    Break
}

Write-Host -ForegroundColor Blue "Cloning GUI tools"
if ((Test-Path -Path "gui")) {
    Write-Host -ForegroundColor Blue "Removing existing gui folder."
    Remove-Item -Recurse -Force gui
}
git clone --no-checkout --depth 1 --single-branch --branch Windows https://github.com/aircrack-ng/aircrack-ng.git gui
Push-Location gui
git reset --hard
Pop-Location

c:\cygwin\bin\bash.exe -e -l -c "/bin/rsync -a gui/ `"$env:DIST/src`" && /bin/rm -fr `"$env:DIST/src/.git`" `"$env:DIST/.gitignore`" `"$env:DIST/appveyor.yml`" `"$env:DIST/.travis.yml`" `"$env:DIST/README.md`" `"$env:DIST/.github`" `"$env:DIST/patches`" `"$env:DIST/apparmor`""

Push-Location gui/GUI
& "$env:MSBUILD" Aircrack-ng.sln /p:Configuration=Release /p:Platform="Any CPU"
if ($LASTEXITCODE -ne 0) {
    Write-Host -ForegroundColor Red "Failed to build GUI!"
    Pop-Location
    Break
}
Pop-Location

if ((Test-Path -Path "$env:DIST.zip")) {
    Write-Host -ForegroundColor Blue "Removing existing ZIP file."
    Remove-Item -Force "$env:DIST.zip"
}

$pkg = @"
#!/bin/bash
set -eufx

mkdir "$env:DIST/bin"
mkdir "$env:DIST/bin/32bit"
mkdir "$env:DIST/bin/64bit"

cp -pr "gui/GUI/Aircrack-ng/bin/Release/Aircrack-ng GUI.exe" $env:DIST/bin

find 32bit -path "*/.libs" -print0 | xargs -0I [] -n 1 find [] \( -name "*.exe" -o -name "*.dll" \) -exec cp -p {} "$env:DIST/bin/32bit" ';'
find 64bit -path "*/.libs" -print0 | xargs -0I [] -n 1 find [] \( -name "*.exe" -o -name "*.dll" \) -exec cp -p {} "$env:DIST/bin/64bit" ';'

# AirPcap DLLs
cp -p "Airpcap_Devpack/bin/x86/airpcap.dll" "$env:DIST/bin/32bit"
cp -p "Airpcap_Devpack/bin/x64/airpcap.dll" "$env:DIST/bin/64bit"

# Cygwin License
cp /usr/share/doc/Cygwin/CYGWIN_LICENSE "$env:DIST/LICENSE.Cygwin"

# gather dependencies of Cygwin
FILES="cygcrypto-1.1.dll cyghwloc-15.dll cyggcc_s-1.dll cyggcc_s-seh-1.dll cygpcre-1.dll cygsqlite3-0.dll cygstdc++-6.dll cygwin1.dll cygz.dll cygxml2-2.dll cyglzma-5.dll cygiconv-2.dll"

for FILE in `$FILES; do
    cp -p "/cygdrive/c/cygwin/bin/`$FILE" "$env:DIST/bin/32bit" || :
    cp -p "/cygdrive/c/cygwin64/bin/`$FILE" "$env:DIST/bin/64bit" || :
done

"$env:DIST/bin/32bit/aircrack-ng" -u
rc=`$("$env:DIST/bin/32bit/aircrack-ng" --simd-list | wc -c)
if [ `$rc -ne 22 ]; then
	echo "The expected number of SIMD engines are NOT present in 32-bit binary."
	exit 1
fi

"$env:DIST/bin/64bit/aircrack-ng" -u
rc=`$("$env:DIST/bin/64bit/aircrack-ng" --simd-list | wc -c)
if [ `$rc -ne 22 ]; then
	echo "The expected number of SIMD engines are NOT present in 64-bit binary."
	exit 1
fi

zip -o -v -9 -r "$env:DIST.zip" "$env:DIST"
( cat README; echo; echo . ) | zip -z "$env:DIST.zip"
exit 0
#
#
"@
$pkg.Replace("`r`n","`n") | Set-Content -Path pkg.sh -Force
c:\cygwin\bin\bash.exe -e -l -c "/bin/chmod +x pkg.sh && ./pkg.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host -ForegroundColor Red "Failed to package!"
    Break
}

Write-Host -ForegroundColor Green "Packaging successful!"
