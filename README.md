# OYDVAT for Linux

You need to switch to Windows to get OYDVAT? Nope, not anymore!\
This is correct, OYDVAT is now on Linux

# How to use
1. Install development libraries and GCC:\
\
Debian/Ubuntu:
```
sudo apt update
sudo apt install build-essential
```
Fedora:
```
sudo dnf groupinstall "Development Tools"
```
Arch Linux:
```
sudo pacman -Syu base-devel
```

2. Install CMake and Ninja:\
\
Debian/Ubuntu:
```
sudo apt update
sudo apt install cmake ninja-build
```
Fedora:
```
sudo dnf install cmake ninja-build
```
Arch Linux:
```
sudo pacman -S cmake ninja
```
3. Clone repo:
```
git clone --depth 1 -b oydvat-for-linux https://github.com/OYDVATTeam/OYDVAT
cd OYDVAT
```
the -b oydvat-for-linux part is ESSENTIAL, otherwise it would clone the Windows branch (main)

4. Configure and build:
```
mkdir build
cd build
cmake .. -G Ninja
ninja
```
And you're done compiling!\
Run it with:
```
./OYDVAT
```
    
