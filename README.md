## Cobalt Strike BOF - Inject ETW Bypass
Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)

#### Running InjectEtwBypass BOF from CobaltStrike to Bypass ETW in Notepad.exe
  ![](images/injectEtw.png)

## Build (Only tested from macOS at the moment)
1. Run the compile-x64.sh shell script after installling required dependencies
```bash
# Install brew on macOS if you need it (https://brew.sh/)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Install Ming using Brew
brew install mingw-w64
# Clone this Reflective DLL project from this github repo
git clone https://github.com/boku7/CobaltStrikeReflectiveLoader.git
# Compile the ReflectiveLoader Object file
cd CobaltStrikeReflectiveLoader/
cat compile.sh
x86_64-w64-mingw32-gcc -m64 -mwindows -c injectEtwBypass.c -o injectEtwBypass.o -masm=intel -Wall -fno-asynchronous-unwind-tables -nostdlib -fno-ident -Wl,-Tlinker.ld,--no-seh
bash compile.sh
```

## Credits / References
### ETW Bypass (Mass Credits to [Adam Chester (@\_xpn\_) of TrustedSec](https://twitter.com/_xpn_) 
+ [@\_xpn\_ Hiding Your .NET – ETW](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/)
+ [ajpc500/BOFs](https://github.com/ajpc500/BOFs/)
+ [Offensive Security OSEP](https://www.offensive-security.com/pen300-osep/)
### HalosGate SysCaller
+ Reenz0h from @SEKTOR7net
  + Most of the C techniques I use are from Reenz0h's awesome courses and blogs 
  + Best classes for malware development out there.
  + Creator of the halos gate technique. His work was the motivation for this work.
  + [Sektor7 HalosGate Blog](https://blog.sektor7.net/#!res/2021/halosgate.md)
### HellsGate Syscaller
+ @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique )
  + Could not have made my implementation of HellsGate without them :)
  + Awesome work on this method, really enjoyed working through it myself. Thank you!
  + https://github.com/am0nsec/HellsGate 
  + Link to the [Hell's Gate paper: https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf](https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf)
### Great Resource for learning Intel ASM
+ [Pentester Academy - SLAE64](https://www.pentesteracademy.com/course?id=7)
### Implementing ASM in C Code with GCC
+ [Outflank - Direct Syscalls in Beacon Object Files](https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/)
+ https://www.cs.uaf.edu/2011/fall/cs301/lecture/10_12_asm_c.html
+ http://gcc.gnu.org/onlinedocs/gcc-4.0.2/gcc/Extended-Asm.html#Extended-Asm
