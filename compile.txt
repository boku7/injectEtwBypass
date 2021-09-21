x86_64-w64-mingw32-gcc -m64 -mwindows -c injectEtwBypass.c -o injectEtwBypass.o -masm=intel -Wall -fno-asynchronous-unwind-tables -nostdlib -fno-ident -Wl,-Tlinker.ld,--no-seh
