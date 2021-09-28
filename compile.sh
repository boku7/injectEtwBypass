x86_64-w64-mingw32-gcc -m64 -mwindows -c injectEtwBypass.c -o injectEtwBypass.o -masm=intel -Wall -fno-asynchronous-unwind-tables -nostdlib -fno-ident -Wl,-Tlinker.ld,--no-seh
echo "Succesfully compiled, you can load 'injectEtwBypass.cna' into Cobalt-Strike and use the command 'injectEtwBypass PID'"
