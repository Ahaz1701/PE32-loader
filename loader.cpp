#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winnt.h>

void failure(const char* err);
char* pe_data(const char* file);
void* load_pe(char* pe_data);
void load_sections(char* data, char* img_base, PIMAGE_SECTION_HEADER sections, size_t nb_sections);
void load_imports(char* img_base, PIMAGE_IMPORT_DESCRIPTOR imp_descriptor);
void relocations(char* img_base, DWORD rva_reloc, PIMAGE_BASE_RELOCATION base_reloc);
void load_perms(char* img_base, PIMAGE_SECTION_HEADER sections, WORD nb_sections, DWORD hdrs_size);

int main(int argc, char* argv[]) {
    const char* pe = "C:\\Windows\\SysWOW64\\calc.exe";
    // const char* pe = "C:\\Users\\ahaz1\\OneDrive\\Documents\\Personnel\\hello_world\\x64\\Debug\\hello_world.exe";
    
    char* data = pe_data(pe);
    void* ep   = load_pe(data);

    if (!ep) failure("Panic");
    ((void (*)(void)) ep)();
    
    return EXIT_SUCCESS;
}

void failure(const char* err) {
    fprintf(stderr, "\n%s\n", err);
    exit(EXIT_FAILURE);
}

char* pe_data(const char* pe) {
    FILE* fp;
    if (fopen_s(&fp, pe, "rb") != 0) failure("fopen_s failed");

    fseek(fp, 0L, SEEK_END);
    long size = ftell(fp);
    if (size == -1L) failure("ftell failed");
    fseek(fp, 0L, SEEK_SET);

    char* data = (char*)malloc(sizeof(char) * size + 1);
    if (!data) failure("malloc failed");

    if (fread(data, 1, size, fp) != size) failure("fread failed");
    fclose(fp);

    return data;
}

void* load_pe(char* data) {
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)data;
    PIMAGE_NT_HEADERS32 nt_hdr = (PIMAGE_NT_HEADERS32)(((char*)dos_hdr + dos_hdr->e_lfanew)); // 32 bits
    // PIMAGE_NT_HEADERS64 nt_hdr = (PIMAGE_NT_HEADERS64)(((char*)dos_hdr + dos_hdr->e_lfanew)); // 64 bits

    // CHECK FILE FORMAT
    if (dos_hdr->e_magic  != IMAGE_DOS_SIGNATURE ||
        nt_hdr->Signature != IMAGE_NT_SIGNATURE) failure("This is not a PE");

    DWORD img_size   = nt_hdr->OptionalHeader.SizeOfImage;
    DWORD rva_ep       = nt_hdr->OptionalHeader.AddressOfEntryPoint;
    DWORD hdrs_size = nt_hdr->OptionalHeader.SizeOfHeaders;
    WORD nb_sections   = nt_hdr->FileHeader.NumberOfSections;

    // DEBUG START
    // printf("\nSize of image: 0x%X\n", img_size);
    // printf("Address of entry point: 0x%X\n", rva_ep);
    // printf("Size of headers: 0x%X\n", hdrs_size);
    // printf("Number of sections: 0x%X\n", nb_sections);
    // DEBUG END
    
    // MAP PE INTO MEMORY
    char* img_base = (char*)VirtualAlloc(NULL, img_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!img_base) failure("VirtualAlloc failed");
    memcpy(img_base, data, hdrs_size);

    // LOAD SECTIONS
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(data + dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS32)); // 32 bits
    // PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(data + dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS64)); // 64 bits
    load_sections(data, img_base, sections, nb_sections);

    // LOAD IMPORT DIRECTORY
    PIMAGE_DATA_DIRECTORY data_dir = (PIMAGE_DATA_DIRECTORY)nt_hdr->OptionalHeader.DataDirectory;
    PIMAGE_IMPORT_DESCRIPTOR imp_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(img_base + data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    load_imports(img_base, imp_descriptor);

    // RELOCATIONS
    DWORD rva_reloc = (DWORD)img_base - nt_hdr->OptionalHeader.ImageBase;
    if (rva_reloc && data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        PIMAGE_BASE_RELOCATION base_reloc = (PIMAGE_BASE_RELOCATION)(img_base + data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        relocations(img_base, rva_reloc, base_reloc);
    }

    load_perms(img_base, sections, nb_sections, hdrs_size);

    return (void*)(img_base + rva_ep);
}

void load_sections(char* data, char* img_base, PIMAGE_SECTION_HEADER sections, size_t nb_sections) {
    char *dest, *src;
    size_t size, v_size ;

    for (size_t i = 0; i < nb_sections; i++) {
        dest = img_base + sections[i].VirtualAddress;
        src  = data + sections[i].PointerToRawData;

        size   = (size_t)sections[i].SizeOfRawData;
        v_size = (size_t)sections[i].Misc.VirtualSize;

        // DEBUG START
        // printf("\n%.8s:\n", sections[i].Name);
        // printf("VirtualAddress: 0x%X\n", sections[i].VirtualAddress);
        // printf("SizeOfRawData: 0x%X\n", sections[i].SizeOfRawData);
        // printf("PointerToRawData: 0x%X\n", sections[i].PointerToRawData);
        // DEBUG END

        if (size > 0) memcpy(dest, src, size);
        else memset(dest, 0, v_size);
    }
}

void load_imports(char* img_base, PIMAGE_IMPORT_DESCRIPTOR imp_descriptor) {
    char* dll_name;
    HMODULE dll;

    PIMAGE_THUNK_DATA32 idt, iat; // 32 bits
    // PIMAGE_THUNK_DATA64 idt, iat; // 64 bits
    DWORD funct_addr, funct_handle;
    PIMAGE_IMPORT_BY_NAME funct_name = NULL;

    for (size_t i = 0; imp_descriptor[i].OriginalFirstThunk; i++) {
        // DEBUG START
        dll_name = img_base + imp_descriptor[i].Name;
        // printf("\n%s:\n", dll_name);
        // DEBUG END

        dll = LoadLibraryA(dll_name);
        if (!dll) failure("LoadLibraryA failed");

        idt = (PIMAGE_THUNK_DATA32)(img_base + imp_descriptor[i].OriginalFirstThunk); // 32 bits
        iat = (PIMAGE_THUNK_DATA32)(img_base + imp_descriptor[i].FirstThunk); // 32 bits
        // idt = (PIMAGE_THUNK_DATA64)(img_base + imp_descriptor[i].OriginalFirstThunk); // 64 bits
        // iat = (PIMAGE_THUNK_DATA64)(img_base + imp_descriptor[i].FirstThunk); // 64 bits
        
        for (size_t j = 0; idt[j].u1.AddressOfData; j++) {
            funct_addr = idt[j].u1.AddressOfData;

            if (funct_addr & IMAGE_ORDINAL_FLAG32) funct_handle = (DWORD)GetProcAddress(dll, (LPCSTR)funct_addr); // 32 bits
            // if (funct_addr & IMAGE_ORDINAL_FLAG64) funct_handle = (DWORD)GetProcAddress(dll, (LPCSTR)funct_addr); // 64 bits
            else {
                funct_name   = (PIMAGE_IMPORT_BY_NAME)(img_base + funct_addr);
                funct_handle = (DWORD)GetProcAddress(dll, (LPCSTR)&funct_name->Name);
            }

            // DEBUG START
            // printf("\n%s:\nFunction: %s\nAddress: 0x%X\n", dll_name, funct_name->Name, funct_addr);
            // DEBUG END

            if (!funct_handle) {
                // DEBUG START
                // printf("\n%s:\nFunction: %s\nAddress: 0x%X\n", dll_name, funct_name->Name, funct_addr);
                // DEBUG END

                // failure("GetProcAddress failed");
            }

            iat[j].u1.Function = funct_handle;
        }
    }
}

void relocations(char* img_base, DWORD rva_reloc, PIMAGE_BASE_RELOCATION base_reloc) {
    DWORD block_size, *new_addr;
    PWORD reloc;
    int type, offset;

    while (base_reloc->VirtualAddress) {
        block_size = (base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        reloc      = (PWORD)(base_reloc + 1);

        for (size_t i = 0; i < block_size; i++) {
            type   = reloc[i] >> 12;
            offset = reloc[i] & 0x0fff;

            new_addr = (PDWORD)(img_base + base_reloc->VirtualAddress + offset);

            if (type == IMAGE_REL_BASED_HIGHLOW) *new_addr += rva_reloc;
        }

        // DEBUG START
        // printf("%X\n", *base_reloc);
        base_reloc = (PIMAGE_BASE_RELOCATION)((DWORD)base_reloc + base_reloc->SizeOfBlock);
        // printf("%X\n", *base_reloc);
        // DEBUG END
    }
}

void load_perms(char* img_base, PIMAGE_SECTION_HEADER sections, WORD nb_sections, DWORD hdrs_size) {
    DWORD lpflOldProtect, s_perm;
    char* dest;
    size_t v_size, v_perm;

    if (!VirtualProtect(img_base, hdrs_size, PAGE_READONLY, &lpflOldProtect)) failure("VirtualProtect failed #1");

    for (size_t section = 0; section < nb_sections; section++) {
        dest = img_base + sections[section].VirtualAddress;
        v_size = (size_t)sections[section].Misc.VirtualSize;
        s_perm = sections[section].Characteristics;

        // READ: 2
        // WRITE: 2
        // EXECUTE: 16
        v_perm = 1;
        if (s_perm & IMAGE_SCN_MEM_READ)    v_perm *= 0x2;
        if (s_perm & IMAGE_SCN_MEM_WRITE)   v_perm *= 0x2;
        if (s_perm & IMAGE_SCN_MEM_EXECUTE) v_perm *= 0x10;

        if (!VirtualProtect(dest, v_size, v_perm, &lpflOldProtect)) failure("VirtualProtect failed #2");
    }
}
