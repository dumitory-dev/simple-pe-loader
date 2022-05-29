#include <Windows.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "test_data.h"

using namespace std;

void custom_virtual_free(PBYTE ptr)
{
    ::VirtualFree(ptr, 0, MEM_RELEASE);
}

string read_all_file(const string& path)
{
    ifstream file { path, ios::binary };
    if (!file.is_open()) {
        throw exception("Error open file!");
    }
    return { istreambuf_iterator { file }, istreambuf_iterator<char> {} };
}

auto allocate_pe_section(const string& raw_data, const PIMAGE_NT_HEADERS nt_headers)
{
    const DWORD size_of_image = nt_headers->OptionalHeader.SizeOfImage;

    const auto handle = ::VirtualAlloc(nullptr, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!handle) {
        throw exception("Error VirtualAlloc!");
    }

    unique_ptr<BYTE, decltype(&custom_virtual_free)> smart_handle { static_cast<PBYTE>(handle), custom_virtual_free };
    const DWORD size_of_headers = nt_headers->OptionalHeader.SizeOfHeaders;
    memcpy(handle, raw_data.c_str(), size_of_headers);

    return smart_handle;
}

auto load_section(const string& raw_data, PBYTE image_base, const PIMAGE_NT_HEADERS nt_headers)
{
    const auto image_section = IMAGE_FIRST_SECTION(nt_headers);

    if (!image_section) {
        throw exception("Error get image first section!");
    }

    for (size_t i {}; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        PBYTE dest = image_base + image_section[i].VirtualAddress;
        if (image_section[i].SizeOfRawData)
            memcpy(dest, raw_data.c_str() + image_section[i].PointerToRawData, image_section[i].SizeOfRawData);
        else
            memset(dest, 0, image_section[i].Misc.VirtualSize);
    }

    return image_section;
}

auto fix_imports(PBYTE image_base, PIMAGE_NT_HEADERS nt_headers)
{
    PIMAGE_DATA_DIRECTORY data_directory = nt_headers->OptionalHeader.DataDirectory;
    const auto import_descriptors = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image_base + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; ++i) {
        const HMODULE import_module = ::LoadLibraryA(reinterpret_cast<const char*>(image_base + import_descriptors[i].Name));
        if (!import_module) {
            throw exception("Error LoadLibraryA!");
        }

        const auto lookup_table = reinterpret_cast<PIMAGE_THUNK_DATA>(image_base + import_descriptors[i].OriginalFirstThunk);

        /* we create a copy of the lookup table but we put the addresses of the loaded function (IAT) */
        const auto address_table = reinterpret_cast<PIMAGE_THUNK_DATA>(image_base + import_descriptors[i].FirstThunk);

        for (size_t j {}; lookup_table[j].u1.AddressOfData != 0; ++j) {

            FARPROC function_handle;

            if (DWORD lookup_addr = lookup_table[j].u1.AddressOfData; (lookup_addr & IMAGE_ORDINAL_FLAG) == 0) {
                /* import by name */
                const auto image_import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image_base + lookup_addr);
                const char* function_name = reinterpret_cast<char*>(&image_import->Name);
                function_handle = ::GetProcAddress(import_module, function_name);

            } else {
                function_handle = ::GetProcAddress(import_module, reinterpret_cast<LPSTR>(lookup_addr));
            }

            if (!function_handle) {
                throw exception("Error get function handler!");
            }

            address_table[j].u1.Function = reinterpret_cast<DWORD>(function_handle);
        }
    }

    return data_directory;
}

void fix_relocations(PBYTE image_base, PIMAGE_NT_HEADERS nt_headers, PIMAGE_DATA_DIRECTORY data_directory)
{
    const DWORD delta_va_reloc = reinterpret_cast<DWORD>(image_base) - nt_headers->OptionalHeader.ImageBase;

    if (nt_headers->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        return;

    if (data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 || delta_va_reloc == 0)
        return;

    auto p_reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image_base + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while (p_reloc->VirtualAddress != 0 && p_reloc->SizeOfBlock) {
        const DWORD size_blocks = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        const auto fixup = reinterpret_cast<PWORD>(p_reloc + 1);
        for (DWORD i {}; i < size_blocks; ++i) {
            // 4 first bits is information of type, 12 last bits is the offset
            const int type = fixup[i] >> 12;
            const int offset = fixup[i] & 0x0fff;
            const auto change_addr = reinterpret_cast<PDWORD>(image_base + p_reloc->VirtualAddress + offset);

            if (type == IMAGE_REL_BASED_HIGHLOW)
                *change_addr += delta_va_reloc;
        }
        p_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PDWORD>(p_reloc) + p_reloc->SizeOfBlock);
    }
}

void set_protect_permissions(PBYTE image_base, const PIMAGE_NT_HEADERS nt_headers, PIMAGE_SECTION_HEADER section_header)
{
    DWORD old_protect {};
    if (!VirtualProtect(image_base, nt_headers->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_protect)) {
        throw exception("Error VirtualProtect!");
    }

    for (WORD i {}; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        PBYTE dest = image_base + section_header[i].VirtualAddress;

        DWORD section_permission = section_header[i].Characteristics;
        DWORD protect_permission;

        if (section_permission & IMAGE_SCN_MEM_EXECUTE)
            protect_permission = section_permission & IMAGE_SCN_MEM_WRITE ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else
            protect_permission = section_permission & IMAGE_SCN_MEM_WRITE ? PAGE_READWRITE : PAGE_READONLY;

        ::VirtualProtect(dest, section_header[i].Misc.VirtualSize, protect_permission, &old_protect);
    }
}

void load_pe(string raw_file_data)
{
    const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(raw_file_data.data());
    const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(raw_file_data.data() + dos_header->e_lfanew);

    // check headers
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        throw exception("Error parse DOS header!");
    }

    if (const uint64_t res = raw_file_data.size() - sizeof(IMAGE_DOS_HEADER) - sizeof(IMAGE_OPTIONAL_HEADER);
        static_cast<uint64_t>(dos_header->e_lfanew) >= res) {
        throw exception("Error parse DOS header!");
    }

    const auto image_base = allocate_pe_section(raw_file_data, nt_headers);
    const auto image_sections = load_section(raw_file_data, image_base.get(), nt_headers);
    const auto image_data_directory = fix_imports(image_base.get(), nt_headers);
    fix_relocations(image_base.get(), nt_headers, image_data_directory);
    set_protect_permissions(image_base.get(), nt_headers, image_sections);
    const DWORD entry_point_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;

    // run pe
    reinterpret_cast<void (*)()>(image_base.get() + entry_point_rva)();
}

int main(const int argc, char** argv)
{
    try {
        string raw_data;

        if (argc != 3)
            raw_data = { std::begin(test_exe), std::end(test_exe) };
        else
            raw_data = read_all_file(argv[1]);

        load_pe(raw_data);
    } catch (const std::exception& error) {
        std::cerr << error.what();
    }
}