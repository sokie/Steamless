
/**
 * Steamless Steam DRM Remover - SteamStub_Variant2.h
 * (c) 2015 atom0s [atom0s@live.com]
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

#ifndef __STEAMSTUB32VARIANT2_H_INCLUDED__
#define __STEAMSTUB32VARIANT2_H_INCLUDED__

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#pragma comment(lib, "bea/BeaEngine.lib")
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL

#include <Windows.h>
#include "aes\aes.h"
#include "bea\BeaEngine.h"
#include "PEFile.h"
#include "Utils.h"

namespace SteamStub32Variant2
{
    /**
     * @brief The information block that holds the DRM information.
     */
    typedef struct tagSteamStub32Var2Header
    {
        unsigned int        XorKey;                     // The base XOR key, if defined, to unpack the file with.
        unsigned int        GetModuleHandleA_idata;     // The address of GetModuleHandleA inside of the .idata section.
        unsigned int        GetModuleHandleW_idata;     // The address of GetModuleHandleW inside of the .idata section.
        unsigned int        GetProcAddress_idata;       // The address of GetProcAddress inside of the .idata section.
        unsigned int        LoadLibraryA_idata;         // The address of LoadLibraryA inside of the .idata section.
        unsigned int        Unknown0000;                // Unknown (Was 0 when testing. Possibly LoadLibraryW.)
        unsigned int        BindSectionVirtualAddress;  // The virtual address to the .bind section.
        unsigned int        Unknown0001;
        unsigned int        Unknown0002;
        unsigned int        PayloadDataVirtualAddress;  // The virtual address to the payload data.
        unsigned int        PayloadDataSize;            // The size of the payload data.
        unsigned int        SteamAppID;                 // The steam application id of the packed file.
        unsigned int        Unknown0003;
        unsigned int        Unknown0004;
        unsigned int        Unknown0005;
        unsigned int        SteamDRMPDllVirtualAddress; // The offset inside of the payload data holding the virtual address to the SteamDRMP.dll file data.
        unsigned int        SteamDRMPDllSize;           // The offset inside of the payload data holding the size of the SteamDRMP.dll file data.
        unsigned int        XTeaKeys;                   // The offset inside of the payload data holding the address to the Xtea keys to decrypt the SteamDRMP.dll file.
        unsigned char       StubData[0x31C];            // Misc stub data, such as strings, error messages, etc.
    } SteamStub32Var2Header;

    /**
     * @brief Xor decrypts the given data starting with the given key, if any.
     *
     * @param data          The data to xor.
     * @param size          The size of the data to xor.
     * @param key           The starting key to xor with.
     *
     * @return The Xor key for any future data to decrypt.
     *
     * @note    If no key is given (0) then the first key is read from the first
     *          4 bytes inside of the data given.
     */
    unsigned int SteamXor(unsigned char* data, unsigned int size, unsigned int key = 0)
    {
        auto offset = 0;

        // Read the first key if none was given..
        if (key == 0)
        {
            offset += 4;
            key = *(unsigned int*)data;
        }

        // Decode the data..
        for (size_t x = offset; x < size; x += 4)
        {
            auto val = *(unsigned int*)(data + x);
            *(unsigned int*)(data + x) = val ^ key;
            key = val;
        }

        return key;
    }

    /**
     * @brief Xor's the given data starting with the given key, if any. Returns the new key.
     *
     * @param data          The data to xor.
     * @param size          The size of the data to xor.
     * @param key           The starting key to xor with.
     *
     * @return The Xor key for any future data to decrypt.
     */
    unsigned int SteamXorKeyCalc(unsigned char* data, unsigned int size, unsigned int key = 0)
    {
        for (size_t x = 0; x < size; ++x)
        {
            key ^= *(unsigned char*)(data + x) << 24;
            for (size_t y = 8; y > 0; --y)
            {
                if (key & 0x80000000)
                    key = 2 * key ^ 0x488781ED;
                else
                    key *= 2;
            }
        }

        return key;
    }

    /**
     * @brief The second pass of decryption for the SteamDRMP.dll file.
     *
     * @param res           The result value buffer to write our returns to.
     * @param keys          The keys used for the decryption.
     * @param v1            The first value to decrypt from.
     * @param v2            The second value to decrypt from.
     * @param n             The number of passes to crypt the data with.
     *
     * @note    The encryption method here is known as XTEA.
     */
    void SteamDrmpDecryptPass2(unsigned int res[], unsigned int* keys, unsigned int v1, unsigned int v2, unsigned int n = 32)
    {
        auto delta = 0x9E3779B9;
        auto mask = 0xFFFFFFFF;
        auto sum = (delta * n) & mask;

        for (size_t x = 0; x < n; x++)
        {
            v2 = (v2 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + keys[sum >> 11 & 3]))) & mask;
            sum = (sum - delta) & mask;
            v1 = (v1 - (((v2 << 4 ^ v2 >> 5) + v2) ^ (sum + keys[sum & 3]))) & mask;
        }

        res[0] = v1;
        res[1] = v2;
    }

    /**
     * @brief The first pass of the decryption for the SteamDRMP.dll file.
     *
     * @param data          The data to decrypt.
     * @param size          The size of the data to decrypt.
     * @param keys          The keys used for the decryption.
     *
     * @note    The encryption method here is known as XTEA. It is modded to include
     *          some basic xor'ing.
     */
    void SteamDrmpDecryptPass1(unsigned char* data, unsigned int size, unsigned int* keys)
    {
        auto v1 = 0x55555555;
        auto v2 = 0x55555555;

        for (size_t x = 0; x < size; x += 8)
        {
            auto d1 = *(unsigned int*)(data + x + 0);
            auto d2 = *(unsigned int*)(data + x + 4);

            unsigned int res[2] = { 0 };
            SteamDrmpDecryptPass2(res, keys, d1, d2, 32);

            *(unsigned int*)(data + x + 0) = res[0] ^ v1;
            *(unsigned int*)(data + x + 4) = res[1] ^ v2;

            v1 = d1;
            v2 = d2;
        }
    }

    /**
     * @brief Processes the given file for unpacking.
     *
     * @param file          The file being unpacked.
     * @param fileName      The original files full path.
     *
     * @return True on success, false otherwise.
     */
    bool ProcessFile(PEFile* file, const char* fileName)
    {
        // Obtain the current directory..
        char szCurrentDirectory[MAX_PATH] = { 0 };
        ::GetCurrentDirectory(MAX_PATH, szCurrentDirectory);

        // Obtain the NT headers..
        IMAGE_NT_HEADERS ntHeaders = { 0 };
        file->GetNtHeaders(&ntHeaders);

        // Obtain the entry point file offset..
        auto entryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
        auto fileOffset = file->GetFilePointerFromRva(entryPoint);

        // Validate the stub chunk..
        auto validation = *(unsigned int*)((unsigned char*)file->GetDataPointer() + ((unsigned int)fileOffset - 4));
        if (validation != 0xC0DEC0DE)
        {
            Console::output(Console::Colors::LightRed, "\n[*] ERROR: Failed to validate stub loader signature!\n");
            return false;
        }

        auto structOffset = 0;
        auto structSize = 0;
        auto structXorKey = 0;

        // Disassemble the file to locate the stubs information structure..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Disassembling the entry point to locate stub header pointer..\n");
        auto foundStubStruct = [&]() -> bool
        {
            // Prepare the BeaEngine disassembler..
            DISASM disasm = { 0 };
            memset(&disasm, 0x00, sizeof(DISASM));
            disasm.EIP = (size_t)((unsigned char*)file->GetDataPointer() + (unsigned int)fileOffset);

            // Disassemble the stub function to locate the needed data..
            while (true)
            {
                // Stop processing if we have found all our data..
                if (structOffset != 0 && structSize != 0 && structXorKey != 0)
                    return true;

                // Disassemble the curent opcode..
                auto len = Disasm(&disasm);
                if (len == UNKNOWN_OPCODE)
                    break;

                // Locate the first mov for our structure location.. (mov [ptr], val)
                if (structOffset == 0 && disasm.Instruction.Opcode == 0xC7 && disasm.Instruction.Immediat > 0)
                {
                    std::cout << Console::Colors::LightGreen << "    " << std::uppercase << std::hex << (disasm.EIP - (int)file->GetDataPointer()) << " :: " << disasm.CompleteInstr << std::endl;
                    structOffset = (int)disasm.Instruction.Immediat - ntHeaders.OptionalHeader.ImageBase;
                }

                // Locate the size of the structure..
                else if (disasm.Instruction.Opcode == 0xB9 && disasm.Instruction.Immediat > 0)
                {
                    std::cout << Console::Colors::LightGreen << "    " << std::uppercase << std::hex << (disasm.EIP - (int)file->GetDataPointer()) << " :: " << disasm.CompleteInstr << std::endl;
                    structSize = (int)disasm.Instruction.Immediat * 4;
                }

                // Locate the xor key..
                else if (disasm.Instruction.Opcode == 0xC7 && disasm.Instruction.Immediat > 0)
                {
                    std::cout << Console::Colors::LightGreen << "    " << std::uppercase << std::hex << (disasm.EIP - (int)file->GetDataPointer()) << " :: " << disasm.CompleteInstr << std::endl;
                    structXorKey = (int)disasm.Instruction.Immediat;
                }
                else
                    std::cout << Console::Colors::LightPurple << "    " << std::uppercase << std::hex << (disasm.EIP - (int)file->GetDataPointer()) << " :: " << disasm.CompleteInstr << std::endl;

                disasm.EIP += len;
            }

            return false;
        }();

        // Ensure the pointer to the stub structure was found..
        if (!foundStubStruct)
        {
            Console::output(Console::Colors::LightRed, "\n[*] ERROR: Failed to locate stub header pointer!\n");
            return false;
        }

        // Read the raw stub data..
        auto stubRaw = new unsigned char[structSize];
        memset(stubRaw, 0x00, structSize);
        memcpy(stubRaw, (unsigned char*)file->GetDataPointer() + (unsigned int)file->GetFilePointerFromRva(structOffset), structSize);

        // Decrypt the raw stub..
        auto xorKey = SteamXor(stubRaw, structSize, structXorKey);
        auto steamStub = (SteamStub32Var2Header*)stubRaw;

        // Obtain the payload data and decrypt it..
        auto payloadAddr = (unsigned char*)file->GetDataPointer() + (unsigned int)file->GetFilePointerFromRva((unsigned int)file->GetRvaFromVa(steamStub->PayloadDataVirtualAddress));
        auto payloadData = new unsigned char[steamStub->PayloadDataSize];
        memset(payloadData, 0x00, steamStub->PayloadDataSize);
        memcpy(payloadData, payloadAddr, steamStub->PayloadDataSize);
        SteamXor(payloadData, steamStub->PayloadDataSize);

        // Obtain the SteamDRMP.dll from the payload data..
        auto drmpAddr = (unsigned char*)file->GetDataPointer() + (unsigned int)file->GetFilePointerFromRva((unsigned int)file->GetRvaFromVa(*(unsigned int*)((unsigned char*)payloadData + steamStub->SteamDRMPDllVirtualAddress)));
        auto drmpSize = *(unsigned int*)((unsigned char*)payloadData + steamStub->SteamDRMPDllSize);
        auto drmpData = new unsigned char[drmpSize];
        memset(drmpData, 0x00, drmpSize);
        memcpy(drmpData, drmpAddr, drmpSize);

        // Obtain the XTea keys and decrypt the SteamDRMP.dll file..
        auto xteakeys = (unsigned int*)((unsigned char*)payloadData + steamStub->XTeaKeys);
        SteamDrmpDecryptPass1(drmpData, drmpSize, xteakeys);

        // Save the SteamDRMP.dll file to disk..
        char szDrmpFilePath[MAX_PATH] = { 0 };
        strcpy_s(szDrmpFilePath, szCurrentDirectory);
        strcat_s(szDrmpFilePath, "\\SteamDRMP.dll");

        FILE* f = nullptr;
        if (fopen_s(&f, szDrmpFilePath, "wb") == 0)
        {
            fwrite(drmpData, 1, drmpSize, f);
            fclose(f);
            f = nullptr;
        }
        else
            Console::output(Console::Colors::LightRed, "[*] ERROR: Failed to write SteamDRMP.dll to disk!\n");

        delete[] drmpData;

        // Todo .. rest of unpacking.
        // - Fix .text section
        // - Rebuild file..

        // Cleanup..
        delete[] payloadData;
        delete[] stubRaw;
        return true;
    }
}; // namespace SteamStub32Variant2

#endif // __STEAMSTUB32VARIANT2_H_INCLUDED__