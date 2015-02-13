
/**
 * Steamless Steam DRM Remover - SteamStub_Variant3.h
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

#ifndef __STEAMSTUB32VARIANT3_H_INCLUDED__
#define __STEAMSTUB32VARIANT3_H_INCLUDED__

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <Windows.h>
#include "aes\aes.h"
#include "PEFile.h"
#include "Utils.h"

namespace SteamStub32Variant3
{
    /**
     * @brief The information block that holds the DRM information.
     */
    typedef struct tagSteamStub32Var3Header
    {
        unsigned int        XorKey;                     // The base XOR key, if defined, to unpack the file with.
        unsigned int        Signature;                  // 0xC0DEC0DE signature to validate this header is proper.
        unsigned int        ImageBase;                  // The base of the image that is protected.
        unsigned int        Unknown0000;                // Seems to always be 0.
        unsigned int        AddressOfEntryPoint;        // The entry point that is set from the DRM.
        unsigned int        BindSectionOffset;          // The starting offset to the bind section data. RVA(AddressOfEntryPoint - BindSectionOffset)
        unsigned int        Unknown0001;                // Unknown. Changes per-file. (Ranges have been 0x1000 -> 0x2000)
        unsigned int        OriginalEntryPoint;         // The original entry point of the binary before it was protected.
        unsigned int        Unknown0002;                // Seems to always be 0.
        unsigned int        PayloadSize;                // The size of the payload data.
        unsigned int        DRMPDLLOffset;              // The offset to the SteamDRMP.dll file.
        unsigned int        DRMPDLLSize;                // The size of the SteamDRMP.dll file.
        unsigned int        Unknown0003;
        unsigned int        Unknown0004;
        unsigned int        Unknown0005;
        unsigned int        Unknown0006;
        unsigned int        Unknown0007;                // Possible section alignment.
        unsigned int        TextSectionRawSize;         // The raw size of the text section.
        unsigned char       AES_Key[0x20];              // The AES encryption key.
        unsigned char       AES_IV[0x10];               // The AES encryption IV.
        unsigned char       TextSectionStolenData[0x10];// The first 16 bytes of the .text section stolen.
        unsigned int        EncryptionKeys[0x04];       // Encryption keys used for decrypting SteamDRMP.dll file.
        unsigned int        Unknown0008;
        unsigned int        Unknown0009;
        unsigned int        Unknown0010;
        unsigned int        Unknown0011;
        unsigned int        Unknown0012;
        unsigned int        Unknown0013;
        unsigned int        GetModuleHandleA_RVA;       // The RVA to GetModuleHandleA.
        unsigned int        GetModuleHandleW_RVA;       // The RVA to GetModuleHandleW.
        unsigned int        LoadLibraryA_RVA;           // The RVA to LoadLibraryA.
        unsigned int        LoadLibraryW_RVA;           // The RVA to LoadLibraryW.
        unsigned int        GetProcAddress_RVA;         // The RVA to GetProcAddress.
        unsigned int        Unknown0014;
        unsigned int        Unknown0015;
        unsigned int        Unknown0016;
    } SteamStub32Var3Header;

    /**
     * @brief Xor decrypts the given data starting with the given key, if any.
     *
     * @param data          The data to xor.
     * @param size          The size of the data to xor.
     * @param key           The starting key to xor with.
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

        // Obtain the SteamStub32Var3Header..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Obtaining SteamStub32Var3Header..\n");
        unsigned char steamStubRaw[sizeof(SteamStub32Var3Header)];
        memcpy(&steamStubRaw, (unsigned char*)(file->GetDataPointer() + ((unsigned int)fileOffset - 0xD0)), sizeof(steamStubRaw));
        auto key = SteamXor(steamStubRaw, sizeof(SteamStub32Var3Header));
        auto steamStub = *(SteamStub32Var3Header*)steamStubRaw;

        // Ensure the steam stub signature is valid..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Validating SteamStub32Var3Header..\n");
        if (steamStub.Signature != 0xC0DEC0DE)
        {
            Console::output(Console::Colors::LightRed, "[*] ERROR: Invalid steam stub header signature!\n");
            return false;
        }

        // Obtain the payload stub and decrypt it..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Obtaining payload stub (if it exists)..\n");
        auto payloadAddr = file->GetFilePointerFromRva(ntHeaders.OptionalHeader.AddressOfEntryPoint - steamStub.BindSectionOffset);
        auto payloadSize = (steamStub.PayloadSize + 0x0F) & 0xFFFFFFF0;

        if (payloadSize)
        {
            Console::output(Console::Colors::LightCyan, "[*] INFO: Payload exists; decrypted data is:\n");
            auto payload = new unsigned char[payloadSize];
            memset(payload, 0x00, payloadSize);
            memcpy(payload, (unsigned char*)file->GetDataPointer() + (unsigned int)payloadAddr, payloadSize);
            key = SteamXor(payload, payloadSize, key);
            Utils::DumpHexData(payload, payloadSize);
            delete[] payload;
        }

        // Obtain the SteamDRMP.dll and dump it..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Obtaining and dumping SteamDRMP.dll..\n");
        auto drmpAddr = file->GetFilePointerFromRva(ntHeaders.OptionalHeader.AddressOfEntryPoint - steamStub.BindSectionOffset + steamStub.DRMPDLLOffset);
        auto drmpData = new unsigned char[steamStub.DRMPDLLSize];
        memset(drmpData, 0x00, steamStub.DRMPDLLSize);
        memcpy(drmpData, (unsigned char*)file->GetDataPointer() + (unsigned int)drmpAddr, steamStub.DRMPDLLSize);
        SteamDrmpDecryptPass1(drmpData, steamStub.DRMPDLLSize, steamStub.EncryptionKeys);

        char szDrmpFilePath[MAX_PATH] = { 0 };
        strcpy_s(szDrmpFilePath, szCurrentDirectory);
        strcat_s(szDrmpFilePath, "\\SteamDRMP.dll");

        FILE* f = nullptr;
        if (fopen_s(&f, szDrmpFilePath, "wb") == 0)
        {
            fwrite(drmpData, 1, steamStub.DRMPDLLSize, f);
            fclose(f);
            f = nullptr;
        }
        else
            Console::output(Console::Colors::LightRed, "[*] ERROR: Failed to write SteamDRMP.dll to disk!\n");

        delete[] drmpData;

        // Obtain the .text section..
        IMAGE_SECTION_HEADER textSection = { 0 };
        file->GetSection(".text", &textSection);

        // Decrypt the key..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Decrypting the AES256 key..\n");
        unsigned char newIV[16] = { 0 };
        aes_decrypt_ctx ctxDec[1] = { 0 };
        aes_decrypt_key256(steamStub.AES_Key, ctxDec);
        aes_ecb_decrypt(steamStub.AES_IV, newIV, 16, ctxDec);

        // Calculate the buffer size and dump the .text section..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Obtaining the .text section data..\n");
        auto buffSize = textSection.SizeOfRawData + sizeof(steamStub.TextSectionStolenData);
        auto textAddr = file->GetFilePointerFromRva(textSection.VirtualAddress);
        auto textBuff = new unsigned char[buffSize];
        memset(textBuff, 0x00, buffSize);
        memcpy(textBuff, steamStub.TextSectionStolenData, sizeof(steamStub.TextSectionStolenData));
        memcpy(textBuff + sizeof(steamStub.TextSectionStolenData), (unsigned char*)file->GetDataPointer() + (unsigned int)textAddr, textSection.SizeOfRawData);

        // Decrypt the .text section data..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Decrypting the .text section data..\n");
        aes_encrypt_ctx ctxEnc[1] = { 0 };
        aes_cbc_decrypt(textBuff, textBuff, buffSize, newIV, ctxDec);

        // Rebuild the unpacked file..
        Console::output(Console::Colors::LightCyan, "[*] INFO: Rebuilding the new unpacked..\n");
        auto rebuildFile = [&]() -> bool
        {
            char szUnpackedPath[MAX_PATH] = { 0 };
            strcpy_s(szUnpackedPath, fileName);
            strcat_s(szUnpackedPath, ".unpacked.exe");

            // Open the new unpacked file for writing..
            if (fopen_s(&f, szUnpackedPath, "wb") != 0)
            {
                Console::output(Console::Colors::LightRed, "[*] ERROR: Failed to open new file for writing!\n");
                return false;
            }

            // Write the DOS header..
            Console::output(Console::Colors::LightCyan, "[*] INFO: Writing the DOS header..\n");
            IMAGE_DOS_HEADER dosHeader = { 0 };
            file->GetDosHeader(&dosHeader);
            fwrite(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, f);

            // Write the DOS stub (if it exists..)
            Console::output(Console::Colors::LightCyan, "[*] INFO: Writing the DOS stub (if exists)..\n");
            auto stubSize = file->GetDosStubSize();
            if (stubSize > 0)
            {
                auto stub = new unsigned char[stubSize];
                file->GetDosStub(stub, stubSize);
                fwrite(stub, stubSize, 1, f);
                delete[] stub;
            }

            // Obtain the sections..
            std::vector<IMAGE_SECTION_HEADER> sections;
            file->GetSections(&sections);

            // Obtain the NTHeaders and make adjustments..
            Console::output(Console::Colors::LightCyan, "[*] INFO: Writing the NT headers..\n");
            IMAGE_NT_HEADERS ntHeaders = { 0 };
            file->GetNtHeaders(&ntHeaders);
            ntHeaders.FileHeader.NumberOfSections--; // We are removing the .bind section..
            ntHeaders.OptionalHeader.AddressOfEntryPoint = steamStub.OriginalEntryPoint; // Reset the entry point..
            auto lastSection = sections[sections.size() - 2];
            ntHeaders.OptionalHeader.SizeOfImage = lastSection.VirtualAddress + lastSection.Misc.VirtualSize; // Fix the file size..
            fwrite(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, f);

            // Write the sections to the file..
            Console::output(Console::Colors::LightCyan, "[*] INFO: Processing the file sections..\n");
            for (auto& s : sections)
            {
                // Obtain the section data..
                auto sectionData = new unsigned char[s.SizeOfRawData];
                memcpy(sectionData, (char*)file->GetDataPointer() + (DWORD)file->GetFilePointerFromRva(s.VirtualAddress), s.SizeOfRawData);

                // Skip the bind section..
                if (!_stricmp((const char*)s.Name, ".bind"))
                    continue;

                // Write the section header..
                Console::output(Console::Colors::LightCyan, "[*] INFO: Writing section header for section: %s..\n", s.Name);
                fwrite(&s, sizeof(IMAGE_SECTION_HEADER), 1, f);

                Console::output(Console::Colors::LightCyan, "[*] INFO: Writing section data for section: %s..\n", s.Name);
                auto sectionOffset = ftell(f);
                fseek(f, s.PointerToRawData, SEEK_SET);
                if (!_stricmp((const char*)s.Name, ".text"))
                    fwrite(textBuff, buffSize, 1, f);
                else
                    fwrite(sectionData, 1, s.SizeOfRawData, f);
                fseek(f, sectionOffset, SEEK_SET);

                // Cleanup the section data..
                delete[] sectionData;
            }

            // Close the file and return..
            fclose(f);
            return true;
        }();

        // Cleanup and return..
        delete[] textBuff;
        return rebuildFile;
    }
}; // namespace SteamStub32Variant3

#endif // __STEAMSTUB32VARIANT3_H_INCLUDED__