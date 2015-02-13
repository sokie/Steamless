
/**
 * Steamless Steam DRM Remover
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

#ifndef __PEFILE_H_INCLUDED__
#define __PEFILE_H_INCLUDED__

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <Windows.h>
#include <algorithm>
#include <string>
#include <vector>

class PEFile
{
    std::string                         m_File;
    unsigned char*                      m_FileData;
    unsigned int                        m_FileSize;

    IMAGE_DOS_HEADER                    m_DosHeader;
    IMAGE_NT_HEADERS                    m_NtHeaders;

    unsigned char*                      m_DosStub;
    unsigned int                        m_DosStubSize;
    unsigned int                        m_DosStubOffset;

    std::vector<IMAGE_SECTION_HEADER>   m_Sections;

public:
    PEFile(void);
    ~PEFile(void);

public:
    bool Initialize(const std::string& file);
    void Release(void);

    unsigned int GetDataPointer(void) const;
    unsigned int GetDataSize(void) const;

public:
    void GetDosHeader(IMAGE_DOS_HEADER* dosHeader) const;
    void GetNtHeaders(IMAGE_NT_HEADERS* ntHeaders) const;
    void GetDosStub(LPVOID lpBuffer, unsigned int size) const;
    unsigned int GetDosStubOffset(void) const;
    unsigned int GetDosStubSize(void) const;

public:
    unsigned int GetAlignment(unsigned int in, unsigned int align);

public:
    bool HasSection(const std::string& name);
    bool GetSection(const std::string& name, IMAGE_SECTION_HEADER* lpSection);
    bool GetSection(unsigned int index, IMAGE_SECTION_HEADER* lpSection);
    bool GetSections(std::vector<IMAGE_SECTION_HEADER>* sections);
    bool GetOwnerSection(unsigned int rva, IMAGE_SECTION_HEADER* lpSection);

public:
    LPVOID GetRvaFromVa(unsigned int va);
    LPVOID GetFilePointerFromRva(unsigned int rva);
};

#endif // __PEFILE_H_INCLUDED__
