
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

#include "PEFile.h"

/**
 * @brief Constructor / Deconstructor
 */
PEFile::PEFile(void)
    : m_File("")
    , m_FileData(nullptr)
    , m_DosStub(nullptr)
    , m_DosStubSize(0)
    , m_DosStubOffset(0)
{ }
PEFile::~PEFile(void)
{
    // Ensure we are cleaned up..
    this->Release();
}

/**
 * @brief Initializes this pe file reader by loading the given file.
 *
 * @param file      The file to load.
 *
 * @return True on success, false otherwise.
 */
bool PEFile::Initialize(const std::string& file)
{
    // Attempt to open the file for reading..
    FILE* f = NULL;
    if (fopen_s(&f, file.c_str(), "rb") != ERROR_SUCCESS)
        return false;

    // Obtain the file size..
    fseek(f, 0, SEEK_END);
    auto size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Validate the size of the file is able to be a .exe..
    if (size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
    {
        fclose(f);
        return false;
    }

    // Read the file data locally..
    this->m_FileData = new unsigned char[size];
    fread(this->m_FileData, 1, size, f);
    fclose(f);

    // Read the dos header..
    memcpy(&this->m_DosHeader, this->m_FileData, sizeof(IMAGE_DOS_HEADER));
    if (this->m_DosHeader.e_magic != 0x5A4D)
    {
        this->Release();
        return false;
    }

    // Read the nt headers..
    memcpy(&this->m_NtHeaders, (char*)this->m_FileData + this->m_DosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS));
    if (this->m_NtHeaders.Signature != 0x4550)
    {
        this->Release();
        return false;
    }

    // Read the dos stub, if the file contains one..
    this->m_DosStubSize = this->m_DosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
    this->m_DosStubOffset = sizeof(IMAGE_DOS_HEADER);

    if (this->m_DosStubSize > 0)
    {
        this->m_DosStub = new unsigned char[this->m_DosStubSize];
        if ((this->m_DosStubSize & 0x80000000) == 0x00000000)
            memcpy(this->m_DosStub, (char*)this->m_FileData + this->m_DosStubOffset, this->m_DosStubSize);
    }

    // Read the file sections..
    for (auto x = 0; x < this->m_NtHeaders.FileHeader.NumberOfSections; x++)
    {
        auto section = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)((char*)this->m_FileData + this->m_DosHeader.e_lfanew)) + x;

        IMAGE_SECTION_HEADER s = { 0 };
        memcpy(&s, section, sizeof(IMAGE_SECTION_HEADER));
        this->m_Sections.push_back(s);
    }

    this->m_File = file;
    this->m_FileSize = size;
    return true;
}

/**
 * @brief Releases this files data and cleans up.
 */
void PEFile::Release(void)
{
    // Cleanup the headers..
    memset(&this->m_DosHeader, 0x00, sizeof(IMAGE_DOS_HEADER));
    memset(&this->m_NtHeaders, 0x00, sizeof(IMAGE_NT_HEADERS));

    // Cleanup the sections..
    this->m_Sections.clear();

    // Cleanup the file data..
    if (this->m_FileData != nullptr)
        delete[] this->m_FileData;
    this->m_FileData = nullptr;

    // Cleanup the dos stub..
    if (this->m_DosStub != nullptr)
        delete[] this->m_DosStub;
    this->m_DosStub = nullptr;
    this->m_DosStubOffset = 0;
    this->m_DosStubSize = 0;
}

/**
 * @brief Returns the internal file datas pointer.
 *
 * @return The internal file data pointer.
 */
unsigned int PEFile::GetDataPointer(void) const
{
    return (unsigned int)this->m_FileData;
}

/**
 * @brief Returns the interna file data size.
 *
 * @return The internal file data size.
 */
unsigned int PEFile::GetDataSize(void) const
{
    return this->m_FileSize;
}

/**
 * @brief Returns the current files dos header.
 *
 * @param dosHeader     The buffer to hold the dos header.
 */
void PEFile::GetDosHeader(IMAGE_DOS_HEADER* dosHeader) const
{
    memcpy(dosHeader, &this->m_DosHeader, sizeof(IMAGE_DOS_HEADER));
}

/**
 * @brief Returns the current files nt headers.
 *
 * @param ntHeaders     The buffer to hold the nt headers.
 */
void PEFile::GetNtHeaders(IMAGE_NT_HEADERS* ntHeaders) const
{
    memcpy(ntHeaders, &this->m_NtHeaders, sizeof(IMAGE_NT_HEADERS));
}

/**
 * @brief Returns the current files dos stub, if it exists.
 *
 * @param lpBuffer      The buffer to obtain the dos stub.
 * @param size          The size of the buffer.
 */
void PEFile::GetDosStub(LPVOID lpBuffer, unsigned int size) const
{
    if (size < this->m_DosStubSize)
        return;

    memcpy(lpBuffer, this->m_DosStub, size);
}

/**
 * @brief Returns the current files dos stub offset.
 *
 * @return The offset to the current files dos stub.
 */
unsigned int PEFile::GetDosStubOffset(void) const
{
    return this->m_DosStubOffset;
}

/**
 * @brief Returns the current files dos stub size.
 *
 * @return The size of the current files dos stub.
 */
unsigned int PEFile::GetDosStubSize(void) const
{
    return this->m_DosStubSize;
}

/**
 * @brief Gets the alignment of the given value.
 *
 * @param in            The value to obtain the alignment of.
 * @param align         The alignment to use.
 *
 * @return The calculated alignment.
 */
unsigned int PEFile::GetAlignment(unsigned int in, unsigned int align)
{
    return (((in + align - 1) / align) * align);
}

/**
 * @brief Determines if the loaded file has a given section by its name.
 *
 * @param name          The name of the section to locate.
 *
 * @return True if found, false otherwise.
 */
bool PEFile::HasSection(const std::string& name)
{
    for (auto& s : this->m_Sections)
    {
        if (!_stricmp(name.c_str(), (const char*)s.Name))
            return true;
    }

    return false;
}

/**
 * @brief Obtains a section by its name.
 *
 * @param name          The name of the section to obtain.
 * @param lpSection     The buffer to obtain the section.
 *
 * @return True on success, false otherwise.
 */
bool PEFile::GetSection(const std::string& name, IMAGE_SECTION_HEADER* lpSection)
{
    for (auto& s : this->m_Sections)
    {
        if (!_stricmp(name.c_str(), (const char*)s.Name))
        {
            memcpy(lpSection, &s, sizeof(IMAGE_SECTION_HEADER));
            return true;
        }
    }

    return false;
}

/**
 * @brief Obtains a section by its index.
 *
 * @param index         The index of the section to obtain.
 * @param lpSection     The buffer to obtain the section.
 *
 * @return True on success, false otherwise.
 */
bool PEFile::GetSection(unsigned int index, IMAGE_SECTION_HEADER* lpSection)
{
    if (index > this->m_Sections.size())
        return false;

    auto s = this->m_Sections.at(index);
    memcpy(lpSection, &s, sizeof(IMAGE_SECTION_HEADER));
    return true;
}

/**
 * @brief Gets all the sections of the current file.
 *
 * @param sections      A vector to obtain the sections.
 *
 * @return True on success, false otherwise.
 */
bool PEFile::GetSections(std::vector<IMAGE_SECTION_HEADER>* sections)
{
    if (this->m_Sections.size() == 0)
        return false;

    for (auto& s : this->m_Sections)
    {
        IMAGE_SECTION_HEADER section = { 0 };
        memcpy(&section, &s, sizeof(IMAGE_SECTION_HEADER));
        sections->push_back(section);
    }

    return true;
}

/**
 * @brief Obtains the owner section of the given rva.
 *
 * @param rva           The rva to obtain the owning section of.
 * @param lpSection     The buffer to obtain the section.
 *
 * @return True on success, false otherwise.
 */
bool PEFile::GetOwnerSection(unsigned int rva, IMAGE_SECTION_HEADER* lpSection)
{
    for (auto& s : this->m_Sections)
    {
        // Obtain the size of the section..
        auto size = s.Misc.VirtualSize;
        if (size == 0)
            size = s.SizeOfRawData;

        // Determine if we are within this section..
        if ((rva >= s.VirtualAddress) && (rva < s.VirtualAddress + size))
        {
            memcpy(lpSection, &s, sizeof(IMAGE_SECTION_HEADER));
            return true;
        }
    }

    return false;
}

/**
 * @brief Obtains the the rva from the va.
 *
 * @param va            The va to obtain the rva of.
 *
 * @return True on success, false otherwise.
 */
LPVOID PEFile::GetRvaFromVa(unsigned int va)
{
    return (LPVOID)(va - this->m_NtHeaders.OptionalHeader.ImageBase);
}

/**
 * @brief Obtains the file pointer from the given rva.
 *
 * @param rva           The rva to obtain the file pointer of.
 *
 * @return True on success, false otherwise.
 */
LPVOID PEFile::GetFilePointerFromRva(unsigned int rva)
{
    // Obtain the owning section of this rva..
    IMAGE_SECTION_HEADER section = { 0 };
    if (!this->GetOwnerSection(rva, &section))
        return nullptr;

    // Calcuate the file pointer from the rva..
    return (LPVOID)(rva - (section.VirtualAddress - section.PointerToRawData));
}
