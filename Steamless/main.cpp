
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

#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h>
#include <functional>
#include <Shlwapi.h>
#include <string>

#include "PEFile.h"
#include "Utils.h"

#include "SteamStub32_Variant2.h"
#include "SteamStub32_Variant3.h"

/**
 * @brief Removal Stub Function Prototype
 */
typedef std::function<bool(PEFile*, const char*)> STUBFUNC;

/**
 * @brief Steam Stub Signatures
 */
struct
{
    char*           Name;
    unsigned char*  Pattern;
    char*           Mask;
    STUBFUNC        Func;
} g_Signatures[]
{
    { "SteamStub Variant #1", (unsigned char*)"\x53\x51\x52\x56\x57\x55\x8B\xEC\x81\xEC\x00\x10\x00\x00\xBE", "xxxxxxxxxxxxxxx", nullptr },
    { "SteamStub Variant #2", (unsigned char*)"\x53\x51\x52\x56\x57\x55\x8B\xEC\x81\xEC\x00\x10\x00\x00\xC7", "xxxxxxxxxxxxxxx", SteamStub32Variant2::ProcessFile },
    { "SteamStub Variant #3", (unsigned char*)"\xE8\x00\x00\x00\x00\x50\x53\x51\x52\x56\x57\x55\x8B\x44\x24\x1C\x2D\x05\x00\x00\x00\x8B\xCC\x83\xE4\xF0\x51\x51\x51\x50", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", SteamStub32Variant3::ProcessFile }
};

/**
 * @brief Main Entry Point
 *
 * @param argc      The number of arguments passed to this application.
 * @param argv      The array of arguments passed to this application.
 *
 * @return Non-important return value.
 */
int __cdecl main(int argc, char* argv[])
{
    // Display our project header..
    Console::output(Console::Colors::LightPurple, "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    Console::output(Console::Colors::LightPurple, "-=-");
    Console::output(Console::Colors::LightCyan, "                 Steamless - Steam DRM Remover v1.0              ");
    Console::output(Console::Colors::LightPurple, "-=-\n");
    Console::output(Console::Colors::LightPurple, "-=-");
    Console::output(Console::Colors::LightYelllow, "                    by atom0s [atom0s@live.com]                  ");
    Console::output(Console::Colors::LightPurple, "-=-\n");
    Console::output(Console::Colors::LightPurple, "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n\n");

    // Ensure the argument count is valid..
    if (argc <= 1)
    {
        Console::output(Console::Colors::LightRed, "[*] ERROR: Invalid usage!\n");
        Console::output(Console::Colors::LightRed, "[*] ERROR: Usage is: Steamless.exe [file]\n");
        return 0;
    }

    // Ensure the given file exists..
    if (::GetFileAttributes(argv[1]) == INVALID_FILE_ATTRIBUTES)
    {
        Console::output(Console::Colors::LightRed, "[*] ERROR: Invalid input file; file does not exist!\n");
        return 0;
    }

    // Set the current working directory to the given input file..
    char szWorkingDirectory[MAX_PATH] = { 0 };
    strcpy_s(szWorkingDirectory, argv[1]);
    ::PathRemoveFileSpec(szWorkingDirectory);

    if (strlen(szWorkingDirectory) > 0)
        ::SetCurrentDirectory(szWorkingDirectory);

    // Load the input file for processing..
    auto file = new PEFile();
    if (!file->Initialize(argv[1]))
    {
        Console::output(Console::Colors::LightRed, "[*] ERROR: Failed to initialize PEFile wrapper. Invalid file maybe?\n");
        delete file;
        return 0;
    }

    // Determine if the file has the proper .bind section..
    if (!file->HasSection(".bind"))
    {
        Console::output(Console::Colors::LightRed, "[*] ERROR: Failed to locate .bind section, cannot process file!\n");
        delete file;
        return 0;
    }

    // Attempt to process the file..
    auto processed = [&]() -> bool
    {
        // Locate a known Steam signature by scanning for stub information..
        for (auto x = 0; x < _countof(g_Signatures); x++)
        {
            auto found = Utils::FindPattern((unsigned char*)file->GetDataPointer(), file->GetDataSize(), g_Signatures[x].Pattern, g_Signatures[x].Mask);
            if (found != 0)
            {
                Console::output(Console::Colors::LightGreen, "[*] INFO: Located Steam Stub! (%s)\n", g_Signatures[x].Name);
                return g_Signatures[x].Func(file, argv[1]);
            }
        }

        return false;
    }();

    if (!processed)
        Console::output(Console::Colors::LightRed, "[*] ERROR: Failed to process file!\n");
    else
        Console::output(Console::Colors::LightGreen, "[*] Successfully processed the file!\n");

    // Cleanup..
    delete file;
    file = nullptr;
    return 0;
}
