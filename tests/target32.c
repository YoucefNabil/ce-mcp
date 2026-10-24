// SPDX-License-Identifier: GPL-3.0-or-later
// 32-bit test target, like target.py: prints the address of a u32 that goes up by 1 every second,
// then runs for `seconds` (argv[1]). run.py builds it with MSVC into tests/build/target32.exe.
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

static volatile unsigned int v = 1234567;

int main(int argc, char** argv) {
    DWORD end = GetTickCount() + 1000 * (DWORD)(argc > 1 ? atoi(argv[1]) : 120);
    printf("0x%p\n", (void*)&v);
    fflush(stdout);
    while ((int)(end - GetTickCount()) > 0) {
        Sleep(1000);
        v = v + 1;
    }
    return 0;
}
