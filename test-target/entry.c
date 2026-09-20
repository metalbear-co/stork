#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HANDLE event_for(const wchar_t *prefix) {
    wchar_t name[96];
    unsigned int n = 0;
    while (prefix[n]) {
        name[n] = prefix[n];
        n++;
    }
    DWORD pid = GetCurrentProcessId();
    wchar_t digits[10];
    unsigned int count = 0;
    do {
        digits[count++] = (wchar_t)(L'0' + pid % 10);
        pid /= 10;
    } while (pid);
    while (count) {
        name[n++] = digits[--count];
    }
    name[n] = 0;
    return OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name);
}

static int is_set(const wchar_t *prefix) {
    HANDLE event = event_for(prefix);
    DWORD result;
    if (!event) {
        return 0;
    }
    result = WaitForSingleObject(event, 0);
    CloseHandle(event);
    return result == WAIT_OBJECT_0;
}

static void signal(const wchar_t *prefix) {
    HANDLE event = event_for(prefix);
    if (event) {
        SetEvent(event);
        CloseHandle(event);
    }
}

__declspec(noreturn) void WINAPI stork_entry(void) {
    if (is_set(L"Local\\stork_test_")) {
        signal(L"Local\\stork_pass_");
    }
    if (is_set(L"Local\\stork_ready_")) {
        signal(L"Local\\stork_ready_at_entry_");
    }
    signal(L"Local\\stork_entry_");
    for (;;) {
        Sleep(60000);
    }
}
