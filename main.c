#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


typedef struct {
    char *name;
    WORD vk;
} GetVkItem;

union KeyScanRet {
    SHORT ret;
    BYTE bytes[2];
};
#define VK_NOT_FOUND 0xffff

// TODO: accept this through .ini
static WORD g_ssc_mvks[] = { VK_RMENU };


/*
 *   Extendable
*/

static WORD get_vk(const char *str)
{
    if (str == NULL) return 0;

    if (strlen(str) == 1) {
        HKL hkl = GetKeyboardLayout(0);

        union KeyScanRet x;
        x.ret = VkKeyScanExA(*str, hkl);
        if (x.bytes[0] < 0 && x.bytes[1] < 0)
            return VK_NOT_FOUND;

        return x.bytes[0];
    }

    GetVkItem items[] = {
        { "ctrl",    VK_CONTROL },
        { "lctrl",   VK_LCONTROL },
        { "rctrl",   VK_RCONTROL },

        { "alt",     VK_MENU },
        { "lalt",    VK_LMENU },
        { "ralt",    VK_RMENU },

        { "shift",   VK_SHIFT },
        { "lshift",  VK_LSHIFT },
        { "rshift",  VK_RSHIFT },

        { "esc",     VK_ESCAPE },
        { "caps",    VK_CAPITAL },

        { "up",      VK_UP },
        { "down",    VK_DOWN },
        { "left",    VK_LEFT },
        { "right",   VK_RIGHT },

        { "np0",     VK_NUMPAD0 },
        { "np1",     VK_NUMPAD1 },
        { "np2",     VK_NUMPAD2 },
        { "np3",     VK_NUMPAD3 },
        { "np4",     VK_NUMPAD4 },
        { "np5",     VK_NUMPAD5 },
        { "np6",     VK_NUMPAD6 },
        { "np7",     VK_NUMPAD7 },
        { "np8",     VK_NUMPAD8 },
        { "np9",     VK_NUMPAD9 },
    };

    for (int i = 0; i < _countof(items); ++i) {
        if (strcmp(str, items[i].name) == 0)
            return items[i].vk;
    }

    return VK_NOT_FOUND;
}


/*
 *  Typedefs
*/

typedef uint8_t u8;

#define MAX_MODS 3
#define MAX_SCS MAX_MODS
#define SIDES 2

typedef struct {
    WORD key;
    WORD mods[3];
    WORD mods[MAX_MODS];
} MapSide;

typedef union {
    MapSide sides[2];
    MapSide sides[SIDES];
    struct {
        MapSide trigger;
        MapSide target;
    };
} Map;

typedef struct {
    u8 count;
    Map map[];
} Remap;

Remap *remap = NULL;

typedef struct {
    WORD scs[MAX_SCS];
    u8 flags[MAX_SCS];
} ScansFlags;

typedef union {
    ScansFlags sides[SIDES];
    struct {
        ScansFlags trigger;
        ScansFlags target;
    };
} ScanCodes;

ScanCodes *scan_codes = NULL;


/*
 *  Logging
*/

#ifdef KBMAP_CONSOLE
#define error_out(...) printf(__VA_ARGS__)

typedef union {
    LONG l;
    struct {
        WORD lo;
        WORD hi;
    };
} Something;

static_assert(sizeof(WORD) == 2, "");
static_assert(sizeof(DWORD) == sizeof(WORD) * 2, "");
static_assert(sizeof(LONG) == sizeof(DWORD), "");

static bool get_sc_name(UINT sc, char *buf, int buf_size)
{
    Something s;
    s.hi = sc;

    bool extended = sc & 0xe0 << 8;
    if (extended) _bittestandset(&s.l, 24);

    return GetKeyNameTextA(s.l, buf, buf_size) != 0;
}


static bool get_vk_name(UINT vk, char *buf, int buf_size)
{
    UINT sc = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC_EX);
    if (!sc) return false;
    return get_sc_name(sc, buf, buf_size) != 0;
}


static void dump_mappings(void)
{
    assert(remap);

    printf("Mapped virtual keys:\n"
           "|     trigger     |    target\n"
           "|key,  modifiers  | key,  modifiers\n\n");

    for (int c = 0; c < remap->count; ++c) {
        Map *map = &remap->map[c];

        char buf[50];
        for (int s = 0; s < SIDES; ++s) {
            if (get_vk_name(map->sides[s].key, buf, 50))
                printf("|%s, ", buf);
            else
                printf("|%s, ", "-");

            for (int m = 0; m < MAX_MODS; ++m) {
                if (get_vk_name(map->sides[s].mods[m], buf, 50))
                    printf("%s, ", buf);
                else
                    printf("%s, ", "-");
            }
        }
        printf("\n");
    }
    printf("\n");
    fflush(stdout);
}


static void dump_inputs(UINT count, LPINPUT inputs, int size)
{
    for (UINT c = 0; c < count; ++c) {
        INPUT *inp = &inputs[c];
        assert(inp->type == INPUT_KEYBOARD);

        char buf[50];
        char *name = "-";
        if (inp->ki.wVk && get_vk_name(inp->ki.wVk, buf, 50))
            name = buf;

        if (!inp->ki.wVk && inp->ki.wScan && get_sc_name(inp->ki.wScan, buf, 50))
            name = buf;

        char *up_down = "down";
        if (inp->ki.dwFlags & KEYEVENTF_KEYUP) up_down = "up";

        printf("0x%04x: %s -> %s\n", inp->ki.wScan, name, up_down);
    }
    printf("--------------------\n");
    fflush(stdout);
}

#else  // No Console

static void error_out(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    int required = _vscprintf(fmt, args);
    required++;

    char *msg = malloc(required);
    if (!msg) return;

    int w = vsprintf_s(msg, required, fmt, args);
    if (w < 0 || w > required) return;

    va_end(args);

    MessageBoxA(NULL, msg, "kbmap", MB_ICONERROR);
    free(msg);
}

#   define dump_mappings(...)
#   define dump_inputs(...)
#endif


/*
 *  "Callback-time" code
*/

// TODO: typedef a sc bigger than WORD and hold these values in upper bytes
// Would be a problem if any driver uses theses numbers...
#define SC_QUERY_CONTROL 0xffff
#define SC_QUERY_MENU    (0xffff - 1)
#define SC_QUERY_SHIFT   (0xffff - 2)
// TODO: SC_QUERY_NUMBER

static void identify_triggers(ScansFlags *triggers)
{
    for (int i = 0; i < MAX_SCS; ++i) {
        WORD vk;

        switch (triggers->scs[i]) {
            case SC_QUERY_CONTROL:
                vk = 0;
                if (GetKeyState(VK_LCONTROL) & 0x8000) vk = VK_LCONTROL;
                if (GetKeyState(VK_RCONTROL) & 0x8000) vk = VK_RCONTROL;
                assert(vk != 0);
                break;

            case SC_QUERY_MENU:
                vk = 0;
                if (GetKeyState(VK_LMENU) & 0x8000) vk = VK_LMENU;
                if (GetKeyState(VK_RMENU) & 0x8000) vk = VK_RMENU;
                assert(vk != 0);
                break;

            case SC_QUERY_SHIFT:
                vk = 0;
                if (GetKeyState(VK_LSHIFT) & 0x8000) vk = VK_LSHIFT;
                if (GetKeyState(VK_RSHIFT) & 0x8000) vk = VK_RSHIFT;
                assert(vk != 0);
                break;

            default:
                continue;
        }

        WORD sc = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC_EX);
        assert(sc);
        triggers->scs[i] = sc;

        u8 flag = KEYEVENTF_SCANCODE;
        if (sc & 0xe0 << 8) flag |= KEYEVENTF_EXTENDEDKEY;
        triggers->flags[i] = flag;
    };
}


static bool g_remapping = false;

// 3 to reset trigger modifiers
// 3 to set target modifiers
// 2 to press target key down and up
// 3 to reset target modifiers
// 3 to set trigger modifiers (if not ssc_mvk)
#define MAX_INPUTS    \
    (MAX_MODS * 2 +   \
     2 +              \
     MAX_MODS * 2)
    
static_assert(MAX_INPUTS == 14, "");


static LRESULT __stdcall LowLevelKeyboardProc(int nCode,
                                              WPARAM wParam,
                                              LPARAM lParam)
{
    if (g_remapping || nCode < 0 || (wParam != WM_KEYDOWN && wParam != WM_SYSKEYDOWN))
        return CallNextHookEx(0, nCode, wParam, lParam);

    KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT*)lParam;

    for (u8 c = 0; c < remap->count; ++c) {
        Map *map = &remap->map[c];
        WORD key = map->trigger.key;
        assert(key && key != VK_NOT_FOUND);

        if (kb->vkCode != key) continue;

        // Check if modifiers are also pressed
        bool do_continue = false;
        for (int m = 0; m < MAX_MODS; ++m) {
            WORD modifier = map->trigger.mods[m];
            if (!modifier) continue;

            if (!(GetKeyState(modifier) & 0x8000)) {
                do_continue = true;
                break;
            }
        }
        if (do_continue) continue;

        // PERF: since we only need to copy `trigger`, ScanCodes should not
        // hold both trigger and target
        ScanCodes scs = scan_codes[c];
        identify_triggers(&scs.trigger);

        INPUT inputs[MAX_INPUTS] = {0};
        INPUT *inp;
        u8 cursor = 0;

        // Reset trigger modifiers
        for (int m = 0; m < MAX_MODS; ++m) {
            WORD modifier = scs.trigger.scs[m];
            if (!modifier) continue;

            u8 flags = scs.trigger.flags[m];

            inp = &inputs[cursor++];
            inp->type = INPUT_KEYBOARD;
            inp->ki.wScan = modifier;
            inp->ki.dwFlags = flags | KEYEVENTF_KEYUP;
        }

        // Set target modifiers
        for (int m = 0; m < MAX_MODS; ++m) {
            WORD modifier = scs.target.scs[m];
            if (!modifier) continue;

            u8 flags = scs.target.flags[m];

            inp = &inputs[cursor++];
            inp->type = INPUT_KEYBOARD;
            inp->ki.wScan = modifier;
            inp->ki.dwFlags = flags;
        }

        // Set target key
        key = map->target.key;

        inp = &inputs[cursor++];
        inp->type = INPUT_KEYBOARD;
        inp->ki.wVk = key;
        inp->ki.dwFlags = 0;

        inp = &inputs[cursor++];
        inp->type = INPUT_KEYBOARD;
        inp->ki.wVk = key;
        inp->ki.dwFlags = KEYEVENTF_KEYUP;

        // Reset target modifiers
        for (int m = 0; m < MAX_MODS; ++m) {
            WORD modifier = scs.target.scs[m];
            if (!modifier) continue;

            u8 flags = scs.target.flags[m];

            inp = &inputs[cursor++];
            inp->type = INPUT_KEYBOARD;
            inp->ki.wScan = modifier;
            inp->ki.dwFlags = flags | KEYEVENTF_KEYUP;
        }

        bool set_triggers = true;
        for (int m = 0; m < MAX_MODS; ++m) {
            WORD modifier = map->trigger.mods[m];
            for (int i = 0; i < _countof(g_ssc_mvks); ++i) {
                WORD vk = g_ssc_mvks[i];
                if (modifier == vk) set_triggers = false;
            }
        }

        // Set trigger modifiers
        if (set_triggers) {
            for (int s = 0; s < MAX_SCS; ++s) {
                WORD modifier = scs.trigger.scs[s];
                if (!modifier) continue;

                u8 flags = scs.trigger.flags[s];

                inp = &inputs[cursor++];
                inp->type = INPUT_KEYBOARD;
                inp->ki.wScan = modifier;
                inp->ki.dwFlags = flags;
            }
        }
        assert(cursor <= MAX_INPUTS);

        dump_inputs(cursor, inputs, sizeof(INPUT));
        g_remapping = true;
        UINT sent = SendInput(cursor, inputs, sizeof(INPUT));
        g_remapping = false;
        assert(sent == cursor);
        return 1;
    }

    return CallNextHookEx(0, nCode, wParam, lParam);
}


/*
 *  "Setup-time" code
*/

#define FLAT_SIZE (MAX_MODS + 1)

static bool parse_item(const char *key_or_val, MapSide *dest)
{
    if (!key_or_val) return false;

    char *dup = _strdup(key_or_val);
    if (!dup) return false;

    WORD flat[FLAT_SIZE] = {0};
    const char *delim = " +";

    char *tok, *ntok;
    tok = strtok_s(dup, delim, &ntok);
    if (!tok) {
        error_out("Empty trigger or target\n");
        return false;
    }

    WORD vk = get_vk(tok);
    if (vk == VK_NOT_FOUND) {
        error_out("\"%s\": Unhandled `%s`\n", key_or_val, tok);
        return false;
    };
    flat[0] = vk;

    for (int i = 1; i < _countof(flat); ++i) {
        tok = strtok_s(NULL, delim, &ntok);
        vk = get_vk(tok);
        if (vk == VK_NOT_FOUND) {
            error_out("\"%s\": Unhandled `%s`\n", key_or_val, tok);
            return false;
        };
        flat[i] = vk;
    }
    tok = strtok_s(NULL, delim, &ntok);
    if (tok) {
        error_out("\"%s\": Too many tokens given\n", key_or_val);
        return false;
    }
    free(dup);

    int cursor = -1;
    for (int i = FLAT_SIZE - 1; i >= 0; --i) {
        WORD it = flat[i];
        if (!it) continue;

        if (cursor == -1) {
            dest->key = it;
            cursor++;
            continue;
        }
        dest->mods[cursor++] = it;
    }

    return true;
}


static bool is_modifier(WORD test)
{
    switch (test) {
        case 0:
        case VK_CONTROL:
        case VK_RCONTROL:
        case VK_LCONTROL:
        case VK_MENU:
        case VK_RMENU:
        case VK_LMENU:
        case VK_SHIFT:
        case VK_LSHIFT:
        case VK_RSHIFT:
            return true;
        default:
            return false;
    }
}


static bool validate_remap(void)
{
    // TODO: We don't support VK_LWIN bc it is not a valid trigger, but it is a
    // valid target. Validating should address this case. Most win + <key>
    // chords are taken by explorer.exe and are processed before the hook
    assert(remap);
    if (!remap->count) return false;

    for (int i = 0; i < remap->count; ++i) {
        Map *map = &remap->map[i];

        for (int j = 0; j < 2; ++j) {
            MapSide side = map->sides[j];

            if (is_modifier(side.key)) return false;

            for (int k = 0; k < 3; ++k) {
                WORD mod = side.mods[k];
                if (!is_modifier(mod)) return false;
            }
        }
    }

    return true;
}


static bool get_init_path_and_size(char **full_path, DWORD *file_size)
{
    char *userprofile = NULL;
    size_t upsize;
    if (_dupenv_s(&userprofile, &upsize, "USERPROFILE")) return false;

    const char *ini_name = ".kbmap.ini";
    const size_t namelen = strlen(ini_name);
    size_t size = upsize + strlen("\\") + namelen + 1;
    char *ini_path = malloc(size);
    if (!ini_path) return false;

    int w = sprintf_s(ini_path, size, "%s\\%s", userprofile, ini_name);
    if (w < 0 || w > size) return false;

    // Can't get needed memory allocation size for parsing through
    // GetPrivateProfileStringA so we alloc the size of the whole file
    HANDLE ini = CreateFileA(
        ini_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (ini == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER li;
    if (!GetFileSizeEx(ini, &li)) return false;
    CloseHandle(ini);

    if (li.QuadPart > MAXDWORD) return false;
    DWORD ini_size = (DWORD)li.QuadPart;

    *full_path = ini_path;
    *file_size = ini_size;
    return true;
}


static bool parse_ini_into_remap(char *ini_path, DWORD ini_size)
{
    assert(ini_path);
    if (!ini_size) return false;

    char *keys_mem = malloc(ini_size);
    char *val = malloc(ini_size);
    if (!keys_mem || !val) return false;

    GetPrivateProfileStringA(
        "remap",
        NULL,
        NULL,
        keys_mem,
        ini_size,
        ini_path
    );
    int id = GetLastError();
    if (id != 0) {
        error_out("Could not get keys of .ini file. LastError: %i\n", id);
        return false;
    }

    u8 count = 0;
    char *key = keys_mem;
    while (*key) {
        count++;
        key += strlen(key) + 1;
    }
    key = keys_mem;
    if (!count) return false;

    // PERF: `remap` and `scan_codes` should be in a contiguous memory block
    size_t size = sizeof(Remap) + sizeof(Map) * count;
    remap = malloc(size);
    memset(remap, 0, size);
    remap->count = count;

    int map_idx = 0;
    while (*key) {
        size_t len = strlen(key);
        Map *map = &remap->map[map_idx];

        if (!parse_item(key, &map->trigger)) return false;

        DWORD n = GetPrivateProfileStringA(
                "remap", key, NULL, val, ini_size, ini_path) + 1;
        id = GetLastError();
        if (id != 0) {
            error_out("Could not get .ini value for key `%s`\n", key);
            return false;
        }

        if (!parse_item(val, &map->target)) return false;

        map_idx++;
        key += len + 1;
    }

    free(keys_mem);
    free(val);

    return true;
}


static ScanCodes to_scan_code(Map *map)
{
    ScanCodes ret = {0};
    for (int m = 0; m < MAX_MODS; ++m) {
        WORD vk = map->trigger.mods[m];
        if (!vk) continue;

        WORD sc;
        switch (vk) {
            case VK_CONTROL:
                sc = SC_QUERY_CONTROL;
                break;
            case VK_MENU:
                sc = SC_QUERY_MENU;
                break;
            case VK_SHIFT:
                sc = SC_QUERY_SHIFT;
                break;
            default:
                sc = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC_EX);
                assert(sc);
        }

        u8 flag = KEYEVENTF_SCANCODE;
        if (sc & 0xe0 << 8) flag |= KEYEVENTF_EXTENDEDKEY;

        ret.trigger.scs[m] = sc;
        ret.trigger.flags[m] = flag;
    }

    for (int m = 0; m < MAX_MODS; ++m) {
        WORD vk = map->target.mods[m];
        if (!vk) continue;

        WORD sc = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC_EX);
        assert(sc);
        u8 flag = KEYEVENTF_SCANCODE;
        if (sc & 0xe0 << 8) flag |= KEYEVENTF_EXTENDEDKEY;

        ret.target.scs[m] = sc;
        ret.target.flags[m] = flag;
    }

    return ret;
}


static bool populate_scan_codes(void)
{
    assert(remap && remap->count);

    size_t size = sizeof(ScanCodes) * remap->count;
    // PERF: same memory block as `remap`
    scan_codes = malloc(size);
    if (!scan_codes) return false;
    memset(scan_codes, 0, size);

    for (int i = 0; i < remap->count; ++i) {
        scan_codes[i] = to_scan_code(&remap->map[i]);
    }

    return true;
}


static bool kbmap_setup(void)
{
    char *ini_path;
    DWORD ini_size;
    if (!get_init_path_and_size(&ini_path, &ini_size)) {
        error_out("Could not find .ini file\n");
        return false;
    }

    if (!parse_ini_into_remap(ini_path, ini_size))
        return false;

    free(ini_path);

    if (!validate_remap()) {
        error_out("Invalid Remap\n");
        return false;
    }
    if (!populate_scan_codes()) {
        error_out("Could not get scan codes\n");
        return false;
    }

    return true;
}


#ifdef KBMAP_CONSOLE
int main(void)
#else
int WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmdline, int show)
#endif
{
    if (!kbmap_setup()) {
        error_out("Errors occurred. Exiting.\n");
        return 1;
    }

    dump_mappings();

    if (!SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0)) {
        error_out("Could not set Windows hook. Exiting.\n");
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) { }

    return 0;
}
