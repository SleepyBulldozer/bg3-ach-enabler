/*
 * bg3ach - re-enable achievements in modded Baldur's Gate 3 (native Linux build).
 *
 * This file builds into a small shared library that is loaded into the game with
 * LD_PRELOAD. It runs once, before the game's own code starts, and makes a single
 * three-byte change to the game in memory. Nothing on disk is modified.
 *
 * WHY
 *   Before unlocking an achievement (or recording progress towards one), the game asks
 *   "are any non-official mods loaded?". It answers by walking the list of loaded
 *   modules and checking each one's UUID against a built-in whitelist. If anything is
 *   not on the list, the achievement is silently skipped.
 *
 * WHAT WE DO
 *   1. Find that check function by searching the game's code for a known sequence of
 *      machine-code bytes (a "signature"). It must be found exactly once.
 *   2. Double-check we found the right function: the per-module helper it calls must
 *      use the UUID format string "%08x-%04hx-...". If it doesn't, we stop.
 *   3. Overwrite the start of the check with "return false" (xor eax,eax; ret), so the
 *      game always believes no mods are loaded.
 *
 *   If anything looks wrong (the game was updated, the signature matches more than
 *   once, the double-check fails) we log why and leave the game untouched.
 *
 * SETTINGS (environment variables)
 *   BG3ACH_DISABLE=1      do nothing at all
 *   BG3ACH_DRYRUN=1       find and verify the check, but don't patch it
 *   BG3ACH_NOVERIFY=1     patch even if the double-check fails (still needs a unique match)
 *   BG3ACH_LOG=<path>     append log messages to this file (default: stderr)
 *   BG3ACH_EXE=<name>     only act on an executable with this name (default: bg3)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <link.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

/* ============================================================================================
 * Types and small helpers
 * ========================================================================================== */

/* A contiguous chunk of the game's memory, e.g. its code or its read-only data. */
typedef struct {
    uint8_t *start;
    size_t length;
    int protection; /* PROT_READ / PROT_WRITE / PROT_EXEC, as the loader mapped it */
} memory_region;

/* An executable normally has only a handful of segments; this is plenty. */
#define MAX_REGIONS 32

/* Outcome of bg3ach_apply(). */
typedef enum {
    BG3ACH_OK = 0,              /* patched (or found and verified, in dry-run mode) */
    BG3ACH_BAD_SIGNATURE = 1,   /* the built-in signature text is malformed (a bug here) */
    BG3ACH_NOT_FOUND = 2,       /* signature not present: game updated, or already patched */
    BG3ACH_AMBIGUOUS = 3,       /* signature found more than once: unsafe to guess */
    BG3ACH_VERIFY_FAILED = 4,   /* found something, but it doesn't look like the mod check */
    BG3ACH_PATCH_FAILED = 5,    /* couldn't make the code writable */
} bg3ach_result;

/* True if the environment variable is set to anything other than "" or "0". */
static int env_flag_set(const char *name)
{
    const char *value = getenv(name);
    return value && *value && strcmp(value, "0") != 0;
}

/* ============================================================================================
 * Logging
 * ========================================================================================== */

static FILE *log_file; /* NULL means stderr */

static void log_message(const char *format, ...)
{
    FILE *out = log_file ? log_file : stderr;
    va_list args;

    va_start(args, format);
    fprintf(out, "[bg3ach] ");
    vfprintf(out, format, args);
    fputc('\n', out);
    fflush(out);
    va_end(args);
}

/* ============================================================================================
 * What we search for
 *
 * The signature is written as hex bytes, with "??" for bytes that are allowed to differ.
 * Wildcards cover jump distances, call targets and struct field offsets, which tend to
 * change between game builds. Everything else (which registers are used, the shape of the
 * loop) is kept, because that is what makes the match unique.
 * ========================================================================================== */

/*
 * bool HasNonWhitelistedMods(ModuleList *list)
 *
 * Returns true as soon as it finds a loaded module that is not whitelisted. One
 * instruction per line:
 */
static const char MOD_CHECK_SIGNATURE[] =
    /* -- save registers -------------------------------------------------------------- */
    "55 "                   /* push rbp                                                  */
    "41 57 "                /* push r15                                                  */
    "41 56 "                /* push r14                                                  */
    "41 55 "                /* push r13                                                  */
    "41 54 "                /* push r12                                                  */
    "53 "                   /* push rbx                                                  */
    "50 "                   /* push rax                                                  */
    /* -- if the module list is empty, skip the loop ----------------------------------- */
    "44 8B 77 ?? "          /* mov  r14d, [rdi + count]                                  */
    "4D 85 F6 "             /* test r14, r14                                             */
    "74 ?? "                /* je   empty                                                */
    /* -- set up the loop ------------------------------------------------------------- */
    "4C 89 F0 "             /* mov  rax, r14                                             */
    "48 89 FB "             /* mov  rbx, rdi                                             */
    "40 B5 01 "             /* mov  bpl, 1                                               */
    "41 BC 01 00 00 00 "    /* mov  r12d, 1                                              */
    "45 31 ED "             /* xor  r13d, r13d                                           */
    "48 C1 E0 05 "          /* shl  rax, 5                                               */
    "4C 8D 3C 40 "          /* lea  r15, [rax + rax*2]       ; end = count * 0x60        */
    /* -- loop body: is this module whitelisted? ------------------------------------- */
    "48 8B 7B ?? "          /* mov  rdi, [rbx + data]                                    */
    "4C 01 EF "             /* add  rdi, r13                 ; rdi = &modules[i]         */
    "E8 ?? ?? ?? ?? "       /* call IsWhitelisted            ; <- offset 53, see below   */
    "84 C0 "                /* test al, al                                               */
    "74 ?? "                /* je   done                     ; not whitelisted -> true   */
    /* -- next module ----------------------------------------------------------------- */
    "4D 39 F4 "             /* cmp  r12, r14                                             */
    "40 0F 92 C5 "          /* setb bpl                                                  */
    "49 83 C5 ?? "          /* add  r13, stride                                          */
    "49 FF C4 "             /* inc  r12                                                  */
    "4D 39 EF "             /* cmp  r15, r13                                             */
    "75 ??";                /* jne  loop                                                 */

/* Byte offset of the "call IsWhitelisted" instruction (opcode E8) within the signature. */
#define CALL_OFFSET_IN_SIGNATURE 53

/* The whitelist helper formats each module's UUID with this string. Finding a reference
 * to it inside the helper tells us we have the right function. */
static const char UUID_FORMAT[] = "%08x-%04hx-%04hx-%04hx-%04hx%04hx%04hx";

/* How many bytes at the start of the helper to search for that reference. */
#define HELPER_SEARCH_LENGTH 0x100

/* The replacement code: "return false". */
static const uint8_t RETURN_FALSE[] = {
    0x31, 0xC0, /* xor eax, eax */
    0xC3,       /* ret          */
};

/* ============================================================================================
 * Pattern matching
 * ========================================================================================== */

typedef struct {
    uint8_t bytes[256];
    uint8_t mask[256]; /* 0xFF = this byte must match, 0x00 = wildcard */
    size_t length;
} byte_pattern;

/* Turns "55 41 ?? 53" into bytes + mask. Returns 0 on success, -1 if the text is malformed. */
static int parse_pattern(const char *text, byte_pattern *pattern)
{
    pattern->length = 0;

    while (*text) {
        while (*text == ' ')
            text++;
        if (!*text)
            break;
        if (pattern->length >= sizeof pattern->bytes)
            return -1;

        if (text[0] == '?') {
            pattern->bytes[pattern->length] = 0;
            pattern->mask[pattern->length] = 0x00;
            text += (text[1] == '?') ? 2 : 1;
        } else {
            char hex[3] = {text[0], text[1], '\0'};
            char *end;
            unsigned long value = strtoul(hex, &end, 16);
            if (end != hex + 2)
                return -1;
            pattern->bytes[pattern->length] = (uint8_t)value;
            pattern->mask[pattern->length] = 0xFF;
            text += 2;
        }
        pattern->length++;
    }
    return 0;
}

static int pattern_matches_at(const byte_pattern *pattern, const uint8_t *candidate)
{
    for (size_t i = 0; i < pattern->length; i++)
        if ((candidate[i] & pattern->mask[i]) != pattern->bytes[i])
            return 0;
    return 1;
}

/*
 * Searches every executable region for the pattern.
 * Returns how many times it was found (or -1 if the pattern is all wildcards), and stores
 * the address of the first match in *first_match.
 */
static int find_pattern(const memory_region *regions, int region_count,
                        const byte_pattern *pattern, uint8_t **first_match)
{
    /* Use the first fixed byte as an "anchor" so memchr can skip ahead quickly. */
    size_t anchor = 0;
    while (anchor < pattern->length && pattern->mask[anchor] == 0x00)
        anchor++;
    if (anchor == pattern->length)
        return -1;

    int match_count = 0;

    for (int r = 0; r < region_count; r++) {
        const memory_region *region = &regions[r];
        if (!(region->protection & PROT_EXEC) || region->length < pattern->length)
            continue;

        /* A match may start anywhere from region->start to last_start (inclusive). */
        uint8_t *last_start = region->start + region->length - pattern->length;
        uint8_t *search = region->start + anchor;
        uint8_t *search_end = last_start + anchor + 1;

        while (search < search_end) {
            uint8_t *hit = memchr(search, pattern->bytes[anchor], (size_t)(search_end - search));
            if (!hit)
                break;

            uint8_t *candidate = hit - anchor;
            if (pattern_matches_at(pattern, candidate)) {
                if (match_count == 0)
                    *first_match = candidate;
                match_count++;
            }
            search = hit + 1;
        }
    }
    return match_count;
}

/* ============================================================================================
 * Verification
 * ========================================================================================== */

/* True if [address, address + length) lies entirely inside one readable region. */
static int is_readable(const memory_region *regions, int region_count,
                       const void *address, size_t length)
{
    uintptr_t addr = (uintptr_t)address;

    for (int r = 0; r < region_count; r++) {
        uintptr_t start = (uintptr_t)regions[r].start;
        uintptr_t end = start + regions[r].length;
        if ((regions[r].protection & PROT_READ) && addr >= start && addr + length <= end)
            return 1;
    }
    return 0;
}

/*
 * Does the function at `function` load the address of UUID_FORMAT near its start?
 *
 * We look for a RIP-relative LEA instruction ("lea reg, [rip + offset]", encoded as
 * 48/4C 8D modrm disp32) and check whether the address it points to holds UUID_FORMAT.
 */
static int references_uuid_format(const memory_region *regions, int region_count,
                                  const uint8_t *function)
{
    if (!is_readable(regions, region_count, function, HELPER_SEARCH_LENGTH))
        return 0;

    for (size_t i = 0; i + 7 <= HELPER_SEARCH_LENGTH; i++) {
        uint8_t rex = function[i];
        uint8_t opcode = function[i + 1];
        uint8_t modrm = function[i + 2];

        int is_lea_rip_relative = (rex == 0x48 || rex == 0x4C) && opcode == 0x8D &&
                                  (modrm & 0xC7) == 0x05;
        if (!is_lea_rip_relative)
            continue;

        /* The offset is relative to the end of the 7-byte instruction. */
        int32_t offset;
        memcpy(&offset, function + i + 3, sizeof offset);
        const char *target = (const char *)(function + i + 7 + offset);

        if (is_readable(regions, region_count, target, sizeof UUID_FORMAT) &&
            memcmp(target, UUID_FORMAT, sizeof UUID_FORMAT) == 0)
            return 1;
    }
    return 0;
}

/* ============================================================================================
 * Patching
 * ========================================================================================== */

/*
 * Copies `count` bytes over the code at `destination`.
 *
 * Code is normally read-only, so we temporarily make the surrounding memory pages writable,
 * write the bytes, then put the original protection back.
 */
static int overwrite_code(const memory_region *regions, int region_count,
                          uint8_t *destination, const uint8_t *source, size_t count)
{
    /* Remember the protection the code had, so we can restore it afterwards. */
    int original_protection = PROT_READ | PROT_EXEC;
    for (int r = 0; r < region_count; r++) {
        uint8_t *start = regions[r].start;
        if (destination >= start && destination + count <= start + regions[r].length)
            original_protection = regions[r].protection;
    }

    /* mprotect works on whole pages, so round the range out to page boundaries. */
    uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
    uintptr_t first_page = (uintptr_t)destination & ~(page_size - 1);
    uintptr_t end_page = ((uintptr_t)destination + count + page_size - 1) & ~(page_size - 1);
    void *pages = (void *)first_page;
    size_t pages_length = end_page - first_page;

    if (mprotect(pages, pages_length, PROT_READ | PROT_WRITE) != 0) {
        log_message("Could not make the game's code writable: %s", strerror(errno));
        return -1;
    }

    memcpy(destination, source, count);
    __builtin___clear_cache((char *)destination, (char *)destination + count);

    if (mprotect(pages, pages_length, original_protection) != 0) {
        log_message("Could not restore the game's code protection: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ============================================================================================
 * Main logic
 *
 * Kept separate from the start-up code below so the offline test can feed it a game
 * binary loaded from disk instead of the running game.
 * ========================================================================================== */

/* `base` is the address the executable was loaded at; it is only used to print offsets
 * that can be compared against a disassembler. */
static bg3ach_result bg3ach_apply(const memory_region *regions, int region_count, uintptr_t base)
{
    /* Step 1: find the mod check. */
    byte_pattern pattern;
    if (parse_pattern(MOD_CHECK_SIGNATURE, &pattern) != 0 ||
        pattern.bytes[CALL_OFFSET_IN_SIGNATURE] != 0xE8) {
        log_message("Internal error: the built-in signature is malformed.");
        return BG3ACH_BAD_SIGNATURE;
    }

    uint8_t *mod_check = NULL;
    int matches = find_pattern(regions, region_count, &pattern, &mod_check);
    if (matches == 0) {
        log_message("Could not find the mod check. The game may have been updated, or it is "
                    "already patched. Nothing was changed.");
        return BG3ACH_NOT_FOUND;
    }
    if (matches > 1) {
        log_message("The mod check signature matched %d places, so it is not safe to guess "
                    "which one is right. Nothing was changed.", matches);
        return BG3ACH_AMBIGUOUS;
    }
    log_message("Found the mod check at offset 0x%lx.",
                (unsigned long)((uintptr_t)mod_check - base));

    /* Step 2: make sure it is really the mod check, by following its call to the
     * whitelist helper and checking that the helper formats module UUIDs. */
    uint8_t *call = mod_check + CALL_OFFSET_IN_SIGNATURE;
    int32_t call_distance;
    memcpy(&call_distance, call + 1, sizeof call_distance);
    uint8_t *helper = call + 5 + call_distance; /* relative to the end of the 5-byte call */

    if (references_uuid_format(regions, region_count, helper)) {
        log_message("Verified: the helper at offset 0x%lx works with module UUIDs.",
                    (unsigned long)((uintptr_t)helper - base));
    } else if (env_flag_set("BG3ACH_NOVERIFY")) {
        log_message("WARNING: could not verify the mod check, patching anyway because "
                    "BG3ACH_NOVERIFY is set.");
    } else {
        log_message("Could not verify that this is the mod check, so nothing was changed. "
                    "Set BG3ACH_NOVERIFY=1 to patch anyway.");
        return BG3ACH_VERIFY_FAILED;
    }

    /* Step 3: replace the start of the mod check with "return false". */
    if (env_flag_set("BG3ACH_DRYRUN")) {
        log_message("Dry run (BG3ACH_DRYRUN is set): not patching.");
        return BG3ACH_OK;
    }
    if (overwrite_code(regions, region_count, mod_check, RETURN_FALSE, sizeof RETURN_FALSE) != 0)
        return BG3ACH_PATCH_FAILED;

    log_message("Patched: the game now always reports no mods loaded. Achievements are enabled.");
    return BG3ACH_OK;
}

/* ============================================================================================
 * Start-up: runs automatically when the library is loaded into a process
 * ========================================================================================== */

#ifndef BG3ACH_NO_CTOR /* the offline test defines this and provides its own main() */

typedef struct {
    memory_region regions[MAX_REGIONS];
    int region_count;
    uintptr_t base;
    int done;
} main_executable_info;

/*
 * Callback for dl_iterate_phdr(), which reports every loaded object in turn. The first one
 * is always the main executable; we record its loaded segments and ignore the rest.
 */
static int record_main_executable(struct dl_phdr_info *object, size_t size, void *data)
{
    (void)size;
    main_executable_info *info = data;

    if (info->done)
        return 1;
    info->done = 1;
    info->base = object->dlpi_addr;

    for (int i = 0; i < object->dlpi_phnum && info->region_count < MAX_REGIONS; i++) {
        const ElfW(Phdr) *segment = &object->dlpi_phdr[i];
        if (segment->p_type != PT_LOAD)
            continue;

        memory_region *region = &info->regions[info->region_count++];
        region->start = (uint8_t *)(object->dlpi_addr + segment->p_vaddr);
        region->length = segment->p_filesz; /* only bytes from the file are worth searching */
        region->protection = ((segment->p_flags & PF_R) ? PROT_READ : 0) |
                             ((segment->p_flags & PF_W) ? PROT_WRITE : 0) |
                             ((segment->p_flags & PF_X) ? PROT_EXEC : 0);
    }
    return 1; /* stop iterating */
}

/* True if the current process's executable is the one we should patch. */
static int is_target_process(char *exe_path, size_t exe_path_size)
{
    ssize_t length = readlink("/proc/self/exe", exe_path, exe_path_size - 1);
    if (length <= 0)
        return 0;
    exe_path[length] = '\0';

    const char *slash = strrchr(exe_path, '/');
    const char *exe_name = slash ? slash + 1 : exe_path;

    const char *wanted = getenv("BG3ACH_EXE");
    if (!wanted || !*wanted)
        wanted = "bg3";

    return strcmp(exe_name, wanted) == 0;
}

__attribute__((constructor)) static void bg3ach_on_load(void)
{
    if (env_flag_set("BG3ACH_DISABLE"))
        return;

    /* LD_PRELOAD is passed on to every program the launcher starts (shell scripts, crash
     * reporters, ...). Only touch the game itself. */
    char exe_path[4096];
    if (!is_target_process(exe_path, sizeof exe_path))
        return;

    const char *log_path = getenv("BG3ACH_LOG");
    if (log_path && *log_path)
        log_file = fopen(log_path, "a"); /* if this fails we fall back to stderr */

    char timestamp[32];
    time_t now = time(NULL);
    strftime(timestamp, sizeof timestamp, "%Y-%m-%d %H:%M:%S", localtime(&now));
    log_message("%s - starting in %s (pid %d)", timestamp, exe_path, (int)getpid());

    main_executable_info info = {0};
    dl_iterate_phdr(record_main_executable, &info);
    bg3ach_apply(info.regions, info.region_count, info.base);

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

#endif /* BG3ACH_NO_CTOR */
