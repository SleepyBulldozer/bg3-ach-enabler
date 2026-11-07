/*
 * Offline test for bg3ach: checks that the patch would work against a given game binary,
 * without launching the game.
 *
 *   usage: test_offline <path/to/bg3>
 *
 * It loads the executable's segments into memory at the same relative positions the
 * system loader would use, then runs exactly the same find / verify / patch logic as the
 * real library. Finally it runs that logic a second time: if the first patch really landed,
 * the signature should be gone and the second run should report "not found".
 *
 * Exit code: 0 on success, otherwise the bg3ach_result of the failing step (or 10 if the
 * second run unexpectedly found the signature again).
 */

/* Pull in the library source directly so we can call its internal (static) functions.
 * BG3ACH_NO_CTOR stops it from trying to patch this test program when it starts. */
#define BG3ACH_NO_CTOR
#include "bg3ach.c"

#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Maps the file read-only. Returns NULL (after printing why) on failure. */
static uint8_t *map_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    struct stat info;
    if (fstat(fd, &info) != 0) {
        fprintf(stderr, "Cannot read %s: %s\n", path, strerror(errno));
        close(fd);
        return NULL;
    }

    uint8_t *data = mmap(NULL, (size_t)info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) {
        fprintf(stderr, "Cannot map %s: %s\n", path, strerror(errno));
        return NULL;
    }

    if (info.st_size < (off_t)sizeof(Elf64_Ehdr) || memcmp(data, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s is not an ELF executable\n", path);
        return NULL;
    }
    return data;
}

/*
 * Copies each loadable segment of the ELF file into a fresh block of memory, at the same
 * offsets the loader would use, and describes them in `regions`.
 * Returns the number of regions, or -1 on failure. *base receives the image's start address.
 */
static int load_segments(const uint8_t *file, memory_region *regions, uintptr_t *base)
{
    const Elf64_Ehdr *header = (const Elf64_Ehdr *)file;
    const Elf64_Phdr *segments = (const Elf64_Phdr *)(file + header->e_phoff);

    /* How much memory the whole image needs. */
    uint64_t image_size = 0;
    for (int i = 0; i < header->e_phnum; i++) {
        uint64_t segment_end = segments[i].p_vaddr + segments[i].p_memsz;
        if (segments[i].p_type == PT_LOAD && segment_end > image_size)
            image_size = segment_end;
    }

    uint64_t page_size = (uint64_t)sysconf(_SC_PAGESIZE);
    image_size = (image_size + page_size - 1) & ~(page_size - 1);

    uint8_t *image = mmap(NULL, image_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED) {
        fprintf(stderr, "Cannot allocate %lu bytes for the image: %s\n",
                (unsigned long)image_size, strerror(errno));
        return -1;
    }

    int count = 0;
    for (int i = 0; i < header->e_phnum && count < MAX_REGIONS; i++) {
        const Elf64_Phdr *segment = &segments[i];
        if (segment->p_type != PT_LOAD)
            continue;

        memcpy(image + segment->p_vaddr, file + segment->p_offset, segment->p_filesz);

        regions[count].start = image + segment->p_vaddr;
        regions[count].length = segment->p_filesz;
        regions[count].protection = ((segment->p_flags & PF_R) ? PROT_READ : 0) |
                                    ((segment->p_flags & PF_X) ? PROT_EXEC : 0);
        count++;
    }

    /* Make the copy read-only, like real loaded code, so the patch has to go through the
     * same make-writable / restore steps as it does in the game. (Execute permission isn't
     * needed: we only read and write these bytes, never run them.) */
    for (int i = 0; i < count; i++) {
        uintptr_t first_page = (uintptr_t)regions[i].start & ~(page_size - 1);
        uintptr_t end_page = ((uintptr_t)regions[i].start + regions[i].length + page_size - 1) &
                             ~(page_size - 1);
        mprotect((void *)first_page, end_page - first_page, PROT_READ);
    }

    *base = (uintptr_t)image;
    return count;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path/to/bg3>\n", argv[0]);
        return 1;
    }

    /* Log messages go to stderr; flush our own output line by line so the two stay in order. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    uint8_t *file = map_file(argv[1]);
    if (!file)
        return 1;

    memory_region regions[MAX_REGIONS];
    uintptr_t base;
    int region_count = load_segments(file, regions, &base);
    if (region_count < 0)
        return 1;

    printf("Run 1: find, verify and patch\n");
    bg3ach_result first = bg3ach_apply(regions, region_count, base);
    if (first != BG3ACH_OK) {
        printf("FAIL: the patch could not be applied (result %d)\n", first);
        return first;
    }

    printf("Run 2: the signature should now be gone\n");
    bg3ach_result second = bg3ach_apply(regions, region_count, base);
    if (second != BG3ACH_NOT_FOUND) {
        printf("FAIL: expected 'not found' on the second run, got result %d\n", second);
        return 10;
    }

    printf("PASS\n");
    return 0;
}
