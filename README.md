# bg3-ach-enabler

Allow achievements in **Baldur's Gate 3** while playing with mods, on the **native Linux**
version of the game.

BG3 turns achievements off as soon as you load a mod that isn't on its built-in whitelist.
`libbg3ach.so` is a small library, loaded with `LD_PRELOAD`, that switches that check off
in memory when the game starts. No game files are modified, and the change is gone when
you close the game.

> **Native Linux only.** This patches the Linux `bg3` executable. It has no effect on the
> Windows version running through Proton.

## Quick start

1. **Build it.** You need a C compiler (`gcc` or `clang`) and `make`.

   ```sh
   make
   ```

   This creates `build/libbg3ach.so`.

2. **Tell Steam to load it.** Right-click Baldur's Gate 3 → *Properties* →
   *Launch Options*, and enter (using the full path):

   ```
   LD_PRELOAD="/full/path/to/build/libbg3ach.so:$LD_PRELOAD" %command%
   ```

   The `:$LD_PRELOAD` part keeps anything Steam already loads, such as the overlay.

3. **Play.** Start the game as usual, then check the log (below) to confirm it worked.

To uninstall, clear the launch options.

## Checking that it worked

The library prints a few lines starting with `[bg3ach]` when the game starts. Steam
hides that output, so use `BG3ACH_LOG` to save it to a file:

```
BG3ACH_LOG=/tmp/bg3ach.log LD_PRELOAD="/full/path/to/build/libbg3ach.so:$LD_PRELOAD" %command%
```

A successful run looks like this:

```
[bg3ach] 2026-11-06 23:41:46 - starting in /.../Baldurs Gate 3/bin/bg3 (pid 12345)
[bg3ach] Found the mod check at offset 0x37675d0.
[bg3ach] Verified: the helper at offset 0x3767640 works with module UUIDs.
[bg3ach] Patched: the game now always reports no mods loaded. Achievements are enabled.
```

(The offsets are positions in the game's code and will be different after a game update.)

If something goes wrong, the library logs why and leaves the game untouched:

| Message                                       | Likely cause                                         |
|-----------------------------------------------|------------------------------------------------------|
| *Could not find the mod check*                | A game update changed the code; this library needs updating |
| *The mod check signature matched N places*    | Not sure which match is right, so it won't guess     |
| *Could not verify that this is the mod check* | The match doesn't look like the real check           |
| *Could not make the game's code writable*     | The system refused the change (e.g. a security policy) |

The game always keeps running normally. You just won't get achievements with mods until
it's fixed.

## Testing without launching the game

`make test` tries the whole patch against a copy of the game executable, without running
the game. By default it uses `bin/bg3` in this folder (which git ignores):

```sh
make test
make test GAME="$HOME/.local/share/Steam/steamapps/common/Baldurs Gate 3/bin/bg3"
```

It loads the executable into memory the same way Linux would, applies the patch, then
checks a second time to make sure the patch actually took. It prints `PASS` if
everything worked. This is the quickest way to find out whether a game update broke things.

## Versioning

Releases are tagged with the **minimum game version they were tested against**, rather than a
separate version number of their own. For example, the tag `4.1.1.7631656` means
`make test` passed against BG3 version 4.1.1.7631656.

To build a specific release, check out its tag:

```sh
git checkout 4.1.1.7631656
make
```

**Which release should I use?**

- If a tag matches your game version, use that one.
- If your game is newer than every tag, try the latest tag. The patch often keeps working
  across game updates. Run `make test` against your copy of the game: if it prints `PASS`,
  you're good.
- If it doesn't pass, the signature needs updating for the new game version. Once it
  passes again, that commit is tagged with the new game version.

## Settings

Settings are environment variables. Put them in front of `%command%` in the launch options:

| Variable            | What it does                                                        |
|---------------------|---------------------------------------------------------------------|
| `BG3ACH_LOG=<file>` | Save log messages to this file                                      |
| `BG3ACH_DISABLE=1`  | Turn the library off without removing it                            |
| `BG3ACH_DRYRUN=1`   | Find and check the mod check, but don't change anything             |
| `BG3ACH_NOVERIFY=1` | Skip the safety check (step 3 below). Only use this if you know why |
| `BG3ACH_EXE=<name>` | Act on an executable with a different name (default: `bg3`)         |

## How it works

Before unlocking an achievement, the game calls a function that goes through every loaded
mod and checks it against the whitelist. If any mod isn't on the list, the function
returns `true` and the achievement is skipped.

When the game starts, before any of its own code runs, the library:

1. **Makes sure this is the game.** Steam's launch options apply to every program the
   launch command starts, not just the game. The library ignores anything not named `bg3`.
2. **Finds the function.** It searches the game's code for a known pattern of machine-code
   bytes. Parts that tend to change between game versions are treated as wildcards. The
   pattern must match exactly one place, or nothing is changed.
3. **Double-checks it.** The function calls a helper for each mod, and that helper should
   use the text format for mod IDs (`%08x-%04hx-...`). If it doesn't, nothing is changed.
4. **Patches it.** It temporarily makes that bit of code writable, replaces the first three
   bytes with `return false` (`xor eax, eax; ret`), and makes it read-only again.

The full pattern is in [`src/bg3ach.c`](src/bg3ach.c), with one instruction per line and a
note on what each does.

## Building

```sh
make          # build the library: build/libbg3ach.so
make test     # offline test against bin/bg3 (or GAME=...)
make debug    # offline test with extra memory-error checking (ASan + UBSan)
make clean    # delete build/
make help     # list these commands
```

## Project layout

```
src/bg3ach.c          the library (all of the logic lives here)
tests/test_offline.c  the offline test (make test)
bin/bg3               your copy of the game executable, for testing (not committed)
```
