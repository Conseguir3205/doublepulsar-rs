## DoublePulsar

Cobalt Strike User-Defined Reflective Loader (UDRL) in Rust, implementing Shellcode Reflective DLL Injection (sRDI). A ~65KB position-independent reflective loader with module stomping, synthetic call stack spoofing, sleep obfuscation, memory encryption, return address spoofing, IAT hooking, and heap isolation.

Named after [DoublePulsar](https://en.wikipedia.org/wiki/DoublePulsar), an implant developed by the NSA's [Equation Group](https://en.wikipedia.org/wiki/Equation_Group), leaked by the Shadow Brokers in 2017.

## Credits

- [Raphael Mudge](https://www.cobaltstrike.com/profile/raphael-mudge) and [Cobalt Strike](https://www.cobaltstrike.com/) - User-Defined Reflective Loader API
- [Revisiting the UDRL Part 1](https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development) by Robert Bearsby / [Cobalt Strike](https://www.cobaltstrike.com/) - Prepended loader architecture diagram
- [Red Team Ops II](https://www.zeropointsecurity.co.uk/course/red-team-ops-ii) by [RastaMouse](https://github.com/rasta-mouse) / [Zero Point Security](https://www.zeropointsecurity.co.uk/) - CRTO II course and advanced Cobalt Strike training
- [AceLdr](https://github.com/kyleavery/AceLdr/) by [Kyle Avery](https://github.com/kyleavery) - IAT hooking, return address spoofing, heap isolation
- [TitanLdr](https://github.com/benheise/TitanLdr) by [Austin Hudson](https://github.com/realoriginal) - FOLIAGE sleep obfuscation, memory encryption
- [FOLIAGE](https://github.com/benheise/FOLIAGE) by [Austin Hudson](https://github.com/realoriginal) - FOLIAGE sleep obfuscation
- [titanldr-ng](https://github.com/klezVirus/titanldr-ng) by [Austin Hudson](https://github.com/realoriginal) - CNA integration, RC4 beacon encryption
- [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk) by [klezVirus](https://github.com/klezVirus), [trickster0](https://github.com/trickster0), and [waldo-irc](https://github.com/waldo-irc) - Call stack spoofing
- [Ekko](https://github.com/Cracked5pider/Ekko) by [Cracked5pider](https://github.com/Cracked5pider) - Ekko sleep obfuscation technique
- [Crystal-Kit](https://github.com/rasta-mouse/Crystal-Kit) by [RastaMouse](https://github.com/rasta-mouse) - Cobalt Strike kit reference
- [uwd](https://github.com/joaoviictorti/uwd) and [hypnus](https://github.com/joaoviictorti/hypnus) by [Joao Victor](https://github.com/joaoviictorti) - Original unwinder and sleep obfuscation crates, rewritten and converted to position-independent code (PIC)
- [x64 return address spoofing](https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html) by [namazso](https://github.com/namazso) - Original return address spoofing technique
- [Gargoyle](https://github.com/JLospinoso/gargoyle) by [J. Lospinoso](https://github.com/JLospinoso) - Timer-based code execution
- [MalMemDetect](https://github.com/waldo-irc/MalMemDetect) by [waldo-irc](https://github.com/waldo-irc) - Malicious memory detection
- [Bypassing PE-sieve and Moneta](https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/) by Arash Parsa
- [Hook heaps and live free](https://www.arashparsa.com/hook-heaps-and-live-free/) by Arash Parsa
- [Masking malicious memory artifacts](https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta) by Forrest Orr
- [Hunting Gargoyle](https://blog.f-secure.com/hunting-for-gargoyle-memory-scanning-evasion/) by F-Secure
- [Detecting Cobalt Strike with memory signatures](https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures) by Elastic
- [MDSec Nighthawk study](https://web.archive.org/web/20220625003531/https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html) - Ekko sleep obfuscation research
- [Equation Group / NSA](https://en.wikipedia.org/wiki/Equation_Group) - Original DoublePulsar implant concept

## Prepended Loader Architecture

Unlike Stephen Fewer's original approach where the reflective loader lives inside the PE's `.text` section, DoublePulsar uses a prepended architecture where the `ReflectiveLoader()` is placed before the PE file. This allows the loader to be fully position-independent shellcode that decrypts and maps the beacon payload at runtime.

![Prepended vs Embedded Reflective Loader](image/diagram_different-locations-of-reflective-loader-1024x483.png)

*Diagram from [Revisiting the UDRL Part 1](https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development) by Robert Bearsby / [Cobalt Strike](https://www.cobaltstrike.com/)*

## Features

- Position-independent Rust reflective loader for Cobalt Strike (prepended loader)
- Module stomping (loads beacon into a legitimate module's memory, enabled by default)
- Synthetic call stack spoofing (randomized per call, enabled by default via `spoof-uwd`). Either module stomping or call stack spoofing is needed, but module stomping is preferred. Call stack spoofing serves as a fallback
- Dynamic memory encryption (new heap for beacon allocations, encrypted during sleep)
- Code obfuscation and encryption (non-executable + encrypted during sleep)
- Return address spoofing (InternetConnectA, NtWaitForSingleObject, RtlAllocateHeap)
- IAT hooking
- Heap isolation
- RC4 encryption via SystemFunction032
- Optional syscall dispatch (cringe, but it's there :roll_eyes:) (`spoof-syscall` feature, requires `spoof-uwd`). Uses [Hell's Gate](https://github.com/am0nsec/HellsGate) for direct syscalls when unhooked, falls back to Halo's Gate / [Tartarus Gate](https://github.com/trickster0/TartarusGate) for indirect syscalls when hooks are detected
- Multiple sleep obfuscation techniques:

| Feature | Technique | Description |
|---------|-----------|-------------|
| `sleep-ekko` | Ekko | Timer-based (TpAllocTimer/TpSetTimer) + RC4 + NtContinue chain + fiber support **(default)** |
| `sleep-foliage` | FOLIAGE | APC-based (NtQueueApcThread) + RC4 + NtContinue chain + fiber support |
| `sleep-zilean` | Zilean | Wait-based (TpAllocWait/TpSetWait) + RC4 + NtContinue chain + fiber support |
| `sleep-xor` | XOR | XOR section masking + plain Sleep (no CONTEXT chain, no fiber mode) |

## How It Works

Import the `Titan.cna` script before generating shellcode. The script:
1. Takes your raw beacon payload
2. RC4 encrypts it with a random 16-byte key
3. Appends `[CONFIG (key + size)][Encrypted Beacon]` to the loader
4. At runtime, the loader decrypts the beacon in-memory and executes it

## Building

x64 only. x86 is not supported.

Recommended: build on Ubuntu/WSL to avoid MinGW relocation issues on Windows.

### Requirements

- Rust nightly with `x86_64-pc-windows-gnu` target
- MinGW-w64
- [cargo-make](https://github.com/sagiegurari/cargo-make)
- nasm

### Ubuntu/WSL Setup (Recommended)

```bash
# Install Rust nightly and add target
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
rustup default nightly
rustup target add x86_64-pc-windows-gnu

# Install MinGW-w64 and nasm
sudo apt update
sudo apt install -y mingw-w64 nasm

# Install cargo-make
cargo install cargo-make

# Build
cd udrl
cargo make x64
```

### Build Commands

```bash
cargo make x64        # x64 release
cargo make x64-debug  # x64 with debug logging (DbgPrint)
cargo make clean      # clean build artifacts
```

### Sleep Feature Selection

Only enable one sleep feature at a time. They are mutually exclusive. Use `--no-default-features` when selecting a non-default technique.

```bash
# Ekko (default)
cargo make x64

# FOLIAGE
cargo build --release --target x86_64-pc-windows-gnu --features sleep-foliage --no-default-features

# Zilean
cargo build --release --target x86_64-pc-windows-gnu --features sleep-zilean --no-default-features

# XOR (no ROP chain, no fiber)
cargo build --release --target x86_64-pc-windows-gnu --features sleep-xor --no-default-features
```

### Output

```
bin/Titan.x64.bin    - x64 shellcode
```

## Detection

Tested on Windows 10 (Build 19045) and Windows 11 (Build 22631) against Elastic 9.0.1 (trial) in prevention mode with aggressive settings and the following integrations enabled: Elastic Defend, Elastic Agent, Fleet Server, Prebuilt Security Detection Rules, Elastic Synthetics, System, and Windows. Cobalt Strike settings: Stageless Windows Executable, Raw output, x64 payload, Process exit function, winhttp library. Lab environment: [GOAD](https://github.com/Orange-Cyberdefense/GOAD) on [Ludus](https://docs.ludus.cloud/docs/environment-guides/goad).

YARA rules for detection are provided in [doublepulsar.yar](doublepulsar.yar).

## Known Issues

- Not compatible with loaders that rely on the shellcode thread staying alive
- Windows builds may encounter relocation errors with newer MinGW versions (use WSL)
- AllocConsole logging can cause crashes when spammed with too many log entries, use DbgPrint instead

## License and Disclaimer

**License**: MIT. See [LICENSE](./LICENSE)

**Disclaimer**: This project is provided for authorized security testing, educational purposes, and legitimate security research only.

**Permitted use includes:**

- Authorized penetration testing and red team engagements
- Purple teaming, adversary simulation, and threat emulation
- Detection engineering, threat hunting, and security operations
- Blue team and SOC activities including malware reverse engineering
- CTF competitions and security research
- Educational and training purposes

**Prohibited use includes:**

- Unauthorized access to systems or networks
- Any activity that violates applicable laws or regulations
- Use against systems without explicit written authorization

**Liability**: The author assumes no responsibility for misuse, damages, or legal consequences arising from the use of this software. Users are solely responsible for ensuring compliance with all applicable laws, regulations, and organizational policies. By using this software, you agree that you have proper authorization for any systems you interact with.

## Author

[memN0ps](https://github.com/memN0ps)
