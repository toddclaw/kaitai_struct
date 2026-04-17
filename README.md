# Kaitai Struct → Wireshark Lua Pipeline

Convert `.ksy` binary format descriptions into Wireshark Lua dissector plugins.

## Requirements (target system)

- **Java 8+** (for kaitai-struct-compiler)
- **Python 3** with `pyyaml` and `jinja2`

No compilation or build tools required.

## Quick Start

```bash
./compile_wireshark.sh your_protocol.ksy your_protocol.lua
```

Then copy `your_protocol.lua` to your Wireshark plugins directory:
- Linux: `~/.local/lib/wireshark/plugins/`
- macOS: `~/.config/wireshark/plugins/`
- Windows: `%APPDATA%\Wireshark\plugins\`

## Contents

| Path | Description |
|------|-------------|
| `compiler/kaitai-struct-compiler-0.11/` | Pre-built kaitai-struct-compiler v0.11 |
| `compiler/kaitai-struct-compiler-0.11/lib/io.kaitai.kaitai-struct-compiler-0.11.jar` | Main compiler JAR |
| `kaitai-to-wireshark/convert.py` | Python Wireshark Lua converter |
| `compile_wireshark.sh` | Wrapper script |
| `test_sample.ksy` | Example .ksy protocol definition |

## Using the compiler for other targets

The kaitai-struct-compiler supports many output languages (Python, Java, C++, Go, etc.):

```bash
# List available targets
compiler/kaitai-struct-compiler-0.11/bin/kaitai-struct-compiler --help

# Compile to Python
compiler/kaitai-struct-compiler-0.11/bin/kaitai-struct-compiler -t python your_protocol.ksy

# Compile to Lua (generic, not Wireshark-specific)
compiler/kaitai-struct-compiler-0.11/bin/kaitai-struct-compiler -t lua your_protocol.ksy
```

## Notes

- The Wireshark dissector output from `kaitai-to-wireshark` is a prototype — it supports basic types (`u1`, `u2`, `u3`, `contents`, `size`) and is intended as a starting point for customization.
- The compiler JAR requires all JARs in `compiler/.../lib/` to be present — use the launcher script, not the JAR directly.
- `kaitai-to-wireshark/template.lua` can be edited to customize the generated dissector structure.
