# Print sample — Prometheus obfuscation

- `print_sample.lua` — original sample script (benign demo: prints a greeting, a sum, and pi)
- `print_sample.obfuscated.lua` — output produced by [Prometheus](https://github.com/prometheus-lua/Prometheus) Lua obfuscator

Generated with:

```bash
lua cli.lua --preset Medium --out print_sample.obfuscated.lua print_sample.lua
```

Verified: the obfuscated script runs under LuaJIT and prints the same output as the original.
