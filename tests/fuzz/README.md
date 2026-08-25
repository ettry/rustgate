# RustGate Fuzz 测试

对规则引擎（`Engine::inspect` + `NormalizedRequest::from_parts`）做随机输入模糊测试，
断言任意字节流不会导致 panic / 崩溃。

## 运行

需要 nightly 工具链和 cargo-fuzz：

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
cargo +nightly fuzz run engine_fuzz -- -max_len=512 -runs=20000
```

## 目录说明

| 路径 | 是否入库 | 说明 |
|---|---|---|
| `fuzz_targets/engine_fuzz.rs` | ✅ 入库 | fuzz 目标源码 |
| `Cargo.toml` / `Cargo.lock` | ✅ 入库 | fuzz 工作空间依赖锁定 |
| `corpus/` | ❌ 忽略 | 运行产生的语料库（体积大、环境相关） |
| `artifacts/` | ❌ 忽略 | 运行产生的崩溃样本（发现 crash 时再单独处理） |
| `target/` | ❌ 忽略 | 构建产物 |

## 崩溃样本处理

若 fuzz 发现 crash，样本会写入 `artifacts/engine_fuzz/`。
复现命令：

```bash
cd fuzz
cargo +nightly fuzz run engine_fuzz artifacts/engine_fuzz/<crash-file>
```

修复后应把最小复现样本固化为单元测试，加入 `src/engine.rs` 的测试模块。
