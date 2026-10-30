# 配方包（recipes/）

> 一个**配方包** = 一份 `pack.json`：官方 `--payload-file` 条目（[D24] schema）+ 元信息
> （目标特征 / 修复建议 / A/B 验证口径）。规范与红线见 [docs/配方包规范.md](../docs/配方包规范.md)。

## 现有哪些

| 目录 | 说明 |
|---|---|
| `demo-postgres-wrapper/` | **演示配方**（`demo: true`）：验证「加载 → 追加 → 硬拒」三条路径。**不是任何真实产品的 CVE 指纹** |

## 用法

```bash
# 1) 校验全部配方（CI / 收口清单用）
node scripts/recipe-pack.mjs --check

# 2) 导出成引擎可直接吃的 --payload-file
node scripts/recipe-pack.mjs --export recipes/demo-postgres-wrapper --out /tmp/demo.json

# 3) 带着配方扫（条目只追加；高危池硬门照旧生效）
node server/bin/cli.js -u "http://127.0.0.1:8130/items?cat=1" --payload-file /tmp/demo.json
```

## 写一个新配方前先读这三条

1. **没有真机验证就不写 CVE 号**：`demo: true` 的包**禁止**带 `cve` 字段（`--check` 会红）。
   要写 `CVE-xxxx-yyyy`，必须补 `affected` + `ab`（修前命中 / 修后 0）+ 真机证据。
2. **破坏性条目不进配方**：模板里出现写操作/删表等高危语句时，必须 `risk: 3` 且写清副作用；
   `--check` 对 `risk < 3` 的破坏性条目直接判红。
3. **配方只追加**：id 与内置注册表冲突、或包内 id 重复 ⇒ 引擎与校验器都会硬拒（不静默覆盖）。
