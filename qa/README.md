# QA / BDD 测试

## 运行 QA 端到端测试

```bash
bash qa/run_qa.sh
```

预期输出 `10 通过, 0 失败`。

## BDD (Gherkin) 场景

`qa/features/waf.feature` 用标准 Gherkin 语法描述防护行为。
每个 `场景` 与 `qa/run_qa.sh` 中的 `check` 用例一一对应：

| Gherkin 场景 | run_qa.sh 用例 |
|---|---|
| 正常请求应放行 | `正常请求放行` |
| SQL 注入（小写）应被拦截 | `SQLi 小写` |
| SQL 注入大小写绕过应被拦截 | `SQLi 大写(大小写绕过)` |
| XSS script 标签应被拦截 | `XSS script 标签` |
| 路径穿越应被拦截 | `路径穿越` |
| 命令注入应被拦截 | `命令注入` |
| NUL 截断绕过应被拦截 | `NUL 截断绕过` |
| 大请求体应流式透传 | `大body跨帧流式(300KB)` |
| 管理 API 需要鉴权 | `管理API鉴权失败/成功` |

> 若需要原生 cucumber 步骤定义（Rust `cucumber` crate 自动执行
> feature 文件），可后续把 run_qa.sh 的断言逻辑映射为步骤函数。
