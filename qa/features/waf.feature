# language: zh-CN
功能: RustGate WAF 核心防护能力
  作为安全防护系统
  我希望检测并拦截常见 Web 攻击
  以便保护后端服务不受侵害

  背景:
    假设 WAF 已启动并监听 127.0.0.1:19009
    并且 后端服务运行在 127.0.0.1:18088
    并且 管理 API token 为 "qatest"

  场景: 正常请求应放行
    当 客户端 GET /index.html
    那么 响应状态码应为 200

  场景: SQL 注入（小写）应被拦截
    当 客户端 GET "/?q=1+union+select"
    那么 响应状态码应为 403

  场景: SQL 注入大小写绕过应被拦截
    当 客户端 GET "/?q=1+UNION+SELECT"
    那么 响应状态码应为 403

  场景: XSS script 标签应被拦截
    当 客户端 POST body 为 "<script>alert(1)</script>"
    那么 响应状态码应为 403

  场景: 路径穿越应被拦截
    当 客户端 GET "/../../etc/passwd" 且保留原始路径
    那么 响应状态码应为 403

  场景: 命令注入应被拦截
    当 客户端 GET "/?q=;cat+/etc/passwd"
    那么 响应状态码应为 403

  场景: NUL 截断绕过应被拦截
    当 客户端 GET "/?q=1+union%00select"
    那么 响应状态码应为 403

  场景: 大请求体应流式透传
    当 客户端 POST 300KB 随机字节
    那么 响应状态码应为 200
    并且 后端应收到完整 300KB 数据

  场景: 管理 API 需要鉴权
    当 客户端 GET /api/stats 且无 Authorization 头
    那么 响应状态码应为 401
    当 客户端 GET /api/stats 且 Authorization 为 "Bearer qatest"
    那么 响应状态码应为 200
