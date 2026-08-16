# RustGate Dashboard

RustGate WAF 的 Flutter 实时告警面板，通过 WebSocket 接收拦截告警，展示统计、攻击类型分布与来源 IP 榜。

## 运行前提

1. 先启动 RustGate 后端（管理 API 默认监听 `127.0.0.1:9001`，WAF 监听 `127.0.0.1:9000`）：

   ```bash
   cd rustgate
   RUSTGATE_BACKEND=http://127.0.0.1:8080 RUSTGATE_API=127.0.0.1:9001 cargo run -- 127.0.0.1:9000
   ```

2. 启动 Flutter 应用：

   ```bash
   cd flutter_dashboard
   flutter pub get
   flutter run
   ```

## 连接配置

默认连接 `http://127.0.0.1:9001` 与 `ws://127.0.0.1:9001/ws/alerts`。
如需修改，编辑 `lib/api.dart` 中 `RustGateApi` 的构造参数。

> 注意：Android 模拟器访问宿主机需把 `127.0.0.1` 改为 `10.0.2.2`。
