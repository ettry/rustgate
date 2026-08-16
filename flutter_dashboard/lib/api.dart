import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';

import 'models.dart';

/// RustGate 管理 API + WebSocket 客户端。
///
/// 默认地址 http://127.0.0.1:9001，可通过 `baseUrl` / `wsUrl` 覆盖。
/// token 需与 RustGate 启动时的 `RUSTGATE_API_TOKEN` 一致。
class RustGateApi {
  final String baseUrl;
  final String wsUrl;
  final String token;
  WebSocketChannel? _channel;

  RustGateApi({
    this.baseUrl = 'http://127.0.0.1:9001',
    this.wsUrl = 'ws://127.0.0.1:9001',
    this.token = 'dev-token-change-me',
  });

  Uri _u(String path) => Uri.parse('$baseUrl$path');

  Map<String, String> get _headers => {
        'Authorization': 'Bearer $token',
        'Content-Type': 'application/json',
      };

  Future<Stats> fetchStats() async {
    final resp = await http.get(_u('/api/stats'), headers: _headers);
    if (resp.statusCode != 200) {
      throw Exception(_friendlyError(resp.statusCode));
    }
    return Stats.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
  }

  Future<List<Alert>> fetchAlerts() async {
    final resp = await http.get(_u('/api/alerts'), headers: _headers);
    if (resp.statusCode != 200) {
      throw Exception(_friendlyError(resp.statusCode));
    }
    final list = jsonDecode(resp.body) as List<dynamic>;
    return list
        .map((e) => Alert.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// 把 HTTP 状态码翻译成人类可读的错误。
  String _friendlyError(int code) {
    switch (code) {
      case 401:
        return '认证失败(401)：token 与 WAF 的 RUSTGATE_API_TOKEN 不一致，请到「连接设置」修改 token';
      case 404:
        return '接口不存在(404)：请确认 WAF 管理 API 地址与端口正确';
      default:
        return '请求失败($code)';
    }
  }

  /// 建立实时告警流；返回的流把每条 JSON 文本解析成 [Alert]。
  ///
  /// WebSocket 握手时的 Authorization 通过 query 参数携带（某些 WS 客户端
  /// 无法自定义握手 header，故用 `?token=` 传递）。
  Stream<Alert> alertStream() {
    final uri = Uri.parse('$wsUrl/ws/alerts?token=${Uri.encodeQueryComponent(token)}');
    _channel = WebSocketChannel.connect(uri);
    return _channel!.stream.map((data) {
      final json = jsonDecode(data as String) as Map<String, dynamic>;
      return Alert.fromJson(json);
    });
  }

  void dispose() {
    _channel?.sink.close();
  }
}
