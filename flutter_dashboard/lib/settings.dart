import 'dart:convert';
import 'dart:io';

/// 连接配置（token + WAF 管理 API 地址），持久化到本地 JSON 文件。
///
/// 使用 `dart:io` 直接读写文件，不引入额外依赖；Android/iOS 也可用。
class AppSettings {
  final String ip;
  final int port;
  final String token;

  const AppSettings({
    required this.ip,
    required this.port,
    required this.token,
  });

  static const defaults = AppSettings(
    ip: '127.0.0.1',
    port: 9001,
    token: 'dev-token-change-me',
  );

  String get baseUrl => 'http://$ip:$port';
  String get wsUrl => 'ws://$ip:$port';

  AppSettings copyWith({String? ip, int? port, String? token}) {
    return AppSettings(
      ip: ip ?? this.ip,
      port: port ?? this.port,
      token: token ?? this.token,
    );
  }

  /// 配置文件名：跨平台放用户目录，桌面端也可靠。
  static File get _file {
    final home = Platform.environment['HOME'] ?? '.';
    return File('$home/.rustgate_dashboard.json');
  }

  /// 读取磁盘配置，失败或格式错误时回退到默认值。
  static AppSettings load() {
    try {
      if (!_file.existsSync()) return defaults;
      final map = jsonDecode(_file.readAsStringSync()) as Map<String, dynamic>;
      final ip = map['ip'] as String? ?? defaults.ip;
      final port = map['port'] as int? ?? defaults.port;
      final token = map['token'] as String? ?? defaults.token;
      if (ip.isEmpty || port <= 0 || port > 65535) return defaults;
      return AppSettings(ip: ip, port: port, token: token);
    } catch (_) {
      return defaults;
    }
  }

  /// 是否已保存过连接配置。
  ///
  /// 首次启动时文件不存在 → 未配置 → 面板应引导用户去设置页填写
  /// WAF 的 IP/端口/token，而不是拿默认值去连（默认值几乎必然 401）。
  static bool isConfigured() {
    try {
      return _file.existsSync();
    } catch (_) {
      return false;
    }
  }

  /// 保存到磁盘。
  Future<void> save() async {
    await _file.writeAsString(
      jsonEncode({'ip': ip, 'port': port, 'token': token}),
      flush: true,
    );
  }
}
