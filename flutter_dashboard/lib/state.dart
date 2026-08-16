import 'dart:async';

import 'package:flutter/foundation.dart';

import 'api.dart';
import 'models.dart';
import 'settings.dart';

/// 面板状态：拉取统计 + 聚合实时告警流。
class DashboardState extends ChangeNotifier {
  AppSettings settings;
  late RustGateApi api;

  Stats? stats;
  final List<Alert> alerts = [];
  final Map<String, int> categoryCount = {};
  StreamSubscription<Alert>? _sub;
  /// 统计卡片定时刷新（每 2 秒拉一次 /api/stats）。
  Timer? _statsTimer;
  /// 最近一次连接/拉取错误，展示在面板顶部。
  String? lastError;

  DashboardState({AppSettings? settings})
      : settings = settings ?? AppSettings.load() {
    final s = this.settings;
    api = RustGateApi(baseUrl: s.baseUrl, wsUrl: s.wsUrl, token: s.token);
  }

  /// 启动：拉一次统计 + 订阅实时告警。
  Future<void> start() async {
    await _connect();
  }

  /// 用新配置重建客户端并重连（设置页保存后调用）。
  Future<void> reconnect(AppSettings newSettings) async {
    settings = newSettings;
    await _disconnect();
    api = RustGateApi(
      baseUrl: newSettings.baseUrl,
      wsUrl: newSettings.wsUrl,
      token: newSettings.token,
    );
    await _connect();
  }

  Future<void> _disconnect() async {
    await _sub?.cancel();
    _sub = null;
    _statsTimer?.cancel();
    _statsTimer = null;
    api.dispose();
    alerts.clear();
    categoryCount.clear();
    stats = null;
    lastError = null;
    notifyListeners();
  }

  Future<void> _connect() async {
    await refreshStats();
    try {
      final recent = await api.fetchAlerts();
      alerts.addAll(recent);
      _recount();
      notifyListeners();
    } catch (_) {
      // 历史拉取失败不阻塞实时流
    }

    // 统计卡片（总请求/拦截数/拦截率）每 2 秒自动刷新
    _statsTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      refreshStats();
    });

    _sub = api.alertStream().listen(
      (alert) {
        alerts.insert(0, alert);
        if (alerts.length > 200) alerts.removeLast();
        _recount();
        notifyListeners();
      },
      onError: (_) {},
    );
  }

  /// 拉取统计；失败时把错误写进 [lastError] 并通知 UI，不抛出异常。
  Future<void> refreshStats() async {
    try {
      stats = await api.fetchStats();
      lastError = null;
    } catch (e) {
      lastError = e.toString();
    }
    notifyListeners();
  }

  void _recount() {
    categoryCount.clear();
    for (final a in alerts) {
      // 按真实重复次数累计，保证饼图与 IP 表口径一致
      categoryCount[a.category] = (categoryCount[a.category] ?? 0) + a.count;
    }
  }

  @override
  void dispose() {
    _sub?.cancel();
    _statsTimer?.cancel();
    api.dispose();
    super.dispose();
  }
}
