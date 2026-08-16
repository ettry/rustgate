/// RustGate 告警数据模型（与 Rust 侧 bus::Alert 字段一一对应）。
class Alert {
  final int time;
  final String ip;
  final String method;
  final String path;
  final String category;
  final String detail;
  final int ruleId;
  final int score;
  final String action;
  /// 连续重复次数：1 表示唯一，>1 表示有重复攻击被去重合并。
  final int count;
  /// 本次请求命中的全部规则（第一条为主展示规则）。
  final List<AlertHit> hits;

  Alert({
    required this.time,
    required this.ip,
    required this.method,
    required this.path,
    required this.category,
    required this.detail,
    required this.ruleId,
    required this.score,
    required this.action,
    this.count = 1,
    this.hits = const [],
  });

  factory Alert.fromJson(Map<String, dynamic> json) {
    return Alert(
      time: json['time'] as int? ?? 0,
      ip: json['ip'] as String? ?? '',
      method: json['method'] as String? ?? '',
      path: json['path'] as String? ?? '',
      category: json['category'] as String? ?? '',
      detail: json['detail'] as String? ?? '',
      ruleId: json['rule_id'] as int? ?? 0,
      score: json['score'] as int? ?? 0,
      action: json['action'] as String? ?? '',
      count: json['count'] as int? ?? 1,
      hits: (json['hits'] as List<dynamic>? ?? [])
          .map((e) => AlertHit.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }

  DateTime get dateTime =>
      DateTime.fromMillisecondsSinceEpoch(time * 1000);
}

/// 统计快照（与 Rust 侧 bus::Stats 对齐）。
class Stats {
  final int totalRequests;
  final int blocked;
  final double qps;

  Stats({
    required this.totalRequests,
    required this.blocked,
    required this.qps,
  });

  factory Stats.fromJson(Map<String, dynamic> json) {
    return Stats(
      totalRequests: json['total_requests'] as int? ?? 0,
      blocked: json['blocked'] as int? ?? 0,
      qps: (json['qps'] as num?)?.toDouble() ?? 0,
    );
  }
}


/// 单条命中规则。
class AlertHit {
  final int ruleId;
  final String category;
  final int score;

  AlertHit({required this.ruleId, required this.category, required this.score});

  factory AlertHit.fromJson(Map<String, dynamic> json) {
    return AlertHit(
      ruleId: json['rule_id'] as int? ?? 0,
      category: json['category'] as String? ?? '',
      score: json['score'] as int? ?? 0,
    );
  }
}
