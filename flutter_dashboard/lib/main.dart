import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import 'models.dart';
import 'settings.dart';
import 'settings_screen.dart';
import 'state.dart';

void main() {
  runApp(
    ChangeNotifierProvider(
      create: (_) => DashboardState()..start(),
      child: const RustGateApp(),
    ),
  );
}

class RustGateApp extends StatelessWidget {
  const RustGateApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RustGate WAF 面板',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF00C853),
          brightness: Brightness.dark,
        ),
        scaffoldBackgroundColor: const Color(0xFF0E1116),
      ),
      home: const DashboardScreen(),
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  @override
  void initState() {
    super.initState();
    // 首次启动且从未保存过配置：直接引导用户去设置页，
    // 避免拿默认 token 去连 WAF 必然 401。
    if (!AppSettings.isConfigured()) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _openSettings(context);
      });
    }
  }

  Future<void> _openSettings(BuildContext context) async {
    final state = context.read<DashboardState>();
    final saved = await Navigator.of(context).push<AppSettings>(
      MaterialPageRoute(builder: (_) => const SettingsScreen()),
    );
    if (saved == null || !context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('已保存，正在重连…')),
    );
    await state.reconnect(saved);
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<DashboardState>();
    final stats = state.stats;

    return Scaffold(
      appBar: AppBar(
        title: const Text('RustGate WAF 实时监控'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            tooltip: '连接设置',
            onPressed: () => _openSettings(context),
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () async {
              await state.refreshStats();
              if (!context.mounted) return;
              if (state.lastError != null) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text(state.lastError!)),
                );
              }
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // 连接错误提示条
          if (state.lastError != null)
            Container(
              width: double.infinity,
              color: Colors.red.shade900,
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              child: Text(
                state.lastError!,
                style: const TextStyle(color: Colors.white, fontSize: 13),
              ),
            ),
          // 统计卡片区
          Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                _StatCard(
                  label: '总请求',
                  value: '${stats?.totalRequests ?? 0}',
                  color: const Color(0xFF3B82F6),
                  icon: Icons.traffic,
                ),
                const SizedBox(width: 12),
                _StatCard(
                  label: '拦截数',
                  value: '${stats?.blocked ?? 0}',
                  color: const Color(0xFFEF4444),
                  icon: Icons.gpp_bad,
                ),
                const SizedBox(width: 12),
                _StatCard(
                  label: '拦截率',
                  value: stats != null && stats.totalRequests > 0
                      ? '${(stats.blocked * 100 / stats.totalRequests).toStringAsFixed(1)}%'
                      : '--',
                  color: const Color(0xFFF59E0B),
                  icon: Icons.shield,
                ),
              ],
            ),
          ),
          // 内容区
          Expanded(
            child: DefaultTabController(
              length: 3,
              child: Column(
                children: [
                  const TabBar(
                    tabs: [
                      Tab(text: '实时告警'),
                      Tab(text: '攻击类型'),
                      Tab(text: '来源 IP'),
                    ],
                  ),
                  Expanded(
                    child: TabBarView(
                      children: [
                        const _AlertList(),
                        _CategoryChart(categoryCount: state.categoryCount),
                        _IpTable(alerts: state.alerts),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _StatCard extends StatelessWidget {
  final String label;
  final String value;
  final Color color;
  final IconData icon;

  const _StatCard({
    required this.label,
    required this.value,
    required this.color,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: const Color(0xFF171C24),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: Colors.white12),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, color: color, size: 20),
            const SizedBox(height: 8),
            Text(
              value,
              style: const TextStyle(
                fontSize: 26,
                fontWeight: FontWeight.bold,
                color: Colors.white,
              ),
            ),
            Text(label, style: TextStyle(color: Colors.grey[400])),
          ],
        ),
      ),
    );
  }
}

/// 实时告警列表。
class _AlertList extends StatelessWidget {
  const _AlertList();

  @override
  Widget build(BuildContext context) {
    final alerts = context.watch<DashboardState>().alerts;
    if (alerts.isEmpty) {
      return const Center(
        child: Text('暂无告警 —— 尝试发一个恶意请求', style: TextStyle(color: Colors.grey)),
      );
    }
    return ListView.separated(
      itemCount: alerts.length,
      separatorBuilder: (_, __) => const Divider(height: 1, color: Colors.white12),
      itemBuilder: (context, i) {
        final a = alerts[i];
        return ListTile(
          dense: true,
          leading: Icon(
            a.category == 'cc' ? Icons.speed : Icons.bug_report,
            color: const Color(0xFFEF4444),
          ),
          title: Text(
            a.count > 1
                ? '[${a.category}] ${a.method} ${a.path}  ×${a.count}'
                : '[${a.category}] ${a.method} ${a.path}',
            style: const TextStyle(color: Colors.white, fontSize: 14),
            overflow: TextOverflow.ellipsis,
          ),
          subtitle: Text(
            '${a.ip} · ${a.detail} · score=${a.score}',
            style: TextStyle(color: Colors.grey[500], fontSize: 12),
          ),
          trailing: Text(
            DateFormat('HH:mm:ss').format(a.dateTime),
            style: TextStyle(color: Colors.grey[500], fontSize: 11),
          ),
        );
      },
    );
  }
}

/// 攻击类型分布饼图。
class _CategoryChart extends StatelessWidget {
  final Map<String, int> categoryCount;

  const _CategoryChart({required this.categoryCount});

  @override
  Widget build(BuildContext context) {
    if (categoryCount.isEmpty) {
      return const Center(child: Text('暂无数据', style: TextStyle(color: Colors.grey)));
    }
    final entries = categoryCount.entries.toList();
    final colors = [Colors.redAccent, Colors.orangeAccent, Colors.amberAccent, Colors.greenAccent, Colors.blueAccent, Colors.purpleAccent];

    return Column(
      children: [
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: PieChart(
              PieChartData(
                sections: [
                  for (var i = 0; i < entries.length; i++)
                    PieChartSectionData(
                      value: entries[i].value.toDouble(),
                      title: entries[i].key,
                      color: colors[i % colors.length],
                      radius: 80,
                      titleStyle: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                ],
              ),
            ),
          ),
        ),
        // 图例
        Padding(
          padding: const EdgeInsets.only(bottom: 16),
          child: Wrap(
            spacing: 12,
            children: [
              for (var i = 0; i < entries.length; i++)
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 10,
                      height: 10,
                      color: colors[i % colors.length],
                    ),
                    const SizedBox(width: 4),
                    Text('${entries[i].key} (${entries[i].value})',
                        style: const TextStyle(color: Colors.white70, fontSize: 12)),
                  ],
                ),
            ],
          ),
        ),
      ],
    );
  }
}

/// 来源 IP 统计表。
class _IpTable extends StatelessWidget {
  final List<Alert> alerts;

  const _IpTable({required this.alerts});

  @override
  Widget build(BuildContext context) {
    final counter = <String, int>{};
    for (final a in alerts) {
      // 每条告警的 count 表示真实重复次数，IP 告警次数按真实次数累计
      counter[a.ip] = (counter[a.ip] ?? 0) + a.count;
    }
    final entries = counter.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));

    if (entries.isEmpty) {
      return const Center(child: Text('暂无数据', style: TextStyle(color: Colors.grey)));
    }

    return DataTable(
      headingRowColor: WidgetStateProperty.all(const Color(0xFF171C24)),
      columns: const [
        DataColumn(label: Text('IP', style: TextStyle(color: Colors.white))),
        DataColumn(label: Text('告警次数', style: TextStyle(color: Colors.white))),
      ],
      rows: [
        for (final e in entries.take(20))
          DataRow(
            cells: [
              DataCell(Text(e.key, style: const TextStyle(color: Colors.white))),
              DataCell(Text('${e.value}', style: const TextStyle(color: Colors.white))),
            ],
          ),
      ],
    );
  }
}
