import 'package:flutter/material.dart';

import 'settings.dart';

/// 连接设置页：填写 WAF 管理 API 的 IP / 端口 / token 并保存。
///
/// 保存成功返回 `true`，调用方可据此重连。
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final TextEditingController _ipCtrl;
  late final TextEditingController _portCtrl;
  late final TextEditingController _tokenCtrl;
  String? _error;
  bool _obscure = true;

  @override
  void initState() {
    super.initState();
    final s = AppSettings.load();
    _ipCtrl = TextEditingController(text: s.ip);
    _portCtrl = TextEditingController(text: '${s.port}');
    _tokenCtrl = TextEditingController(text: s.token);
  }

  @override
  void dispose() {
    _ipCtrl.dispose();
    _portCtrl.dispose();
    _tokenCtrl.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final ip = _ipCtrl.text.trim();
    final portText = _portCtrl.text.trim();
    final token = _tokenCtrl.text.trim();

    final port = int.tryParse(portText);
    if (ip.isEmpty) {
      setState(() => _error = 'IP 地址不能为空');
      return;
    }
    if (port == null || port <= 0 || port > 65535) {
      setState(() => _error = '端口必须是 1~65535 的整数');
      return;
    }
    if (token.isEmpty) {
      setState(() => _error = 'token 不能为空');
      return;
    }

    final settings = AppSettings(ip: ip, port: port, token: token);
    await settings.save();
    if (!mounted) return;
    Navigator.of(context).pop(settings);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('连接设置')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _ipCtrl,
            decoration: const InputDecoration(
              labelText: 'WAF 管理 API 地址 (IP 或域名)',
              hintText: '如 127.0.0.1 或 waf.example.com',
              border: OutlineInputBorder(),
            ),
            keyboardType: TextInputType.url,
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _portCtrl,
            decoration: const InputDecoration(
              labelText: '端口',
              hintText: '默认 9001',
              border: OutlineInputBorder(),
            ),
            keyboardType: TextInputType.number,
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _tokenCtrl,
            obscureText: _obscure,
            decoration: InputDecoration(
              labelText: 'Token (RUSTGATE_API_TOKEN)',
              hintText: '与 RustGate 启动时使用的 token 一致',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: Icon(_obscure ? Icons.visibility : Icons.visibility_off),
                onPressed: () => setState(() => _obscure = !_obscure),
              ),
            ),
          ),
          if (_error != null) ...[
            const SizedBox(height: 16),
            Text(
              _error!,
              style: const TextStyle(color: Colors.redAccent),
            ),
          ],
          const SizedBox(height: 24),
          FilledButton.icon(
            onPressed: _save,
            icon: const Icon(Icons.save),
            label: const Text('保存并连接'),
          ),
          const SizedBox(height: 12),
          Text(
            '保存后会自动重连 WAF。\n配置保存在 ~/.rustgate_dashboard.json',
            style: TextStyle(color: Colors.grey[500], fontSize: 12),
          ),
        ],
      ),
    );
  }
}
