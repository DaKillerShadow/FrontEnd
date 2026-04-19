// lib/features/lesson/micro_lesson_screen.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../core/models/lesson_model.dart';
import '../../core/models/scan_result.dart';
import '../../shared/theme/app_theme.dart';

class MicroLessonScreen extends StatefulWidget {
  const MicroLessonScreen({super.key, required this.result});
  final ScanResult result;

  @override
  State<MicroLessonScreen> createState() => _State();
}

class _State extends State<MicroLessonScreen> {
  bool _bookmarked = false;

  // Maps backend threat/check name → lesson content.
  // Falls back through top_threat → first triggered check → generic.
  LessonModel get _lesson {
    if (widget.result.topThreat != null &&
        widget.result.topThreat!.isNotEmpty &&
        widget.result.topThreat != 'None') {
      return LessonModel.forThreat(widget.result.topThreat);
    }
    try {
      final worst = widget.result.checks.firstWhere((c) => c.triggered);
      return LessonModel.forThreat(worst.name);
    } catch (_) {
      return LessonModel.forThreat('generic');
    }
  }

  // Maps threat type → icon + glow colour for the hero widget.
  _HeroIcon _heroIcon(String threatType) {
    switch (threatType.toLowerCase()) {
      case 'ip literal address':
      case 'ip_literal':
        return const _HeroIcon(Icons.dns_outlined, AppColors.ember);
      case 'homograph attack':
      case 'punycode':
        return const _HeroIcon(Icons.translate_rounded, AppColors.ember);
      case 'nested shorteners':
      case 'nested_short':
        return const _HeroIcon(Icons.link_rounded, AppColors.amber);
      case 'html evasion':
      case 'html_evasion':
        return const _HeroIcon(Icons.code_off_rounded, AppColors.ember);
      case 'machine generated link':
      case 'dga_entropy':
        return const _HeroIcon(Icons.casino_outlined, AppColors.amber);
      case 'deep redirect chain':
      case 'redirect_depth':
        return const _HeroIcon(Icons.fork_right_rounded, AppColors.amber);
      case 'urgency keywords':
      case 'path_keywords':
        return const _HeroIcon(Icons.warning_amber_rounded, AppColors.amber);
      case 'suspicious tld':
      case 'suspicious_tld':
        return const _HeroIcon(Icons.public_off_rounded, AppColors.amber);
      case 'subdomain nesting':
      case 'subdomain_depth':
        return const _HeroIcon(Icons.account_tree_outlined, AppColors.amber);
      case 'no https':
      case 'https_mismatch':
        return const _HeroIcon(Icons.lock_open_rounded, AppColors.amber);
      default:
        return const _HeroIcon(Icons.gpp_maybe_outlined, AppColors.amber);
    }
  }

  // The actual scanned host to display in "Spot the Threat".
  // Uses resolved URL host first (post-redirect), falls back to raw URL.
  String get _actualThreatDisplay {
    final resolved = widget.result.resolvedUrl;
    if (resolved.isNotEmpty) {
      final host = Uri.tryParse(resolved)?.host ?? '';
      if (host.isNotEmpty) return host;
    }
    final raw = widget.result.url;
    final host = Uri.tryParse(raw)?.host ?? '';
    return host.isNotEmpty ? host : raw;
  }

  @override
  Widget build(BuildContext context) {
    final l = _lesson;
    final icon = _heroIcon(l.type);

    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Security Lesson'),
        actions: [
          IconButton(
            icon: Icon(
              _bookmarked
                  ? Icons.bookmark_rounded
                  : Icons.bookmark_border_rounded,
              color: _bookmarked ? AppColors.arc : AppColors.muted,
            ),
            onPressed: () {
              setState(() => _bookmarked = !_bookmarked);
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                content: Text(
                    _bookmarked ? 'Lesson bookmarked' : 'Bookmark removed'),
                duration: const Duration(seconds: 2),
              ));
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.only(bottom: 32),
        child: Column(children: [
          // ── Hero ────────────────────────────────────────────────────
          Container(
            width: double.infinity,
            padding: const EdgeInsets.fromLTRB(20, 28, 20, 22),
            color: AppColors.panel,
            child: Column(children: [
              // FIX 1: Glowing Flutter icon — replaces flat emoji
              Container(
                width: 72,
                height: 72,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: icon.color.withValues(alpha: .12),
                  boxShadow: [
                    BoxShadow(
                      color: icon.color.withValues(alpha: .35),
                      blurRadius: 24,
                      spreadRadius: 2,
                    ),
                  ],
                ),
                child: Icon(icon.data, color: icon.color, size: 36),
              ),
              const SizedBox(height: 14),

              // FIX 2: Pill = threat category label only (no book emoji)
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                decoration: BoxDecoration(
                  color: icon.color.withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(20),
                  border:
                      Border.all(color: icon.color.withValues(alpha: .3)),
                ),
                child: Text(
                  l.type,
                  style: TextStyle(
                    fontSize: 10,
                    color: icon.color,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.8,
                  ),
                ),
              ),
              const SizedBox(height: 12),

              // FIX 2: Title = specific attack name from lesson model,
              // NOT a duplicate of the pill text above it.
              Text(
                l.title,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 20,
                  fontWeight: FontWeight.w800,
                  color: AppColors.textColor,
                  height: 1.3,
                ),
              ),
            ]),
          ),
          const SizedBox(height: 16),

          // ── Summary card ───────────────────────────────────────────
          _LessonCard(
            color: AppColors.arc.withValues(alpha: .06),
            borderColor: AppColors.arc.withValues(alpha: .2),
            child: Text(
              l.summary,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 13,
                color: AppColors.textColor,
                height: 1.6,
              ),
            ),
          ),

          // ── How it works — FIX 4: RichText bolds the scanned value ──
          _Section(
            label: 'HOW IT WORKS',
            child: Text.rich(
              TextSpan(
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: AppColors.muted,
                  height: 1.7,
                ),
                children: [
                  const TextSpan(text: 'You scanned '),
                  TextSpan(
                    text: _actualThreatDisplay,
                    style: TextStyle(
                      color: icon.color,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  TextSpan(text: '. ${l.body}'),
                ],
              ),
            ),
          ),

          // ── Spot the Threat — FIX 3 + 5 ──────────────────────────
          _Section(
            label: 'SPOT THE THREAT',
            child: _buildComparisonCard(l),
          ),

          // ── What to do ─────────────────────────────────────────────
          _Section(
            label: 'WHAT TO DO',
            child: Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.amber.withValues(alpha: .06),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                    color: AppColors.amber.withValues(alpha: .2)),
              ),
              child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.lightbulb_outline_rounded,
                        color: AppColors.amber, size: 18),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        l.tip,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: AppColors.textColor,
                          height: 1.6,
                        ),
                      ),
                    ),
                  ]),
            ),
          ),

          // ── Actions ───────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: Column(children: [
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () => context.go('/'),
                  child: const Text('GOT IT  ✓'),
                ),
              ),
              const SizedBox(height: 10),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton(
                  onPressed: () => context.pop(),
                  child: const Text('← BACK TO RESULT'),
                ),
              ),
            ]),
          ),
        ]),
      ),
    );
  }

  // ── Comparison card ────────────────────────────────────────────────────────
  //
  // FIX 3: ACTUAL THREAT row now shows widget.result's real resolved host —
  //        not the static l.example. An IP scan shows the IP. A domain scan
  //        shows the domain. No more data mismatch.
  // FIX 5: Threat value = red/ember. Safe counterpart = green.

  Widget _buildComparisonCard(LessonModel l) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.panel,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.rim),
      ),
      child: Column(children: [
        _comparisonRow(
          label: 'ACTUAL THREAT',
          value: _actualThreatDisplay,
          labelColor: AppColors.ember,
          valueColor: AppColors.ember,
          dotColor: AppColors.ember,
        ),
        const Divider(color: AppColors.rim, height: 24),
        _comparisonRow(
          label: 'LEGITIMATE SITE',
          value: l.realCounterpart,
          labelColor: AppColors.safe,
          valueColor: AppColors.safe,
          dotColor: AppColors.safe,
        ),
      ]),
    );
  }

  Widget _comparisonRow({
    required String label,
    required String value,
    required Color labelColor,
    required Color valueColor,
    required Color dotColor,
  }) {
    return Row(children: [
      // Glowing dot — instant red/green signal before the user reads text
      Container(
        width: 8,
        height: 8,
        margin: const EdgeInsets.only(right: 10),
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: dotColor,
          boxShadow: [
            BoxShadow(
                color: dotColor.withValues(alpha: .5), blurRadius: 6)
          ],
        ),
      ),
      Expanded(
        child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: TextStyle(
                  color: labelColor,
                  fontSize: 9,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0.8,
                ),
              ),
              const SizedBox(height: 3),
              Text(
                value,
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: valueColor,
                  fontWeight: FontWeight.w600,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ]),
      ),
    ]);
  }
}

// ── Small data class for icon + colour pairing ───────────────────────────────

class _HeroIcon {
  const _HeroIcon(this.data, this.color);
  final IconData data;
  final Color color;
}

// ── Shared layout widgets ────────────────────────────────────────────────────

class _LessonCard extends StatelessWidget {
  const _LessonCard(
      {required this.child,
      required this.color,
      required this.borderColor});
  final Widget child;
  final Color color, borderColor;

  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: color,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: borderColor),
        ),
        child: child,
      );
}

class _Section extends StatelessWidget {
  const _Section({required this.label, required this.child});
  final String label;
  final Widget child;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        child:
            Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(
            label,
            style: const TextStyle(
              fontSize: 9,
              color: AppColors.arc,
              letterSpacing: 1.2,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          child,
        ]),
      );
}
