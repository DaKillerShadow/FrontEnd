// lib/core/models/lesson_model.dart
//
// Educational content for every scoring pillar.
// Previously only 4 of the 11 backend pillars had lesson entries —
// the other 7 silently fell through to the generic default, which is why
// an IP-literal scan showed "General Phishing Risk" instead of the correct
// "IP Literal Address Detected" lesson.
//
// All 11 pillars now have dedicated entries.  The switch matches both:
//   • backend check `name` keys  (e.g. 'ip_literal')
//   • backend `top_threat` labels (e.g. 'IP ADDRESS LITERAL')
// so either value from the API response resolves to the right lesson.

class LessonModel {
  final String title;
  final String type;
  final String summary;
  final String body;
  final String example;        // kept for any legacy callers
  final String realCounterpart;
  final String tip;
  final String quizQuestion;
  final List<String> quizOptions;
  final int correctOptionIndex;

  const LessonModel({
    required this.title,
    required this.type,
    required this.summary,
    required this.body,
    required this.example,
    required this.realCounterpart,
    required this.tip,
    required this.quizQuestion,
    required this.quizOptions,
    required this.correctOptionIndex,
  });

  // ── Factory: maps any backend threat key → lesson content ──────────────────
  //
  // Accepts both machine keys ('ip_literal') and label strings
  // ('IP ADDRESS LITERAL') so callers don't need to normalise.

  factory LessonModel.forThreat(String? threatType) {
    switch (threatType?.toLowerCase().replaceAll(' ', '_')) {

      // ── 1. IP Literal ───────────────────────────────────────────────────
      case 'ip_literal':
      case 'ip_address_literal':
        return const LessonModel(
          title: 'IP Literal Address Detected',
          type: 'IP Literal Address',
          summary:
              'The link uses a raw IP address instead of a registered domain name.',
          body:
              'Legitimate services always use a domain name (e.g. bank.com). '
              'Raw IPs are used by attackers to avoid domain reputation checks '
              'and make the destination impossible to identify at a glance.',
          example: '185.220.101.52',
          realCounterpart: 'mybank.com',
          tip:
              'Never trust a link that shows a numeric IP address. '
              'Real organisations always use registered domain names.',
          quizQuestion:
              'Why do phishers use raw IP addresses in QR codes?',
          quizOptions: [
            'IPs are faster than domain names',
            'To bypass domain reputation filters and hide the destination',
            'Because domain names are expensive',
          ],
          correctOptionIndex: 1,
        );

      // ── 2. Punycode / Homograph ─────────────────────────────────────────
      case 'punycode':
      case 'punycode_attack':
      case 'homograph_attack':
        return const LessonModel(
          title: 'Homograph Attack',
          type: 'Homograph Attack',
          summary:
              'The domain uses foreign lookalike characters to impersonate a trusted brand.',
          body:
              'Attackers replace Latin letters with visually identical Cyrillic '
              'or Greek characters. The URL looks correct but points to a '
              'completely different server. Browsers show the "xn--" Punycode '
              'prefix in the address bar when this is active.',
          example: 'аррlе.com',
          realCounterpart: 'apple.com',
          tip:
              'Look for "xn--" in the address bar. '
              'If you see it, the domain uses non-Latin characters.',
          quizQuestion:
              'Why is "аррlе.com" dangerous even if it looks identical to apple.com?',
          quizOptions: [
            'It uses hidden tracking cookies',
            'It contains non-English characters that look the same as Latin letters',
            'It is a shortened link',
          ],
          correctOptionIndex: 1,
        );

      // ── 3. Nested Shorteners ────────────────────────────────────────────
      case 'nested_short':
      case 'nested_shorteners':
        return const LessonModel(
          title: 'Chained URL Shorteners',
          type: 'Nested Shorteners',
          summary:
              'Multiple URL shorteners are chained to hide the real destination.',
          body:
              'Each shortener hop adds a layer of indirection, making the final '
              'URL invisible until the last moment. This deliberately defeats '
              'preview tools and reputation checkers that only inspect the first hop.',
          example: 'bit.ly/abc → tinyurl.com/xyz → malicious.ru',
          realCounterpart: 'shop.amazon.com/product/123',
          tip:
              'Use a link expander (e.g. checkshorturl.com) before clicking '
              'any shortened link from a QR code.',
          quizQuestion:
              'What is the main danger of chaining multiple URL shorteners?',
          quizOptions: [
            'They are slower to load',
            'They conceal the final destination from reputation scanners',
            'They expire after 24 hours',
          ],
          correctOptionIndex: 1,
        );

      // ── 4. HTML Evasion ─────────────────────────────────────────────────
      case 'html_evasion':
      case 'html_meta_refresh':
        return const LessonModel(
          title: 'Hidden HTML Redirect',
          type: 'HTML Evasion',
          summary:
              'The landing page silently redirects you using a hidden HTML tag.',
          body:
              'A meta-refresh tag in the page\'s HTML instructs your browser '
              'to navigate away immediately — often before you can read the URL. '
              'This bypasses network-level redirect detection because it happens '
              'inside the browser after the page loads.',
          example: '<meta http-equiv="refresh" content="0;url=evil.com">',
          realCounterpart: 'No redirect on legitimate pages',
          tip:
              'If a page loads and instantly jumps somewhere else, '
              'close the browser tab immediately.',
          quizQuestion:
              'How does a meta-refresh redirect differ from a normal 301 redirect?',
          quizOptions: [
            'It is faster',
            'It happens inside the browser after the page loads, bypassing network scanners',
            'It only works on mobile devices',
          ],
          correctOptionIndex: 1,
        );

      // ── 5. DGA / Entropy ────────────────────────────────────────────────
      case 'dga_entropy':
      case 'machine_generated_link':
        return const LessonModel(
          title: 'Machine-Generated Domain',
          type: 'DGA Entropy',
          summary:
              'The domain name looks like random gibberish — a sign of automated malware.',
          body:
              'Malware uses Domain Generation Algorithms (DGA) to create hundreds '
              'of throwaway domains every day. The high Shannon entropy of random '
              'strings is statistically distinct from human-chosen brand names.',
          example: 'x7z9q2mwpb.com',
          realCounterpart: 'amazon.com',
          tip:
              'If you cannot pronounce the domain name, it is likely machine-generated. '
              'Legitimate brands always use memorable names.',
          quizQuestion:
              'What is a common sign of a Domain Generation Algorithm (DGA) domain?',
          quizOptions: [
            'It has a .com extension',
            'It contains a random, unpronounceable string of letters and numbers',
            'It is very short',
          ],
          correctOptionIndex: 1,
        );

      // ── 6. Redirect Depth ───────────────────────────────────────────────
      case 'redirect_depth':
      case 'redirect_chain_depth':
      case 'deep_redirect_chain':
        return const LessonModel(
          title: 'Deep Redirect Chain',
          type: 'Redirect Depth',
          summary:
              'The link bounces through three or more servers before reaching the destination.',
          body:
              'Attackers use long redirect chains to pass through legitimate-looking '
              'intermediate servers (e.g. tracking platforms) before landing on the '
              'malicious page. Each hop makes attribution harder and may bypass '
              'single-hop URL scanners.',
          example: 'track.ad.com → redir.io → phish.ru/steal',
          realCounterpart: 'Direct link: brand.com/offer',
          tip:
              'QR codes from trusted sources (tickets, menus, receipts) should '
              'resolve in one or two hops. Three or more is a red flag.',
          quizQuestion:
              'Why do attackers use long redirect chains?',
          quizOptions: [
            'To improve page load speed',
            'To pass through trusted servers and evade single-hop scanners',
            'To compress the final URL',
          ],
          correctOptionIndex: 1,
        );

      // ── 7. Path Keywords ────────────────────────────────────────────────
      case 'path_keywords':
      case 'urgency_keywords':
        return const LessonModel(
          title: 'Phishing Keywords in URL',
          type: 'Urgency Keywords',
          summary:
              'The URL path contains words designed to create panic and urgency.',
          body:
              'Phishers embed action words like "verify", "secure", "login", '
              'or "update" to make the link feel official and urgent. '
              'Real services rarely include these words in their URL paths.',
          example: 'auth.verify-account.com/login/secure',
          realCounterpart: 'accounts.google.com',
          tip:
              'Official services rarely put "secure", "verify", or "update" '
              'in the URL itself. Check the domain first — ignore the path.',
          quizQuestion:
              'Why do phishers use words like "Verify" or "Secure" in URL paths?',
          quizOptions: [
            'To improve search engine ranking',
            'To create a false sense of legitimacy and urgency',
            'To ensure the connection is encrypted',
          ],
          correctOptionIndex: 1,
        );

      // ── 8. Suspicious TLD ───────────────────────────────────────────────
      case 'suspicious_tld':
        return const LessonModel(
          title: 'High-Risk Domain Extension',
          type: 'Suspicious TLD',
          summary:
              'The domain uses a top-level extension with a statistically elevated abuse rate.',
          body:
              'Certain TLDs (.tk, .ml, .xyz, .ru, .top) are heavily over-represented '
              'in phishing databases because they offer free or very cheap registration '
              'with minimal identity verification. Attackers register and discard '
              'these domains rapidly.',
          example: 'bank-update.tk',
          realCounterpart: 'mybank.com',
          tip:
              'Be especially cautious with .tk, .ml, .xyz, .top, and .ru domains. '
              'Legitimate brands rarely use these extensions.',
          quizQuestion:
              'Why are some TLDs more commonly seen in phishing attacks?',
          quizOptions: [
            'They load faster than .com domains',
            'They are free or cheap with minimal identity verification',
            'They are harder to block by firewalls',
          ],
          correctOptionIndex: 1,
        );

      // ── 9. Subdomain Depth ──────────────────────────────────────────────
      case 'subdomain_depth':
      case 'subdomain_nesting':
        return const LessonModel(
          title: 'Excessive Subdomain Nesting',
          type: 'Subdomain Nesting',
          summary:
              'Too many subdomain labels are used to push the real domain off-screen.',
          body:
              'Attackers prepend a trusted-looking brand name as a subdomain '
              '(e.g. google.com.login.verify.malicious-site.com) so the '
              'visible part of the URL looks familiar. The actual domain — '
              'the part just before the final ".com" — is malicious.',
          example: 'paypal.com.verify.login.evil-site.com',
          realCounterpart: 'paypal.com',
          tip:
              'Always read the URL from right to left. '
              'The real domain is the text immediately before ".com", ".net", etc.',
          quizQuestion:
              'In "paypal.com.verify.login.evil.com", what is the real host domain?',
          quizOptions: [
            'paypal.com',
            'evil.com',
            'login.evil.com',
          ],
          correctOptionIndex: 1,
        );

      // ── 10. HTTPS Mismatch ──────────────────────────────────────────────
      case 'https_mismatch':
      case 'no_https':
        return const LessonModel(
          title: 'Unencrypted HTTP Link',
          type: 'No HTTPS',
          summary:
              'The link uses HTTP, meaning your data is sent in plain text.',
          body:
              'HTTPS encrypts the connection between your device and the server. '
              'HTTP does not — anyone on the same network can read or modify '
              'the data in transit. Any page that asks for credentials over '
              'plain HTTP should be treated as hostile.',
          example: 'http://bank-login.com/signin',
          realCounterpart: 'https://onlinebanking.com/signin',
          tip:
              'Never enter a password or payment details on a page whose URL '
              'starts with "http://" — only "https://" is safe.',
          quizQuestion:
              'What is the key difference between HTTP and HTTPS?',
          quizOptions: [
            'HTTPS loads faster',
            'HTTPS encrypts data in transit; HTTP sends it in plain text',
            'HTTPS requires a paid certificate',
          ],
          correctOptionIndex: 1,
        );

      // ── Generic fallback ────────────────────────────────────────────────
      default:
        return const LessonModel(
          title: 'General Phishing Risk',
          type: 'General Phishing Risk',
          summary:
              'This link shows multiple indicators consistent with a Quishing attack.',
          body:
              'The combination of suspicious signals detected — such as unusual '
              'extensions, redirect chains, or deceptive domains — is consistent '
              'with QR-code phishing campaigns that attempt to harvest credentials '
              'or install malware.',
          example: 'login-update-service.net',
          realCounterpart: 'official-website.com',
          tip:
              'When in doubt, type the official address manually into your browser '
              'rather than following any link from a QR code.',
          quizQuestion:
              'What is the safest action when a QR code link is flagged?',
          quizOptions: [
            'Click it once to test it',
            'Ignore the link and visit the official site directly',
            'Forward it to a friend to verify',
          ],
          correctOptionIndex: 1,
        );
    }
  }
}
