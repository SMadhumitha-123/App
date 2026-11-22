import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';
import 'package:encrypt/encrypt.dart' as e;
import 'package:crypto/crypto.dart';
import 'package:excel/excel.dart' as xl;
import 'package:pdf/widgets.dart' as pw;
import 'package:share_plus/share_plus.dart';

// ---------- Key derivation + encrypted store ----------
List<int> _pbkdf2(List a) {
  final h = Hmac(sha256, utf8.encode(a[0] as String));
  var u = h.convert([...(a[1] as List).cast<int>(), 0, 0, 0, 1]).bytes;
  final t = List<int>.from(u);
  for (var i = 1; i < (a[2] as int); i++) {
    u = h.convert(u).bytes;
    for (var j = 0; j < 32; j++) {
      t[j] ^= u[j];
    }
  }
  return t;
}

/// PBKDF2-HMAC-SHA256, 100,000 rounds, run off the UI thread
Future<e.Key> kdf(String pw, List<int> salt) async =>
    e.Key(Uint8List.fromList(await compute(_pbkdf2, [pw, salt, 100000])));

/// copy to clipboard and wipe it after 60 seconds
Future<void> copySecret(String t) async {
  await Clipboard.setData(ClipboardData(text: t));
  Timer(const Duration(seconds: 60), () => Clipboard.setData(const ClipboardData(text: '')));
}

class Store {
  static Map<String, dynamic> data = {'name': '', 'accounts': []};
  static Map<String, dynamic> _kf = {};
  static e.Key? _dk; // data key: random, wrapped by PIN-key and recovery-key
  static const _ss = FlutterSecureStorage();
  static Future<String?> _ds({bool create = false}) async {
    try {
      var v = await _ss.read(key: 'ds');
      if (v == null && create) {
        v = base64.encode(_rnd(32));
        await _ss.write(key: 'ds', value: v);
      }
      return v;
    } catch (_) {
      return null;
    }
  }

  static List get accounts => data['accounts'];
  static List get folders => (data['folders'] ??= []) as List;

  static Future<File> _f(String n) async =>
      File('${(await getApplicationSupportDirectory()).path}/$n');
  static e.Encrypter _enc(e.Key k) => e.Encrypter(e.AES(k, mode: e.AESMode.gcm));
  static List<int> _rnd(int n) => List.generate(n, (_) => Random.secure().nextInt(256));
  static Uint8List _u(List<int> b) => Uint8List.fromList(b);
  static String _nc(String s) => s.replaceAll(RegExp(r'[\s-]'), '').toUpperCase();

  static String _wrap(e.Key k, List<int> v) {
    final iv = e.IV.fromSecureRandom(12);
    return base64.encode(iv.bytes + _enc(k).encryptBytes(v, iv: iv).bytes);
  }

  static List<int>? _unwrap(e.Key k, String w) {
    try {
      final b = base64.decode(w);
      return _enc(k).decryptBytes(e.Encrypted(_u(b.sublist(12))), iv: e.IV(_u(b.sublist(0, 12))));
    } catch (_) {
      return null;
    }
  }

  static Future<void> _saveKf() async =>
      (await _f('keys.json')).writeAsString(jsonEncode(_kf));

  static Future<bool> hasPin() async {
    final f = await _f('keys.json');
    if (!await f.exists()) return false;
    _kf = jsonDecode(await f.readAsString());
    return true;
  }

  static Future<void> _setPin(String pin, List<int> dk) async {
    final ds = await _ds(create: true);
    if (ds == null) throw StateError('Secure storage unavailable');
    final s = _rnd(16);
    _kf['salt'] = base64.encode(s);
    _kf['pin'] = _wrap(await kdf('$pin:$ds', s), dk);
    _kf['fails'] = 0;
    _kf['lock'] = 0;
    await _saveKf();
  }

  /// creates a new recovery code (old one stops working); shown once
  static Future<String> newRecovery() async {
    const ch = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    final rc = List.generate(20, (i) => (i > 0 && i % 4 == 0 ? '-' : '') + ch[Random.secure().nextInt(ch.length)]).join();
    final s = _rnd(16);
    _kf['rsalt'] = base64.encode(s);
    _kf['rec'] = _wrap(await kdf(_nc(rc), s), _dk!.bytes);
    await _saveKf();
    return rc;
  }

  static Future<String> setup(String pin) async {
    final dk = _rnd(32);
    _dk = e.Key(_u(dk));
    await _setPin(pin, dk);
    return newRecovery();
  }

  /// null = OK, else error message (5 wrong tries = 5 min lock)
  static Future<String?> unlock(String pin, {bool load = true}) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final lock = (_kf['lock'] ?? 0) as int;
    if (now < lock) return 'Locked. Try again in ${((lock - now) / 60000).ceil()} min';
    final ds = await _ds();
    if (ds == null) return 'Device key missing (reinstall?). Use Forgot PIN with your recovery code, or restore a backup.';
    final dk = _unwrap(await kdf('$pin:$ds', base64.decode(_kf['salt'])), _kf['pin']);
    if (dk != null) {
      _dk = e.Key(_u(dk));
      _kf['fails'] = 0;
      await _saveKf();
      return load ? _load() : null;
    }
    final n = ((_kf['fails'] ?? 0) as int) + 1;
    _kf['fails'] = n; // only a correct PIN resets it, so lockouts escalate
    var m = 'Wrong PIN (${5 - n % 5} tries left)';
    if (n % 5 == 0) {
      final mins = n <= 5 ? 5 : (n <= 10 ? 60 : 1440);
      _kf['lock'] = now + mins * 60000;
      m = 'Too many tries. Locked for ${mins >= 60 ? '${mins ~/ 60} hour(s)' : '$mins minutes'}';
    }
    await _saveKf();
    return m;
  }

  static Future<String?> changePin(String old, String pin) async {
    final r = await unlock(old, load: false);
    if (r != null) return r;
    await _setPin(pin, _dk!.bytes);
    return null;
  }

  static Future<String?> recover(String code, String pin) async {
    final dk = _unwrap(await kdf(_nc(code), base64.decode(_kf['rsalt'])), _kf['rec']);
    if (dk == null) return 'Wrong recovery code';
    _dk = e.Key(_u(dk));
    await _setPin(pin, dk);
    return _load();
  }

  static Future<String?> _load() async {
    try {
      final f = await _f('vault.bin');
      if (await f.exists()) {
        final b = await f.readAsBytes();
        data = jsonDecode(_enc(_dk!).decrypt(e.Encrypted(_u(b.sublist(12))), iv: e.IV(_u(b.sublist(0, 12)))));
        _dropShareFields();
      }
      return null;
    } catch (_) {
      return 'Data file damaged. Restore from a backup.';
    }
  }

  static void lockMemory() {
    data = {'name': '', 'accounts': []};
    _dk = null;
  }

  static Future<void> _saveChain = Future.value();

  /// Saves one after another (two quick saves can never write the file at the same time), through a temp file
  /// so a crash can never leave a half-written vault.
  static Future<void> save() {
    final next = _saveChain.then((_) async {
      final k = _dk;
      if (k == null) return; // locked meanwhile: nothing to write
      final iv = e.IV.fromSecureRandom(12);
      final bytes = iv.bytes + _enc(k).encrypt(jsonEncode(data), iv: iv).bytes;
      final f = await _f('vault.bin');
      final t = File('${f.path}.tmp');
      await t.writeAsBytes(bytes, flush: true);
      await t.rename(f.path);
    });
    _saveChain = next.catchError((_) {});
    return next;
  }

  /// old versions could share accounts and sync through Firebase; both are gone, so drop their leftovers
  static void _dropShareFields() {
    data.remove('joins');
    data.remove('rulesOk');
    data.remove('syncUrl'); // Firebase sync was removed
    data.remove('syncKey');
    data.remove('gone');
    for (final x in [...((data['accounts'] as List?) ?? const []), ...((data['folders'] as List?) ?? const [])]) {
      for (final k in ['pw', 'members', 'shared', 'owner', 'isOwner', 'iid', 'isk', 'ipk', 'acl', 'revoked', 'nupd']) {
        x.remove(k);
      }
    }
  }

  // encrypted backup: passphrase -> PBKDF2 -> AES-GCM
  static Future<String> backup(String pass) async {
    final s = _rnd(16);
    final iv = e.IV.fromSecureRandom(12);
    final c = _enc(await kdf(pass, s)).encrypt(jsonEncode(data), iv: iv);
    return 'LGB1.${base64.encode(s)}.${base64.encode(iv.bytes + c.bytes)}';
  }

  static Future<String?> restore(String code, String pass) async {
    try {
      final p = code.trim().split('.');
      if (p.length != 3 || p[0] != 'LGB1') return 'Not a valid backup code';
      final b = base64.decode(p[2]);
      final d = jsonDecode(_enc(await kdf(pass, base64.decode(p[1])))
          .decrypt(e.Encrypted(_u(b.sublist(12))), iv: e.IV(_u(b.sublist(0, 12)))));
      data = d;
      _dropShareFields();
      await save();
      return null;
    } catch (_) {
      return 'Wrong passphrase or damaged backup';
    }
  }
}

String money(int paise) {
  final s = (paise.abs() / 100).toStringAsFixed(paise % 100 == 0 ? 0 : 2);
  final p = s.split('.');
  final r = p[0].replaceAllMapped(RegExp(r'(\d)(?=(\d{3})+$)'), (m) => '${m[1]},');
  return '${paise < 0 ? '-' : ''}$r${p.length > 1 ? '.${p[1]}' : ''}/-';
}

int bal(Map a) => (a['entries'] as List)
    .where((x) => x['del'] != true)
    .fold<int>(0, (t, x) => t + (x['type'] == 'credit' ? 1 : -1) * (x['amt'] as int));

// ---------- App ----------
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const App());
}

/// last time the person touched the screen or pressed a key ANYWHERE in the app (account pages, dialogs, settings...).
/// The auto-lock uses this. It must sit above the Navigator, otherwise only touches on the Home screen would count
/// and the app would lock while you are busy inside an account.
DateTime _lastTouch = DateTime.now();

class App extends StatelessWidget {
  const App({super.key});
  @override
  Widget build(BuildContext c) => MaterialApp(
        title: 'Mr.Kanakku Pillai',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(colorSchemeSeed: const Color(0xFF0B8A62), useMaterial3: true),
        builder: (c, child) => Listener(
          behavior: HitTestBehavior.translucent,
          onPointerDown: (_) => _lastTouch = DateTime.now(),
          onPointerSignal: (_) => _lastTouch = DateTime.now(),
          child: child ?? const SizedBox.shrink(),
        ),
        home: const Root(),
      );
}

enum Stage { loading, setPin, recovery, profile, lock, home }

class Root extends StatefulWidget {
  const Root({super.key});
  @override
  State<Root> createState() => _RootState();
}

class _RootState extends State<Root> with WidgetsBindingObserver {
  Stage st = Stage.loading;
  Timer? idle;
  String rec = '';
  // The PIN is asked again only after the app was NOT used for this long
  // (left in the background, or open but untouched). Switching to another app for a while is fine.
  static const _autoLock = Duration(minutes: 15);
  DateTime? _leftAt; // when the app went to the background (null while it is on screen)

  bool _expired() => DateTime.now().difference(_leftAt ?? _lastTouch) >= _autoLock;

  bool _onKey(KeyEvent ev) {
    _lastTouch = DateTime.now(); // typing on a keyboard (Windows / Linux) counts as use
    return false;
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    HardwareKeyboard.instance.addHandler(_onKey);
    _start();
    idle = Timer.periodic(const Duration(seconds: 15), (_) {
      if (_expired()) _lock();
    });
  }

  @override
  void dispose() {
    idle?.cancel();
    HardwareKeyboard.instance.removeHandler(_onKey);
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  // remember when the app was left; lock only if it stayed away for the whole auto-lock time
  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (s == AppLifecycleState.paused) {
      _leftAt ??= DateTime.now();
    } else if (s == AppLifecycleState.resumed) {
      final expired = _expired();
      _leftAt = null;
      if (expired) {
        _lock();
      } else {
        _lastTouch = DateTime.now(); // coming back counts as activity
      }
    }
  }

  void _lock() {
    if (st != Stage.home) return;
    Navigator.of(context).popUntil((r) => r.isFirst);
    Store.lockMemory();
    setState(() => st = Stage.lock);
  }

  Future<void> _start() async {
    final has = await Store.hasPin();
    setState(() => st = has ? Stage.lock : Stage.setPin);
  }

  @override
  Widget build(BuildContext c) => _screen();

  Widget _screen() {
    switch (st) {
      case Stage.loading:
        return const Scaffold(body: Center(child: CircularProgressIndicator()));
      case Stage.setPin:
        return PinSetup(onDone: (p) async {
          rec = await Store.setup(p);
          setState(() => st = Stage.recovery);
        });
      case Stage.recovery:
        return RecoveryScreen(code: rec, onDone: () => setState(() => st = Stage.profile));
      case Stage.profile:
        return ProfileScreen(onDone: () => setState(() => st = Stage.home));
      case Stage.lock:
        return PinEntry(
            title: 'Enter PIN',
            onOk: () => setState(
                () => st = (Store.data['name'] as String).isEmpty ? Stage.profile : Stage.home));
      case Stage.home:
        return const Home();
    }
  }
}

// ---------- PIN screens ----------
Widget pinField(TextEditingController t, String label, {String? err}) => TextField(
      controller: t,
      obscureText: true,
      maxLength: 32,
      textAlign: TextAlign.center,
      style: const TextStyle(fontSize: 22, letterSpacing: 4),
      decoration: InputDecoration(labelText: label, errorText: err, counterText: ''),
    );

class PinPad extends StatelessWidget {
  final String value;
  final ValueChanged<String> onChanged;
  final String? err;
  const PinPad({super.key, required this.value, required this.onChanged, this.err});
  @override
  Widget build(BuildContext c) {
    void add(String d) {
      if (value.length < 4) onChanged(value + d);
    }

    void back() {
      if (value.isNotEmpty) onChanged(value.substring(0, value.length - 1));
    }

    Widget key(String label, VoidCallback? tap, {IconData? icon}) => Padding(
          padding: const EdgeInsets.all(6),
          child: SizedBox(
            width: 76,
            height: 58,
            child: OutlinedButton(
                onPressed: tap, child: icon != null ? Icon(icon) : Text(label, style: const TextStyle(fontSize: 24))),
          ),
        );
    const digits = ['1', '2', '3', '4', '5', '6', '7', '8', '9'];
    return Focus(
      autofocus: true,
      onKeyEvent: (n, e) {
        if (e is KeyDownEvent) {
          final ch = e.character;
          if (ch != null && RegExp(r'^[0-9]$').hasMatch(ch)) {
            add(ch);
            return KeyEventResult.handled;
          }
          if (e.logicalKey == LogicalKeyboardKey.backspace) {
            back();
            return KeyEventResult.handled;
          }
        }
        return KeyEventResult.ignored;
      },
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        SizedBox(
          height: 30,
          child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            for (var i = 0; i < value.length; i++)
              const Padding(padding: EdgeInsets.all(3), child: Icon(Icons.circle, size: 14)),
          ]),
        ),
        SizedBox(
          height: 24,
          child: err == null ? null : Text(err!, style: TextStyle(color: Theme.of(c).colorScheme.error)),
        ),
        for (var r = 0; r < 3; r++)
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            for (var k = 0; k < 3; k++) key(digits[r * 3 + k], () => add(digits[r * 3 + k])),
          ]),
        Row(mainAxisAlignment: MainAxisAlignment.center, children: [
          key('', value.isEmpty ? null : () => onChanged(''), icon: Icons.clear),
          key('0', () => add('0')),
          key('', value.isEmpty ? null : back, icon: Icons.backspace_outlined),
        ]),
      ]),
    );
  }
}

class PinSetup extends StatefulWidget {
  final Future<void> Function(String) onDone;
  const PinSetup({super.key, required this.onDone});
  @override
  State<PinSetup> createState() => _PinSetupState();
}

class _PinSetupState extends State<PinSetup> {
  String first = '', cur = '';
  String? err;
  @override
  Widget build(BuildContext c) {
    final confirming = first.isNotEmpty;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Column(children: [
              const Text('Mr.Kanakku Pillai', textAlign: TextAlign.center, style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              Image.asset('assets/logo.png', height: 96),
              const SizedBox(height: 12),
              Text(confirming ? 'Confirm your PIN' : 'Set your PIN',
                  style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
              const SizedBox(height: 6),
              const Text('Use 4 digits. Tap the numbers below.'),
              const SizedBox(height: 12),
              PinPad(value: cur, err: err, onChanged: (v) => setState(() => cur = v)),
              const SizedBox(height: 12),
              FilledButton(
                onPressed: cur.isEmpty
                    ? null
                    : () {
                        if (!confirming) {
                          if (weakPin(cur)) return setState(() => err = 'Use 4 digits, not repeated or sequential');
                          setState(() {
                            first = cur;
                            cur = '';
                            err = null;
                          });
                        } else if (cur != first) {
                          setState(() {
                            first = '';
                            cur = '';
                            err = 'PINs did not match. Start again';
                          });
                        } else {
                          widget.onDone(cur);
                        }
                      },
                child: Text(confirming ? 'Confirm' : 'Next'),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}

class PinEntry extends StatefulWidget {
  final String title;
  final VoidCallback onOk;
  const PinEntry({super.key, required this.title, required this.onOk});
  @override
  State<PinEntry> createState() => _PinEntryState();
}

class _PinEntryState extends State<PinEntry> {
  String pin = '';
  String? err;
  bool busy = false;
  Future<void> go() async {
    if (busy) return;
    setState(() => busy = true);
    final r = await Store.unlock(pin);
    if (!mounted) return;
    if (r == null) return widget.onOk();
    setState(() {
      err = r;
      pin = '';
      busy = false;
    });
  }

  @override
  Widget build(BuildContext c) => Scaffold(
        body: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: Column(children: [
                const Text('Mr.Kanakku Pillai', textAlign: TextAlign.center, style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
                const SizedBox(height: 8),
                Image.asset('assets/logo.png', height: 96),
                const SizedBox(height: 12),
                Text(widget.title, style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
                const SizedBox(height: 12),
                PinPad(
                    value: pin,
                    err: err,
                    onChanged: (v) {
                      setState(() => pin = v);
                      if (v.length == 4) go();
                    }),
                const SizedBox(height: 12),
                FilledButton(onPressed: pin.length >= 4 && !busy ? go : null, child: Text(busy ? 'Checking…' : 'Unlock')),
                TextButton(
                  onPressed: () async {
                    final r = await ask(context, 'Reset PIN with recovery code',
                        ['Recovery code', '*New PIN (4 digits)']);
                    if (r == null) return;
                    final m = weakPin(r[1]) ? 'Use 4 digits, not repeated or sequential' : await Store.recover(r[0], r[1]);
                    if (m == null) {
                      widget.onOk();
                    } else {
                      setState(() => err = m);
                    }
                  },
                  child: const Text('Forgot PIN? Use recovery code'),
                ),
              ]),
            ),
          ),
        ),
      );
}

// ---------- Profile ----------
class ProfileScreen extends StatefulWidget {
  final VoidCallback onDone;
  const ProfileScreen({super.key, required this.onDone});
  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  final t = TextEditingController();
  @override
  Widget build(BuildContext c) => Scaffold(
        body: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
            const Icon(Icons.person, size: 56),
            const Text('Set up your profile',
                style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            const Text('This name shows as "by" on your entries.'),
            const SizedBox(height: 24),
            TextField(controller: t, decoration: const InputDecoration(labelText: 'Your name')),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () async {
                if (t.text.trim().isEmpty) return;
                Store.data['name'] = t.text.trim();
                await Store.save();
                widget.onDone();
              },
              child: const Text('Save & open app'),
            ),
          ]),
        ),
      );
}

// ---------- Home ----------
class Home extends StatefulWidget {
  const Home({super.key});
  @override
  State<Home> createState() => _HomeState();
}

class _HomeState extends State<Home> {
  Future<void> newItem() async {
    final k = await showDialog<String>(
        context: context,
        builder: (d) => SimpleDialog(title: const Text('Create'), children: [
              SimpleDialogOption(
                  onPressed: () => Navigator.pop(d, 'a'),
                  child: const Row(children: [Icon(Icons.description_outlined), SizedBox(width: 12), Text('New account')])),
              SimpleDialogOption(
                  onPressed: () => Navigator.pop(d, 'f'),
                  child: const Row(children: [Icon(Icons.create_new_folder_outlined), SizedBox(width: 12), Text('New folder')])),
            ]));
    if (!mounted) return;
    if (k == 'a') await createAccount(context);
    if (k == 'f') await createFolder(context);
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext c) {
    final total = Store.accounts.fold<int>(0, (t, a) => t + bal(a));
    return Scaffold(
      appBar: AppBar(
        title: Text('Hi, ${Store.data['name']}'),
        actions: [
          IconButton(
              icon: const Icon(Icons.receipt_long),
              tooltip: 'View all transactions',
              onPressed: () => Navigator.push(c, MaterialPageRoute(builder: (_) => const AllTransactions()))),
          IconButton(
              icon: const Icon(Icons.settings),
              onPressed: () => Navigator.push(c, MaterialPageRoute(builder: (_) => const Settings()))),
        ],
      ),
      floatingActionButton:
          FloatingActionButton.extended(onPressed: newItem, icon: const Icon(Icons.add), label: const Text('New')),
      body: ListView(padding: const EdgeInsets.all(12), children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.account_balance_wallet),
            title: const Text('Total Balance'),
            subtitle: Text('${money(total)} ${total >= 0 ? 'Credit' : 'Debit'}',
                style: TextStyle(
                    fontSize: 20, fontWeight: FontWeight.bold,
                    color: total >= 0 ? Colors.green[800] : Colors.red)),
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.receipt_long),
            title: const Text('View all transactions'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(c, MaterialPageRoute(builder: (_) => const AllTransactions())),
          ),
        ),
        for (final f in Store.folders)
          Card(
            child: ListTile(
              leading: const Icon(Icons.folder, size: 36),
              title: Text(f['name']),
              subtitle: Text('${folderAccounts(f).length} accounts'),
              trailing: itemActions(
                  c, f, folderAccounts(f).fold<int>(0, (t, a) => t + bal(a)),
                  'Delete folder "${f['name']}" and ALL accounts inside it?', () {
                Store.accounts.removeWhere((a) => a['folder'] == f['id']);
                Store.folders.remove(f);
              }, () => setState(() {})),
              onTap: () async {
                await Navigator.push(c, MaterialPageRoute(builder: (_) => FolderPage(f)));
                setState(() {});
              },
            ),
          ),
        for (final a in Store.accounts.where((a) => a['folder'] == null)) accountTile(c, a, () => setState(() {})),
        if (Store.accounts.isEmpty && Store.folders.isEmpty)
          const Padding(padding: EdgeInsets.all(40), child: Center(child: Text('Nothing yet. Tap New to add an account or folder.'))),
      ]),
    );
  }
}

// ---------- Helpers ----------
const _mo = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
String fd(dynamic iso) {
  final d = DateTime.parse('$iso');
  return '${d.day} ${_mo[d.month - 1]} ${d.year}';
}

String ft(dynamic iso) {
  final d = DateTime.parse('$iso');
  return '${d.hour.toString().padLeft(2, '0')}:${d.minute.toString().padLeft(2, '0')}';
}

// ---------- Ledger table look (blue header, green month bars, Credit / Debit / Balance columns) ----------
const double _wD = 46, _wA = 62;

String fdm(dynamic iso) {
  final d = DateTime.parse('$iso');
  return '${d.day.toString().padLeft(2, '0')} ${_mo[d.month - 1]}';
}

String monthKey(dynamic iso) {
  final d = DateTime.parse('$iso');
  return '${_mo[d.month - 1]} ${d.year}';
}

void scrollToEnd(ScrollController sc) => WidgetsBinding.instance.addPostFrameCallback((_) {
      if (sc.hasClients) sc.jumpTo(sc.position.maxScrollExtent);
    });

Widget _amtCell(String t, {Color? color, bool bold = false}) => SizedBox(
      width: _wA,
      child: Align(
        alignment: Alignment.centerRight,
        child: FittedBox(
          fit: BoxFit.scaleDown,
          alignment: Alignment.centerRight,
          child: Text(t, style: TextStyle(fontSize: 12, color: color, fontWeight: bold ? FontWeight.bold : null)),
        ),
      ),
    );

Widget ledgerHeader() {
  const hs = TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 12);
  Widget h(String t) => SizedBox(width: _wA, child: Text(t, style: hs, textAlign: TextAlign.right));
  return Container(
    color: Colors.blue.shade600,
    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
    child: Row(children: [
      const SizedBox(width: _wD, child: Text('Date', style: hs)),
      const Expanded(child: Text('Detail', style: hs)),
      h('Credit'),
      h('Debit'),
      h('Balance'),
    ]),
  );
}

Widget monthBar(String t) => Container(
      width: double.infinity,
      color: Colors.green.shade600,
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      child: Text(t, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
    );

/// one entry row: date, detail, then Credit / Debit / running Balance
Widget ledgerLine({
  required dynamic date,
  required Widget detail,
  int? credit,
  int? debit,
  required int bal,
  VoidCallback? onTap,
  VoidCallback? onLongPress,
  bool? selected, // null = not selecting; true / false = show a tick box
}) =>
    InkWell(
      onTap: onTap,
      onLongPress: onLongPress,
      child: Container(
        decoration: BoxDecoration(
          color: selected == true ? Colors.blue.shade50 : null,
          border: const Border(bottom: BorderSide(color: Colors.black26)),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          if (selected != null)
            Padding(
              padding: const EdgeInsets.only(right: 6, top: 1),
              child: Icon(selected ? Icons.check_box : Icons.check_box_outline_blank,
                  size: 20, color: selected ? Colors.blue.shade700 : Colors.grey),
            ),
          SizedBox(
            width: _wD,
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(fdm(date), style: const TextStyle(fontSize: 12)),
              Text(ft(date), style: const TextStyle(fontSize: 10, color: Colors.grey)),
            ]),
          ),
          Expanded(child: detail),
          _amtCell(credit == null ? '' : money(credit)),
          _amtCell(debit == null ? '' : money(debit), color: Colors.red),
          _amtCell(money(bal), bold: true, color: bal >= 0 ? Colors.green.shade800 : Colors.red),
        ]),
      ),
    );

/// rows (oldest first) with a green month bar whenever the month changes
List<Widget> ledgerRows<T>(List<T> rows, dynamic Function(T) dateOf, Widget Function(T) row) {
  final out = <Widget>[];
  String? cur;
  for (final r in rows) {
    final k = monthKey(dateOf(r));
    if (k != cur) {
      cur = k;
      out.add(monthBar(k));
    }
    out.add(row(r));
  }
  return out;
}

/// top bar while entries are selected: close, how many, select / deselect all
AppBar selectionAppBar(int count, bool allSelected, VoidCallback onClear, VoidCallback onToggleAll) => AppBar(
      leading: IconButton(icon: const Icon(Icons.close), tooltip: 'Finish selecting', onPressed: onClear),
      title: Text('$count selected'),
      actions: [
        IconButton(
            icon: Icon(allSelected ? Icons.deselect : Icons.select_all),
            tooltip: allSelected ? 'Deselect all' : 'Select all',
            onPressed: onToggleAll),
      ],
    );

/// bottom bar while entries are selected: total credit, total debit and the net of the selected entries
Widget selectionBar(int count, int credit, int debit) {
  Widget cell(String label, int v, Color col) => Expanded(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Text(label, style: const TextStyle(fontSize: 11, color: Colors.black54)),
          FittedBox(
              fit: BoxFit.scaleDown,
              child: Text(money(v), style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold, color: col))),
        ]),
      );
  final net = credit - debit;
  return Material(
    elevation: 10,
    color: Colors.blue.shade50,
    child: SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(children: [
          SizedBox(width: 62, child: Text('$count\nselected', style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold))),
          cell('Credit', credit, Colors.green.shade800),
          cell('Debit', debit, Colors.red),
          cell('Net', net, net >= 0 ? Colors.green.shade800 : Colors.red),
        ]),
      ),
    ),
  );
}

List<String> listOf(String k, List<String> d) =>
    ((Store.data[k] ??= List<String>.from(d)) as List).cast<String>();

List liveEntries(Map a) => (a['entries'] as List).where((x) => x['del'] != true).toList();

Map<String, int> runBal(Map a) {
  final es = liveEntries(a)..sort((p, q) => p['date'].compareTo(q['date']));
  var t = 0;
  final m = <String, int>{};
  for (final x in es) {
    t += (x['type'] == 'credit' ? 1 : -1) * (x['amt'] as int);
    m[x['id'] as String] = t;
  }
  return m;
}

void snack(BuildContext c, String m) {
  if (c.mounted) ScaffoldMessenger.of(c).showSnackBar(SnackBar(content: Text(m)));
}

Future<bool> confirm(BuildContext c, String msg) async =>
    await showDialog<bool>(
        context: c,
        builder: (d) => AlertDialog(content: Text(msg), actions: [
              TextButton(onPressed: () => Navigator.pop(d, false), child: const Text('Cancel')),
              FilledButton(onPressed: () => Navigator.pop(d, true), child: const Text('Yes')),
            ])) ==
    true;

/// re-check the PIN before sensitive actions (does not reload data)
Future<bool> confirmPin(BuildContext c, String why) async {
  final r = await ask(c, '$why - enter PIN', ['*PIN']);
  if (r == null) return false;
  final m = await Store.unlock(r[0], load: false);
  if (m != null) snack(c, m);
  return m == null;
}

// ---------- New / edit entry form ----------
Future<Map?> entryDialog(BuildContext c, {Map? old}) async {
  final now = DateTime.now();
  final date = old?['date'] ?? now.toIso8601String();
  final amt = TextEditingController(
      text: old == null ? '' : ((old['amt'] as int) / 100).toString().replaceAll(RegExp(r'\.0$'), ''));
  final note = TextEditingController(text: old?['note'] ?? '');
  final cats = listOf('categories', ['General', 'Food', 'Travel', 'Bills']);
  final modes = listOf('modes', ['Cash', 'GPay', 'PhonePe', 'Card']);
  String type = old?['type'] ?? 'debit';
  String cat = old?['category'] ?? cats.first;
  String pay = old?['payment'] ?? modes.first;
  if (!cats.contains(cat)) cats.add(cat);
  if (!modes.contains(pay)) modes.add(pay);
  String? err;
  Widget pick(String label, List<String> items, String val, void Function(String) on, VoidCallback add) =>
      Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const SizedBox(height: 8),
        Text(label),
        Row(children: [
          Expanded(
            child: DropdownButton<String>(
              isExpanded: true,
              value: val,
              items: [for (final x in items) DropdownMenuItem<String>(value: x, child: Text(x))],
              onChanged: (v) => on(v!),
            ),
          ),
          IconButton(tooltip: 'Add $label', icon: const Icon(Icons.add_circle_outline), onPressed: add),
        ]),
      ]);
  final ok = await showDialog<bool>(
    context: c,
    builder: (d) => StatefulBuilder(
      builder: (d, set) => AlertDialog(
        title: Text(old == null ? 'New entry' : 'Edit entry'),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Date & time: ${fd(date)} ${ft(date)}'),
            Text('User: ${Store.data['name']}'),
            TextField(
                controller: amt,
                autofocus: true,
                keyboardType: const TextInputType.numberWithOptions(decimal: true),
                decoration: InputDecoration(labelText: 'Amount', errorText: err)),
            TextField(controller: note, decoration: const InputDecoration(labelText: 'Details / remark')),
            pick('Category', cats, cat, (v) => set(() => cat = v), () async {
              final r = await ask(d, 'Add category', ['Category name']);
              if (r == null || r[0].isEmpty) return;
              if (!cats.contains(r[0])) cats.add(r[0]);
              set(() => cat = r[0]);
              await Store.save();
            }),
            pick('Payment mode', modes, pay, (v) => set(() => pay = v), () async {
              final r = await ask(d, 'Add payment mode', ['Payment mode name']);
              if (r == null || r[0].isEmpty) return;
              if (!modes.contains(r[0])) modes.add(r[0]);
              set(() => pay = r[0]);
              await Store.save();
            }),
            const SizedBox(height: 8),
            Wrap(children: [
              radioTile('Credit (+)', type == 'credit', () => set(() => type = 'credit')),
              radioTile('Debit (−)', type == 'debit', () => set(() => type = 'debit')),
            ]),
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(d, false), child: const Text('Cancel')),
          FilledButton(
            onPressed: () {
              final v = double.tryParse(amt.text);
              if (v == null || v <= 0) return set(() => err = 'Enter a valid amount');
              Navigator.pop(d, true);
            },
            child: const Text('Save'),
          ),
        ],
      ),
    ),
  );
  final v = double.tryParse(amt.text);
  if (ok != true || v == null || v <= 0) return null;
  return {'type': type, 'amt': (v * 100).round(), 'note': note.text.trim(), 'category': cat, 'payment': pay, 'date': date};
}

// ---------- Account ledger ----------
class AccountPage extends StatefulWidget {
  final Map a;
  const AccountPage(this.a, {super.key});
  @override
  State<AccountPage> createState() => _AccountPageState();
}

class _AccountPageState extends State<AccountPage> {
  bool searching = false;
  final sq = TextEditingController();
  final _sc = ScrollController();
  bool _first = true;
  final _sel = <String>{}; // ids of the selected entries

  void _toggle(String id) => setState(() {
        if (!_sel.remove(id)) _sel.add(id);
      });

  @override
  void dispose() {
    _sc.dispose();
    super.dispose();
  }

  /// tap a row: Edit or Delete
  Future<void> _rowMenu(Map x) async {
    final v = await showDialog<String>(
        context: context,
        builder: (d) => SimpleDialog(
                title: Text((x['note'] ?? '').isEmpty ? (x['type'] == 'credit' ? 'Credit' : 'Debit') : '${x['note']}'),
                children: [
                  SimpleDialogOption(onPressed: () => Navigator.pop(d, 'e'), child: const Text('Edit')),
                  SimpleDialogOption(onPressed: () => Navigator.pop(d, 'd'), child: const Text('Delete')),
                ]));
    if (v == 'e') await addOrEdit(x);
    if (v == 'd') await delEntry(x);
  }

  Future<void> _rename() async {
    if (await renameItem(context, widget.a)) setState(() {});
  }

  Future<void> addOrEdit([Map? old]) async {
    final r = await entryDialog(context, old: old);
    if (r == null) return;
    final now = DateTime.now();
    // read the list only AFTER the form closed
    final es = widget.a['entries'] as List;
    if (old == null) {
      es.insert(0, {
        ...r,
        'id': now.microsecondsSinceEpoch.toString(),
        'upd': now.millisecondsSinceEpoch,
        'by': Store.data['name'],
      });
    } else {
      // find the entry again by its id, then change it
      final cur = es.firstWhere((x) => x['id'] == old['id'], orElse: () => old);
      cur.addAll(r);
      cur['upd'] = now.millisecondsSinceEpoch;
      cur['by'] = Store.data['name'];
    }
    await Store.save();
    if (mounted) setState(() {});
    if (old == null) scrollToEnd(_sc); // the new entry is at the bottom
  }

  Future<void> delEntry(Map x) async {
    if (!await confirm(context, 'Delete this entry?')) return;
    final cur = (widget.a['entries'] as List).firstWhere((y) => y['id'] == x['id'], orElse: () => x);
    cur['del'] = true; // kept hidden instead of removed
    cur['upd'] = DateTime.now().millisecondsSinceEpoch;
    _sel.remove('${x['id']}');
    cur['by'] = Store.data['name'];
    await Store.save();
    if (mounted) setState(() {});
  }

  Future<void> exportAs(String kind) async {
    final bals = runBal(widget.a);
    final es = liveEntries(widget.a)..sort((p, q) => p['date'].compareTo(q['date']));
    final head = ['Date', 'Time', 'Details', 'Category', 'Payment mode', 'Type', 'Amount', 'Balance', 'By'];
    final data = <List<Object>>[
      for (final x in es)
        [fd(x['date']), ft(x['date']), '${x['note']}', '${x['category'] ?? ''}', '${x['payment'] ?? ''}', '${x['type']}',
          (x['amt'] as int) / 100, (bals[x['id']] ?? 0) / 100, '${x['by']}']
    ];
    var cin = 0.0, cout = 0.0;
    for (final x in es) {
      if (x['type'] == 'credit') {
        cin += (x['amt'] as int) / 100;
      } else {
        cout += (x['amt'] as int) / 100;
      }
    }
    String n2(num v) => v == v.roundToDouble() ? v.toStringAsFixed(0) : v.toStringAsFixed(2);
    String lat(String s) => s.replaceAll(RegExp(r'[^\x00-\xFF]'), '?'); // default PDF font is Latin-only
    final base = '${widget.a['name']}'.replaceAll(RegExp(r'[^A-Za-z0-9_-]'), '_');
    List<int> bytes;
    String file;
    if (kind == 'xlsx') {
      final ex = xl.Excel.createExcel();
      ex.rename('Sheet1', 'Ledger');
      final sh = ex['Ledger'];
      sh.appendRow([for (final h in head) xl.TextCellValue(h)]);
      for (final r in data) {
        sh.appendRow([for (final v in r) v is num ? xl.DoubleCellValue(v.toDouble()) : xl.TextCellValue('$v')]);
      }
      sh.appendRow([xl.TextCellValue('')]);
      sh.appendRow([xl.TextCellValue('Cash In'), xl.DoubleCellValue(cin)]);
      sh.appendRow([xl.TextCellValue('Cash Out'), xl.DoubleCellValue(cout)]);
      sh.appendRow([xl.TextCellValue('Net Balance'), xl.DoubleCellValue(cin - cout)]);
      bytes = ex.encode()!;
      file = '${base}_ledger.xlsx';
    } else if (kind == 'pdf') {
      final doc = pw.Document();
      doc.addPage(pw.MultiPage(
        build: (_) => [
          pw.Text(lat('${widget.a['name']}'), style: pw.TextStyle(fontSize: 18, fontWeight: pw.FontWeight.bold)),
          pw.Text('Cash In ${n2(cin)}    Cash Out ${n2(cout)}    Net Balance ${n2(cin - cout)}'),
          pw.SizedBox(height: 8),
          pw.TableHelper.fromTextArray(
            headers: ['Date & Time', 'Details', 'Category', 'Mode', 'Amount', 'Balance'],
            data: [
              for (final r in data)
                [lat('${r[0]} ${r[1]}'), lat('${r[2]}'), lat('${r[3]}'), lat('${r[4]}'),
                  '${r[5] == 'credit' ? '+' : '-'}${n2(r[6] as num)}', n2(r[7] as num)]
            ],
            cellStyle: const pw.TextStyle(fontSize: 9),
            headerStyle: pw.TextStyle(fontSize: 9, fontWeight: pw.FontWeight.bold),
          ),
        ],
      ));
      bytes = await doc.save();
      file = '${base}_ledger.pdf';
    } else {
      String esc(Object? v) => '"${'$v'.replaceAll('"', '""')}"';
      final b = StringBuffer('${head.join(',')}\n');
      for (final r in data) {
        b.writeln(r.map(esc).join(','));
      }
      bytes = utf8.encode(b.toString());
      file = '${base}_ledger.csv';
    }
    try {
      final m = await deliverFile(file, bytes);
      if (mounted) snack(context, m);
    } catch (_) {
      if (mounted) snack(context, 'Could not save the file');
    }
  }

  @override
  Widget build(BuildContext c) {
    final all = liveEntries(widget.a)..sort((p, q) => p['date'].compareTo(q['date'])); // oldest first, like a cash book
    final bals = runBal(widget.a);
    if (_first) {
      _first = false;
      scrollToEnd(_sc); // open at the latest entries
    }
    final qs = sq.text.toLowerCase();
    final shown = qs.isEmpty
        ? all
        : all.where((x) => '${x['note']} ${x['category']} ${x['payment']} ${x['by']} ${x['amt'] / 100}'.toLowerCase().contains(qs)).toList();
    var cin = 0, cout = 0;
    for (final x in all) {
      if (x['type'] == 'credit') {
        cin += x['amt'] as int;
      } else {
        cout += x['amt'] as int;
      }
    }
    // the selected entries and their totals (they change as entries are selected or deselected)
    var sCount = 0, sCr = 0, sDb = 0;
    for (final x in shown) {
      if (_sel.contains('${x['id']}')) {
        sCount++;
        if (x['type'] == 'credit') {
          sCr += x['amt'] as int;
        } else {
          sDb += x['amt'] as int;
        }
      }
    }
    final selecting = sCount > 0;
    Widget card(String t, int v, Color col) => Expanded(
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(t, style: const TextStyle(fontSize: 12)),
                const SizedBox(height: 4),
                FittedBox(fit: BoxFit.scaleDown, child: Text(money(v), style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: col))),
              ]),
            ),
          ),
        );
    return PopScope(
      canPop: !selecting, // back first leaves selection mode
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) setState(_sel.clear);
      },
      child: Scaffold(
      appBar: selecting
          ? selectionAppBar(sCount, sCount == shown.length, () => setState(_sel.clear), () {
              setState(() {
                if (sCount == shown.length) {
                  _sel.clear();
                } else {
                  _sel.addAll([for (final x in shown) '${x['id']}']);
                }
              });
            })
          : AppBar(
        title: searching
            ? TextField(controller: sq, autofocus: true, decoration: const InputDecoration(hintText: 'Search remark or amount…', border: InputBorder.none), onChanged: (_) => setState(_sel.clear))
            : InkWell(
                onTap: _rename,
                child: Row(mainAxisSize: MainAxisSize.min, children: [
                  Flexible(child: Text('${widget.a['name']}', overflow: TextOverflow.ellipsis)),
                  const SizedBox(width: 6),
                  const Icon(Icons.edit, size: 16),
                ]),
              ),
        actions: [
          IconButton(
              icon: Icon(searching ? Icons.close : Icons.search),
              tooltip: 'Search',
              onPressed: () => setState(() {
                    searching = !searching;
                    if (!searching) sq.clear();
                  })),
          PopupMenuButton<String>(
            icon: const Icon(Icons.table_view),
            tooltip: 'Export (Excel / PDF / CSV)',
            onSelected: exportAs,
            itemBuilder: (_) => const [
              PopupMenuItem(
                  value: 'xlsx',
                  child: Row(children: [Icon(Icons.table_chart, color: Colors.green), SizedBox(width: 10), Text('Excel (.xlsx)')])),
              PopupMenuItem(
                  value: 'pdf',
                  child: Row(children: [Icon(Icons.picture_as_pdf, color: Colors.red), SizedBox(width: 10), Text('PDF')])),
              PopupMenuItem(
                  value: 'csv',
                  child: Row(children: [Icon(Icons.description_outlined), SizedBox(width: 10), Text('CSV')])),
            ],
          ),
        ],
      ),
      floatingActionButton:
          selecting ? null : FloatingActionButton(onPressed: addOrEdit, tooltip: 'Add entry', child: const Icon(Icons.add)),
      bottomNavigationBar: selecting ? selectionBar(sCount, sCr, sDb) : null,
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(8, 4, 8, 0),
          child: Row(children: [
            card('Cash In', cin, Colors.green.shade800),
            card('Cash Out', cout, Colors.red),
            card('Net Balance', cin - cout, Colors.black87),
          ]),
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(8, 4, 12, 2),
          child: Align(
              alignment: Alignment.centerRight,
              child: Text('Closing Balance : ${money(cin - cout)}',
                  style: const TextStyle(fontSize: 12, fontStyle: FontStyle.italic))),
        ),
        ledgerHeader(),
        Expanded(
          child: ListView(controller: _sc, padding: const EdgeInsets.only(bottom: 88), children: [
            if (shown.isEmpty) const Padding(padding: EdgeInsets.all(40), child: Center(child: Text('No entries. Tap + to add one.'))),
            ...ledgerRows(shown, (x) => x['date'], (x) {
              final cr = x['type'] == 'credit';
              return ledgerLine(
                date: x['date'],
                credit: cr ? x['amt'] as int : null,
                debit: cr ? null : x['amt'] as int,
                bal: bals[x['id']] ?? 0,
                onTap: () => selecting ? _toggle('${x['id']}') : _rowMenu(x),
                onLongPress: () => _toggle('${x['id']}'),
                selected: selecting ? _sel.contains('${x['id']}') : null,
                detail: Padding(
                  padding: const EdgeInsets.only(right: 4),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text((x['note'] ?? '').isEmpty ? (cr ? 'Credit' : 'Debit') : x['note'],
                        style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                    Text([x['category'], x['payment'], 'by ${x['by']}'].where((t) => t != null).join(' · '),
                        style: TextStyle(fontSize: 11, color: Colors.grey.shade700)),
                  ]),
                ),
              );
            }),
          ]),
        ),
      ]),
    ));
  }
}

// ---------- All transactions (every account) ----------
class AllTransactions extends StatefulWidget {
  const AllTransactions({super.key});
  @override
  State<AllTransactions> createState() => _AllTransactionsState();
}

class _AllTransactionsState extends State<AllTransactions> {
  DateTimeRange? range;
  bool searching = false;
  final sq = TextEditingController();
  final _sc = ScrollController();
  bool _first = true;
  final _sel = <String>{}; // keys (account id + entry id) of the selected entries

  void _toggle(String k) => setState(() {
        if (!_sel.remove(k)) _sel.add(k);
      });

  @override
  void dispose() {
    _sc.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext c) {
    // oldest first, with the running balance across all accounts (like a cash book)
    final rows = [
      for (final a in Store.accounts) for (final x in liveEntries(a)) {'x': x, 'acc': a['name'], 'type': a['type'], 'aid': a['id']}
    ]..sort((p, q) => (p['x'] as Map)['date'].compareTo((q['x'] as Map)['date']));
    var run = 0;
    for (final r in rows) {
      final x = r['x'] as Map;
      run += (x['type'] == 'credit' ? 1 : -1) * (x['amt'] as int);
      r['bal'] = run;
    }
    if (_first) {
      _first = false;
      scrollToEnd(_sc); // open at the latest transactions
    }
    final qs = sq.text.toLowerCase();
    final shown0 = qs.isEmpty
        ? rows
        : rows.where((r) {
            final x = r['x'] as Map;
            return '${x['note']} ${x['category']} ${x['payment']} ${r['acc']} ${x['amt'] / 100}'.toLowerCase().contains(qs);
          }).toList();
    final rg = range;
    final shown = rg == null
        ? shown0
        : shown0.where((r) {
            final d = DateTime.parse('${(r['x'] as Map)['date']}');
            return !d.isBefore(DateTime(rg.start.year, rg.start.month, rg.start.day)) &&
                d.isBefore(DateTime(rg.end.year, rg.end.month, rg.end.day).add(const Duration(days: 1)));
          }).toList();
    var cr = 0, db = 0;
    for (final r in shown) {
      final x = r['x'] as Map;
      if (x['type'] == 'credit') {
        cr += x['amt'] as int;
      } else {
        db += x['amt'] as int;
      }
    }
    const hs = TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 12);
    String keyOf(Map r) => '${r['aid']}:${(r['x'] as Map)['id']}';
    // the selected entries and their totals (they change as entries are selected or deselected)
    var sCount = 0, sCr = 0, sDb = 0;
    for (final r in shown) {
      if (_sel.contains(keyOf(r))) {
        final x = r['x'] as Map;
        sCount++;
        if (x['type'] == 'credit') {
          sCr += x['amt'] as int;
        } else {
          sDb += x['amt'] as int;
        }
      }
    }
    final selecting = sCount > 0;
    return PopScope(
      canPop: !selecting, // back first leaves selection mode
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) setState(_sel.clear);
      },
      child: Scaffold(
      appBar: selecting
          ? selectionAppBar(sCount, sCount == shown.length, () => setState(_sel.clear), () {
              setState(() {
                if (sCount == shown.length) {
                  _sel.clear();
                } else {
                  _sel.addAll([for (final r in shown) keyOf(r)]);
                }
              });
            })
          : AppBar(
        title: searching
            ? TextField(controller: sq, autofocus: true, decoration: const InputDecoration(hintText: 'Search…', border: InputBorder.none), onChanged: (_) => setState(_sel.clear))
            : const Text('All transactions'),
        actions: [
          IconButton(
              icon: const Icon(Icons.calendar_month),
              tooltip: 'Filter by date',
              onPressed: () async {
                final r = await showDateRangePicker(
                    context: c, firstDate: DateTime(2000), lastDate: DateTime(2100), initialDateRange: range);
                if (r != null) setState(() => range = r);
              }),
          IconButton(
              icon: Icon(searching ? Icons.close : Icons.search),
              onPressed: () => setState(() {
                    searching = !searching;
                    if (!searching) sq.clear();
                  })),
        ],
      ),
      bottomNavigationBar: selecting ? selectionBar(sCount, sCr, sDb) : null,
      body: Column(children: [
        if (rg != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(10, 6, 10, 0),
            child: Row(children: [
              const Icon(Icons.calendar_month, size: 18),
              const SizedBox(width: 6),
              Expanded(child: Text('${fd(rg.start.toIso8601String())} to ${fd(rg.end.toIso8601String())}  (${shown.length} entries)')),
              TextButton(onPressed: () => setState(() => range = null), child: const Text('Clear')),
            ]),
          ),
        Padding(
          padding: const EdgeInsets.fromLTRB(8, 4, 12, 2),
          child: Align(
              alignment: Alignment.centerRight,
              child: Text('Closing Balance : ${money(run)}', style: const TextStyle(fontSize: 12, fontStyle: FontStyle.italic))),
        ),
        ledgerHeader(),
        Expanded(
          child: ListView(controller: _sc, children: [
            if (shown.isEmpty) const Padding(padding: EdgeInsets.all(40), child: Center(child: Text('No transactions'))),
            ...ledgerRows(shown, (r) => (r['x'] as Map)['date'], (r) {
              final x = r['x'] as Map;
              final isCr = x['type'] == 'credit';
              return ledgerLine(
                date: x['date'],
                credit: isCr ? x['amt'] as int : null,
                debit: isCr ? null : x['amt'] as int,
                bal: r['bal'] as int,
                onTap: selecting ? () => _toggle(keyOf(r)) : null,
                onLongPress: () => _toggle(keyOf(r)),
                selected: selecting ? _sel.contains(keyOf(r)) : null,
                detail: Padding(
                  padding: const EdgeInsets.only(right: 4),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text((x['note'] ?? '').isEmpty ? '-' : '${x['note']}',
                        style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                    Text('${r['acc']} · ${r['type'] == 'official' ? 'Official' : 'Personal'}',
                        style: TextStyle(fontSize: 11, color: Colors.grey.shade700)),
                  ]),
                ),
              );
            }),
          ]),
        ),
        Container(
          color: Colors.blue.shade600,
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
          child: Row(children: [
            const SizedBox(width: _wD),
            const Expanded(child: Text('Total', style: hs)),
            SizedBox(width: _wA, child: FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerRight, child: Text(money(cr), style: hs))),
            SizedBox(width: _wA, child: FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerRight, child: Text(money(db), style: hs))),
            const SizedBox(width: _wA),
          ]),
        ),
      ]),
    ));
  }
}

class HelpScreen extends StatelessWidget {
  const HelpScreen({super.key});
  @override
  Widget build(BuildContext c) => Scaffold(
        appBar: AppBar(title: const Text('Backup help')),
        body: const SingleChildScrollView(
          padding: EdgeInsets.all(20),
          child: Text(
              'BACKUP (no email or cloud is used, so YOU keep the backups)\n'
              '1. Settings > Encrypted backup. Choose a passphrase of 8+ characters, different from your PIN.\n'
              '2. The backup code is copied. Paste it somewhere safe: WhatsApp/Telegram "message yourself", an email to yourself, or a notes app. '
              'On Windows a ledger_backup.txt is also saved in Downloads.\n'
              '3. Keep copies in two places. Back up weekly and after big changes.\n'
              '4. Never store the passphrase next to the code. Lose the passphrase and the backup cannot be opened by anyone.\n\n'
              'RESTORE on a new phone or PC\n'
              'Install the app, set a PIN and profile, then Settings > Restore backup, paste the code and enter the passphrase. '
              'This replaces the data on that device.\n\n'
              'MOVE YOUR DATA TO ANOTHER PHONE OR PC\n'
              'The app works fully offline and is for one person. To use it on another device, make an encrypted backup here and restore it there (see BACKUP and RESTORE above).\n\n'
              'SELECT AND ADD UP\n'
              'In an account or in All transactions, long-press an entry to start selecting. Tap more entries to add or remove them, or use the select-all button at the top. The bar at the bottom shows the total credit, debit and net of the selected entries, and changes as you select or deselect. Press the cross or the back button to finish.\n\n'
              'FOLDERS\n'
              'Tap New > New folder, open it and add accounts inside, or long-press an account to move it into a folder. Deleting a folder deletes all accounts inside it.\n\n'
              'RENAME\n'
              'Open the account or folder and tap its name (the one with the pencil) at the top of the page.\n\n'
              'SAFETY\n'
              'The app asks for your PIN again only after 15 minutes of not using it (away in another app, or open but untouched). Deleting and backup always ask for your PIN. '
              'Exported Excel, PDF and CSV files are NOT encrypted: delete them after use. Use a PIN of 4 digits.'),
        ),
      );
}

// ---------- Dialog helper, recovery screen, settings ----------
/// labels starting with '*' are hidden (password style)
Future<List<String>?> ask(BuildContext c, String title, List<String> labels, {List<String>? initial}) async {
  final cs = [
    for (var i = 0; i < labels.length; i++)
      TextEditingController(text: initial != null && i < initial.length ? initial[i] : '')
  ];
  final ok = await showDialog<bool>(
    context: c,
    builder: (d) => AlertDialog(
      title: Text(title),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        for (var i = 0; i < labels.length; i++)
          TextField(
              controller: cs[i],
              obscureText: labels[i].startsWith('*'),
              decoration: InputDecoration(labelText: labels[i].replaceFirst('*', ''))),
      ]),
      actions: [
        TextButton(onPressed: () => Navigator.pop(d, false), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(d, true), child: const Text('OK')),
      ],
    ),
  );
  return ok == true ? [for (final x in cs) x.text.trim()] : null;
}

class RecoveryScreen extends StatelessWidget {
  final String code;
  final VoidCallback onDone;
  const RecoveryScreen({super.key, required this.code, required this.onDone});
  @override
  Widget build(BuildContext c) => Scaffold(
        body: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
            const Icon(Icons.vpn_key, size: 56),
            const Text('Save your recovery code',
                style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
            const SizedBox(height: 16),
            SelectableText(code, style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
            const SizedBox(height: 16),
            const Text('This is the ONLY way to reset a forgotten PIN. Write it on paper and keep it safe. '
                'It is not shown again (you can make a new one in Settings).',
                textAlign: TextAlign.center),
            OutlinedButton(onPressed: () => copySecret(code), child: const Text('Copy (clears in 60 s)')),
            const SizedBox(height: 8),
            FilledButton(onPressed: onDone, child: const Text('I have saved it')),
          ]),
        ),
      );
}

class Settings extends StatelessWidget {
  const Settings({super.key});
  void msg(BuildContext c, String m) =>
      ScaffoldMessenger.of(c).showSnackBar(SnackBar(content: Text(m)));
  @override
  Widget build(BuildContext c) => Scaffold(
        appBar: AppBar(title: const Text('Settings')),
        body: ListView(children: [
          ListTile(
            leading: const Icon(Icons.help_outline),
            title: const Text('Backup help'),
            onTap: () => Navigator.push(c, MaterialPageRoute(builder: (_) => const HelpScreen())),
          ),
          ListTile(
            leading: const Icon(Icons.pin),
            title: const Text('Change PIN / passphrase'),
            subtitle: const Text('4 digits, not repeated or sequential'),
            onTap: () async {
              final r = await ask(c, 'Change PIN', ['*Old PIN', '*New PIN (4 digits)']);
              if (r == null) return;
              if (weakPin(r[1])) return msg(c, 'Use 4 digits, not repeated or sequential');
              msg(c, await Store.changePin(r[0], r[1]) ?? 'PIN changed');
            },
          ),
          ListTile(
            leading: const Icon(Icons.vpn_key),
            title: const Text('New recovery code'),
            onTap: () async {
              final r = await ask(c, 'Confirm PIN', ['*PIN']);
              if (r == null) return;
              final err = await Store.unlock(r[0], load: false);
              if (err != null) return msg(c, err);
              final code = await Store.newRecovery();
              if (c.mounted) {
                await showDialog(
                    context: c,
                    builder: (d) => AlertDialog(
                        title: const Text('New recovery code'),
                        content: SelectableText('$code\n\nWrite it down. The old code no longer works.'),
                        actions: [TextButton(onPressed: () => Navigator.pop(d), child: const Text('Done'))]));
              }
            },
          ),
          ListTile(
            leading: const Icon(Icons.backup),
            title: const Text('Encrypted backup'),
            subtitle: const Text('Copies a backup code (and saves a file in Downloads if possible)'),
            onTap: () async {
              if (!await confirmPin(c, 'Create backup')) return;
              final r = await ask(c, 'Backup', ['*Backup passphrase (8+ characters)']);
              if (r == null) return;
              if (r[0].length < 8) return msg(c, 'Passphrase must be at least 8 characters');
              final code = await Store.backup(r[0]);
              await copySecret(code);
              var where = 'Backup code copied. Paste it somewhere safe.';
              try {
                final dir = await getDownloadsDirectory();
                if (dir != null) {
                  await File('${dir.path}/ledger_backup.txt').writeAsString(code);
                  where = 'Saved ledger_backup.txt in Downloads and copied the code.';
                }
              } catch (_) {}
              msg(c, where);
            },
          ),
          ListTile(
            leading: const Icon(Icons.restore),
            title: const Text('Restore backup'),
            subtitle: const Text('Replaces all data on this device'),
            onTap: () async {
              final r = await ask(c, 'Restore (replaces current data)', ['Backup code', '*Backup passphrase']);
              if (r == null) return;
              msg(c, await Store.restore(r[0], r[1]) ?? 'Backup restored. Go back to see your accounts.');
            },
          ),
        ]),
      );
}

/// renames an account or folder
Future<bool> renameItem(BuildContext c, Map item) async {
  final isF = item['kind'] == 'folder';
  final r = await ask(c, isF ? 'Rename folder' : 'Rename account', [isF ? 'Folder name' : 'Account name'],
      initial: ['${item['name']}']);
  if (r == null || r[0].isEmpty || r[0] == item['name']) return false;
  item['name'] = r[0];
  await Store.save();
  return true;
}

Widget radioTile(String label, bool on, VoidCallback tap) => InkWell(
      onTap: tap,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(0, 8, 16, 8),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(on ? Icons.radio_button_checked : Icons.radio_button_unchecked, size: 22),
          const SizedBox(width: 6),
          Text(label),
        ]),
      ),
    );

/// PIN = exactly 4 digits (keypad), not repeated, not a simple sequence
bool weakPin(String p) =>
    !RegExp(r'^[0-9]{4}$').hasMatch(p) ||
    p.split('').toSet().length < 2 ||
    '01234567890123456789'.contains(p) ||
    '98765432109876543210'.contains(p);

// ---------- Folders ----------
List folderAccounts(Map f) => Store.accounts.where((a) => a['folder'] == f['id']).toList();

Future<void> createAccount(BuildContext c, {String? folder}) async {
  final n = TextEditingController();
  String type = 'personal';
  final ok = await showDialog<bool>(
    context: c,
    builder: (d) => StatefulBuilder(
      builder: (d, set) => AlertDialog(
        title: const Text('New Account'),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          TextField(controller: n, decoration: const InputDecoration(labelText: 'Account name')),
          const SizedBox(height: 12),
          const Text('Account type'),
          radioTile('Personal', type == 'personal', () => set(() => type = 'personal')),
          radioTile('Official', type == 'official', () => set(() => type = 'official')),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(d, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(d, true), child: const Text('Create')),
        ],
      ),
    ),
  );
  if (ok == true && n.text.trim().isNotEmpty) {
    Store.accounts.add(<String, dynamic>{
      'id': DateTime.now().microsecondsSinceEpoch.toString(),
      'name': n.text.trim(),
      'type': type,
      'entries': [],
      if (folder != null) 'folder': folder,
    });
    await Store.save();
  }
}

Future<void> createFolder(BuildContext c) async {
  final r = await ask(c, 'New folder', ['Folder name']);
  if (r == null || r[0].isEmpty) return;
  Store.folders.add(<String, dynamic>{'id': DateTime.now().microsecondsSinceEpoch.toString(), 'name': r[0], 'kind': 'folder'});
  await Store.save();
}

/// balance + delete (PIN required) for an account or folder row
Widget itemActions(BuildContext c, Map item, int balance, String delMsg, VoidCallback remove, VoidCallback refresh) {
  return Row(mainAxisSize: MainAxisSize.min, children: [
    Text(money(balance), style: TextStyle(color: balance >= 0 ? Colors.green[800] : Colors.red)),
    IconButton(
      icon: const Icon(Icons.delete_outline),
      tooltip: 'Delete',
      onPressed: () async {
        final r = await ask(c, '$delMsg Enter PIN to confirm', ['*PIN']);
        if (r == null) return;
        final m = await Store.unlock(r[0], load: false);
        if (m != null) return snack(c, m);
        remove();
        await Store.save();
        refresh();
      },
    ),
  ]);
}

Widget accountTile(BuildContext c, Map a, VoidCallback refresh) => Card(
      child: ListTile(
        leading: CircleAvatar(child: Text(a['name'][0].toUpperCase())),
        title: Text(a['name']),
        subtitle: Text('${a['type'] == 'official' ? 'Official' : 'Personal'} · long-press to move to a folder'),
        trailing: itemActions(c, a, bal(a), 'Delete "${a['name']}" and ALL its entries?', () => Store.accounts.remove(a), refresh),
        onTap: () async {
          await Navigator.push(c, MaterialPageRoute(builder: (_) => AccountPage(a)));
          refresh();
        },
        onLongPress: () async {
          await moveToFolder(c, a);
          refresh();
        },
      ),
    );

class FolderPage extends StatefulWidget {
  final Map f;
  const FolderPage(this.f, {super.key});
  @override
  State<FolderPage> createState() => _FolderPageState();
}

class _FolderPageState extends State<FolderPage> {
  @override
  Widget build(BuildContext c) {
    final accs = folderAccounts(widget.f);
    final total = accs.fold<int>(0, (t, a) => t + bal(a));
    return Scaffold(
      appBar: AppBar(
        title: InkWell(
          onTap: () async {
            if (await renameItem(c, widget.f)) setState(() {});
          },
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Flexible(child: Text('${widget.f['name']}', overflow: TextOverflow.ellipsis)),
            const SizedBox(width: 6),
            const Icon(Icons.edit, size: 16),
          ]),
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () async {
          await createAccount(c, folder: widget.f['id']);
          setState(() {});
        },
        icon: const Icon(Icons.add),
        label: const Text('New account'),
      ),
      body: ListView(padding: const EdgeInsets.all(12), children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.folder),
            title: const Text('Folder balance'),
            subtitle: Text('${money(total)} ${total >= 0 ? 'Credit' : 'Debit'}',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: total >= 0 ? Colors.green[800] : Colors.red)),
          ),
        ),
        for (final a in accs) accountTile(c, a, () => setState(() {})),
        if (accs.isEmpty) const Padding(padding: EdgeInsets.all(40), child: Center(child: Text('No accounts in this folder. Tap New account.'))),
      ]),
    );
  }
}

/// saves (desktop) or opens the share sheet (phone) for an exported file
Future<String> deliverFile(String name, List<int> bytes) async {
  if (Platform.isAndroid || Platform.isIOS) {
    final f = File('${(await getTemporaryDirectory()).path}/$name');
    await f.writeAsBytes(bytes);
    await Share.shareXFiles([XFile(f.path)]);
    try {
      await f.delete();
    } catch (_) {}
    return 'Exported. The file is NOT encrypted - delete it after use.';
  }
  final d = await getDownloadsDirectory() ?? await getApplicationDocumentsDirectory();
  final f = File('${d.path}/$name');
  await f.writeAsBytes(bytes);
  return 'Saved ${f.path} (NOT encrypted - delete after use)';
}

/// moves an account into a folder (or back to the main list)
Future<void> moveToFolder(BuildContext c, Map a) async {
  final k = await showDialog<String>(
    context: c,
    builder: (d) => SimpleDialog(title: Text('Move "${a['name']}" to'), children: [
      SimpleDialogOption(onPressed: () => Navigator.pop(d, ''), child: const Text('Main list (no folder)')),
      for (final f in Store.folders)
        SimpleDialogOption(
            onPressed: () => Navigator.pop(d, '${f['id']}'),
            child: Row(children: [const Icon(Icons.folder), const SizedBox(width: 10), Expanded(child: Text('${f['name']}'))])),
    ]),
  );
  if (k == null) return;
  if (k.isEmpty) {
    a.remove('folder');
  } else {
    a['folder'] = k;
  }
  await Store.save();
}
