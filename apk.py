import telebot
import zipfile
import re
import json
import os
import threading
import tempfile
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BOT_TOKEN = "8500316293:AAGIHRUG0J0Oi6Yd4R97Dz28IkwTDYsxl_A"

bot = telebot.TeleBot(BOT_TOKEN, parse_mode=None)

# ── Firebase URL Patterns ───────────────────────────────────────────────────

FIREBASE_PATTERNS = [
    re.compile(rb'https://[a-zA-Z0-9_-]+\.firebaseio\.com(?:/[^\s"\'<>,\x00-\x1f]*)?'),
    re.compile(rb'https://[a-zA-Z0-9_-]+\.firebasedatabase\.app(?:/[^\s"\'<>,\x00-\x1f]*)?'),
    re.compile(rb'https://[a-zA-Z0-9_-]+\.asia-southeast1\.firebasedatabase\.app(?:/[^\s"\'<>,\x00-\x1f]*)?'),
    re.compile(rb'https://[a-zA-Z0-9_-]+\.us-central1\.firebasedatabase\.app(?:/[^\s"\'<>,\x00-\x1f]*)?'),
]

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0"})


def clean_url(url_bytes):
    try:
        url = url_bytes.decode('utf-8', errors='replace').strip()
        url = re.split(r'[\s"\'<>\x00-\x1f,]', url)[0]
        url = url.rstrip('.,;:')
        base = re.match(
            r'(https://[a-zA-Z0-9_-]+\.(?:firebaseio\.com|firebasedatabase\.app'
            r'|asia-southeast1\.firebasedatabase\.app|us-central1\.firebasedatabase\.app))',
            url
        )
        if base:
            return base.group(1)
        return url
    except Exception:
        return None


# ── Firebase Path Prober ────────────────────────────────────────────────────

ALL_USER_VARIANTS = ['All_User', 'All_Users', 'AllUser', 'all_user']
SKIP_KEYS = {
    'Verify_Device', 'Password', 'password', 'Admin_Password', 'admin_password',
    'panelAnalytics', 'logs', 'received_messages', 'sms_commands', 'tokens',
    'nextUserId', 'encoder', 'Card', 'Mother', 'forwardSms', 'guard',
}


def check_info_json(path):
    """Verify path has Info.json (what bot.py needs to fetch devices)."""
    try:
        r = SESSION.get(path + "Info.json?shallow=true", timeout=5)
        d = r.json()
        return isinstance(d, dict) and len(d) > 0 and 'error' not in d
    except Exception:
        return False


def probe_firebase_path(base_url):
    """
    Probe a Firebase base URL to find ALL valid All_User paths with Info.json.
    Returns all found paths, not just the first one.
    """
    result = {
        'base': base_url,
        'status': 'unknown',
        'root_keys': [],
        'full_path': None,
        'all_paths': [],
    }
    try:
        r = SESSION.get(base_url + "/.json?shallow=true", timeout=8)
        data = r.json()

        if isinstance(data, dict) and 'error' in data:
            result['status'] = 'deactivated'
            result['error'] = data['error']
            return result

        if not isinstance(data, dict):
            result['status'] = 'empty'
            return result

        result['status'] = 'active'
        result['root_keys'] = list(data.keys())
        check_keys = [k for k in data.keys() if k not in SKIP_KEYS]

        # Method A: root_key -> All_User variant -> verify Info.json
        def check_key_l1(key):
            found = []
            try:
                r2 = SESSION.get(f"{base_url}/{key}.json?shallow=true", timeout=6)
                sub = r2.json()
                if not isinstance(sub, dict):
                    return found
                for uk in ALL_USER_VARIANTS:
                    if uk in sub:
                        path = f"{base_url}/{key}/{uk}/"
                        if check_info_json(path):
                            found.append(path)
            except Exception:
                pass
            return found

        # Method B: 2-level deep — root_key/sub_key/All_User
        def check_key_l2(key):
            found = []
            try:
                r2 = SESSION.get(f"{base_url}/{key}.json?shallow=true", timeout=6)
                sub = r2.json()
                if not isinstance(sub, dict):
                    return found
                for sub_key in sub.keys():
                    if sub_key in SKIP_KEYS:
                        continue
                    try:
                        r3 = SESSION.get(
                            f"{base_url}/{key}/{sub_key}.json?shallow=true", timeout=5)
                        sub2 = r3.json()
                        if isinstance(sub2, dict):
                            for uk in ALL_USER_VARIANTS:
                                if uk in sub2:
                                    path = f"{base_url}/{key}/{sub_key}/{uk}/"
                                    if check_info_json(path):
                                        found.append(path)
                    except Exception:
                        pass
            except Exception:
                pass
            return found

        # Run Method A for all keys in parallel — collect ALL paths
        all_found = []
        with ThreadPoolExecutor(max_workers=12) as ex:
            futs = {ex.submit(check_key_l1, k): k for k in check_keys}
            for fut in as_completed(futs):
                paths = fut.result()
                all_found.extend(paths)

        # If Method A found nothing, try Method B (2-level deep)
        if not all_found:
            with ThreadPoolExecutor(max_workers=8) as ex:
                futs = {ex.submit(check_key_l2, k): k for k in check_keys}
                for fut in as_completed(futs):
                    paths = fut.result()
                    all_found.extend(paths)

        result['all_paths'] = sorted(set(all_found))
        if result['all_paths']:
            result['full_path'] = result['all_paths'][0]

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)

    return result


# ── APK Extraction Methods ──────────────────────────────────────────────────

def method_google_services(z):
    results = {}
    for name in z.namelist():
        if 'google-services.json' in name.lower():
            try:
                data = z.read(name)
                parsed = json.loads(data.decode('utf-8', errors='replace'))
                project_info = parsed.get('project_info', {})
                db_url = project_info.get('firebase_url', '')
                project_id = project_info.get('project_id', '')
                if db_url:
                    results['firebase_url'] = db_url
                if project_id:
                    results['project_id'] = project_id
                    results['inferred_url'] = f"https://{project_id}-default-rtdb.firebaseio.com"
            except Exception:
                pass
    return results


def method_strings_xml(z):
    found = set()
    for name in z.namelist():
        if 'strings.xml' in name.lower() or 'values' in name.lower():
            try:
                data = z.read(name)
                for pat in FIREBASE_PATTERNS:
                    for match in pat.findall(data):
                        u = clean_url(match)
                        if u:
                            found.add(u)
            except Exception:
                pass
    return found


def method_manifest(z):
    found = set()
    try:
        data = z.read('AndroidManifest.xml')
        for pat in FIREBASE_PATTERNS:
            for match in pat.findall(data):
                u = clean_url(match)
                if u:
                    found.add(u)
    except Exception:
        pass
    return found


def method_assets(z):
    found = set()
    for name in z.namelist():
        if name.startswith('assets/'):
            try:
                data = z.read(name)
                for pat in FIREBASE_PATTERNS:
                    for match in pat.findall(data):
                        u = clean_url(match)
                        if u:
                            found.add(u)
            except Exception:
                pass
    return found


def method_dex(z):
    found = set()
    for name in z.namelist():
        if name.endswith('.dex') or name.startswith('classes'):
            try:
                data = z.read(name)
                for pat in FIREBASE_PATTERNS:
                    for match in pat.findall(data):
                        u = clean_url(match)
                        if u:
                            found.add(u)
            except Exception:
                pass
    return found


def method_full_scan(z):
    found = set()
    for name in z.namelist():
        try:
            data = z.read(name)
            for pat in FIREBASE_PATTERNS:
                for match in pat.findall(data):
                    u = clean_url(match)
                    if u:
                        found.add(u)
        except Exception:
            pass
    return found


# ── Main Extractor ──────────────────────────────────────────────────────────

def extract_firebase_urls(apk_path):
    results = {
        'google_services': {},
        'strings_xml': set(),
        'manifest': set(),
        'assets': set(),
        'dex': set(),
        'full_scan': set(),
        'all_urls': set(),
        'probed': {},
    }

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            with ThreadPoolExecutor(max_workers=6) as ex:
                f1 = ex.submit(method_google_services, z)
                f2 = ex.submit(method_strings_xml, z)
                f3 = ex.submit(method_manifest, z)
                f4 = ex.submit(method_assets, z)
                f5 = ex.submit(method_dex, z)
                f6 = ex.submit(method_full_scan, z)

                results['google_services'] = f1.result()
                results['strings_xml']     = f2.result()
                results['manifest']        = f3.result()
                results['assets']          = f4.result()
                results['dex']             = f5.result()
                results['full_scan']       = f6.result()

        all_urls = set()
        gs = results['google_services']
        if gs.get('firebase_url'):
            all_urls.add(gs['firebase_url'])
        if gs.get('inferred_url'):
            all_urls.add(gs['inferred_url'])
        all_urls |= results['strings_xml']
        all_urls |= results['manifest']
        all_urls |= results['assets']
        all_urls |= results['dex']
        all_urls |= results['full_scan']

        results['all_urls'] = all_urls

        # Probe each URL live to find correct path
        if all_urls:
            with ThreadPoolExecutor(max_workers=min(len(all_urls), 6)) as ex:
                probe_futures = {ex.submit(probe_firebase_path, u): u for u in all_urls}
                for fut in as_completed(probe_futures):
                    url = probe_futures[fut]
                    results['probed'][url] = fut.result()

    except zipfile.BadZipFile:
        results['error'] = "Invalid APK / ZIP file"
    except Exception as e:
        results['error'] = str(e)

    return results


# ── Format Result ───────────────────────────────────────────────────────────

def format_result(apk_name, res):
    lines = [f"📦 <b>{apk_name}</b>\n"]

    if 'error' in res:
        lines.append(f"❌ Error: {res['error']}")
        return "\n".join(lines)

    all_urls = res.get('all_urls', set())
    gs = res.get('google_services', {})
    probed = res.get('probed', {})

    if not all_urls:
        lines.append("❌ No Firebase URL found in this APK.")
        return "\n".join(lines)

    if gs.get('project_id'):
        lines.append(f"🔑 Project ID: <code>{gs['project_id']}</code>\n")

    lines.append(f"🔥 Firebase URLs found: <b>{len(all_urls)}</b>\n")

    for i, url in enumerate(sorted(all_urls), 1):
        probe = probed.get(url, {})
        status = probe.get('status', 'unknown')

        if status == 'deactivated':
            status_icon = "🔴 Deactivated"
        elif status == 'active':
            status_icon = "🟢 Active"
        elif status == 'empty':
            status_icon = "🟡 Empty"
        elif status == 'error':
            status_icon = "⚠️ Error"
        else:
            status_icon = "❓ Unknown"

        lines.append(f"{i}. <code>{url}</code>")
        lines.append(f"   Status: {status_icon}")

        if probe.get('root_keys'):
            lines.append(f"   Root Keys: <code>{', '.join(probe['root_keys'])}</code>")

        all_paths = probe.get('all_paths', [])
        if all_paths:
            for p in all_paths:
                lines.append(f"   ✅ Path: <code>{p}</code>")
        elif status == 'active':
            lines.append(f"   ⚠️ All_User path not found (different structure)")

        method_tags = []
        if url == gs.get('firebase_url') or url == gs.get('inferred_url'):
            method_tags.append("google-services.json")
        if url in res.get('strings_xml', set()):
            method_tags.append("strings.xml")
        if url in res.get('manifest', set()):
            method_tags.append("AndroidManifest")
        if url in res.get('assets', set()):
            method_tags.append("assets")
        if url in res.get('dex', set()):
            method_tags.append("DEX")
        if method_tags:
            lines.append(f"   📍 Found in: {', '.join(method_tags)}")

        lines.append("")

    return "\n".join(lines)


# ── Telegram Handlers ───────────────────────────────────────────────────────

@bot.message_handler(commands=['start', 'help'])
def cmd_start(msg):
    text = (
        "👋 <b>APK Firebase URL Finder Bot</b>\n\n"
        "📤 Send me one or more APK files.\n"
        "🔍 Scanning methods:\n"
        "  • google-services.json\n"
        "  • strings.xml\n"
        "  • AndroidManifest.xml\n"
        "  • assets/ folder\n"
        "  • DEX/classes files\n"
        "  • Full APK scan\n\n"
        "🔗 Auto-probes Firebase to find:\n"
        "  • Active / Deactivated status\n"
        "  • Correct full path (e.g. /csc5/All_User/)\n\n"
        "✅ Supports multiple APKs at once!"
    )
    bot.send_message(msg.chat.id, text, parse_mode="HTML")


pending_apks = {}
pending_lock = threading.Lock()


def process_apk_queue(chat_id):
    import time
    time.sleep(2)

    with pending_lock:
        queue = pending_apks.pop(chat_id, [])

    if not queue:
        return

    status_msg = bot.send_message(
        chat_id,
        f"⏳ Processing <b>{len(queue)}</b> APK(s) + probing Firebase...",
        parse_mode="HTML"
    )

    def process_one(item):
        file_id, file_name = item
        try:
            file_info = bot.get_file(file_id)
            downloaded = bot.download_file(file_info.file_path)
            with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp:
                tmp.write(downloaded)
                tmp_path = tmp.name
            res = extract_firebase_urls(tmp_path)
            os.unlink(tmp_path)
            return file_name, res
        except Exception as e:
            return file_name, {'error': str(e)}

    with ThreadPoolExecutor(max_workers=min(len(queue), 4)) as ex:
        futures = {ex.submit(process_one, item): item for item in queue}
        results = []
        for fut in as_completed(futures):
            results.append(fut.result())

    try:
        bot.delete_message(chat_id, status_msg.message_id)
    except Exception:
        pass

    for file_name, res in results:
        text = format_result(file_name, res)
        probed = res.get('probed', {})
        for url, probe in probed.items():
            for path in probe.get('all_paths', []):
                print(f"[FOUND] {path}", flush=True)
                # Write to file so main process can read results
                try:
                    with open('/tmp/apk_found_urls.txt', 'a') as f:
                        f.write(path + '\n')
                except Exception:
                    pass
            if probe.get('status') == 'deactivated':
                print(f"[DEAD] {url}", flush=True)
        try:
            bot.send_message(chat_id, text, parse_mode="HTML")
        except Exception:
            bot.send_message(chat_id, text[:4096], parse_mode="HTML")


@bot.message_handler(content_types=['document'])
def handle_document(msg):
    chat_id = msg.chat.id
    doc = msg.document

    if not doc.file_name.lower().endswith('.apk'):
        bot.send_message(chat_id, "⚠️ Please send an APK file (.apk).", parse_mode="HTML")
        return

    with pending_lock:
        if chat_id not in pending_apks:
            pending_apks[chat_id] = []
            threading.Timer(2.0, process_apk_queue, args=[chat_id]).start()
        pending_apks[chat_id].append((doc.file_id, doc.file_name))

    bot.send_message(
        chat_id,
        f"✅ <b>{doc.file_name}</b> received. Processing soon...",
        parse_mode="HTML"
    )


@bot.message_handler(func=lambda m: True)
def fallback(msg):
    bot.send_message(
        msg.chat.id,
        "📤 Please send an APK file to extract Firebase URLs.",
        parse_mode="HTML"
    )


# ── Start ───────────────────────────────────────────────────────────────────
print("🔍 APK Firebase Finder Bot starting...")
bot.infinity_polling(timeout=30, long_polling_timeout=15)
