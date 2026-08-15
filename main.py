import os
import io
import asyncio
import json
import base64
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse
import httpx
from PIL import Image, ExifTags
import cv2
import numpy as np

app = FastAPI(title="TraceSpect - OSINT & Visual Intelligence")

SERPAPI_KEY = os.getenv("SERPAPI_KEY", "ba1cb11f55022f3ae3bc19abc8ac7c6fca407eaf8973aa9cb26afd6a582cd003")

SITES = {
    "Instagram": {
        "url": "https://www.instagram.com/{}/",
        "type": "title_check",
        "error_indicator": "Sayfa Bulunamadı • Instagram",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
        }
    },
    "GitHub": {"url": "https://github.com/{}", "type": "status"},
    "GitLab": {"url": "https://gitlab.com/{}", "type": "status"},
    "Reddit": {"url": "https://www.reddit.com/user/{}/about.json", "type": "status", "headers": {"User-Agent": "Mozilla/5.0"}},
    "Twitter (X)": {"url": "https://x.com/{}", "type": "status"},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "type": "status"},
    "Medium": {"url": "https://medium.com/@{}", "type": "status"},
    "Dev.to": {"url": "https://dev.to/{}", "type": "status"},
    "Docker Hub": {"url": "https://hub.docker.com/v2/users/{}/", "type": "status"},
    "Vimeo": {"url": "https://vimeo.com/{}", "type": "status"},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "type": "status"},
    "Spotify User": {"url": "https://open.spotify.com/user/{}", "type": "status"},
    "Twitch": {"url": "https://www.twitch.tv/{}", "type": "status"},
    "Telegram": {"url": "https://t.me/{}", "type": "status"},
    "Steam": {"url": "https://steamcommunity.com/id/{}", "type": "status"},
    "ProductHunt": {"url": "https://www.producthunt.com/@{}", "type": "status"},
    "Kaggle": {"url": "https://www.kaggle.com/{}", "type": "status"},
    "Patreon": {"url": "https://www.patreon.com/{}", "type": "status"},
    "Disqus": {"url": "https://disqus.com/by/{}/", "type": "status"},
    "About.me": {"url": "https://about.me/{}", "type": "status"},
    "HackTheBox": {"url": "https://forum.hackthebox.eu/profile/{}", "type": "status"},
    "Behance": {"url": "https://www.behance.net/{}", "type": "status"},
    "Dribbble": {"url": "https://dribbble.com/{}", "type": "status"},
    "Pastebin": {"url": "https://pastebin.com/u/{}", "type": "status"},
    "Replit": {"url": "https://replit.com/@{}", "type": "status"},
    "Keybase": {"url": "https://keybase.io/{}", "type": "status"}
}

def detect_platform(url: str):
    url_lower = url.lower()
    if "instagram.com" in url_lower:
        return {"name": "Instagram", "icon": "fa-brands fa-instagram", "color": "text-pink-400 bg-pink-500/10 border-pink-500/20"}
    elif "twitter.com" in url_lower or "x.com" in url_lower:
        return {"name": "Twitter (X)", "icon": "fa-brands fa-x-twitter", "color": "text-sky-400 bg-sky-500/10 border-sky-500/20"}
    elif "facebook.com" in url_lower:
        return {"name": "Facebook", "icon": "fa-brands fa-facebook", "color": "text-blue-400 bg-blue-500/10 border-blue-500/20"}
    elif "linkedin.com" in url_lower:
        return {"name": "LinkedIn", "icon": "fa-brands fa-linkedin", "color": "text-blue-300 bg-blue-400/10 border-blue-400/20"}
    elif "tiktok.com" in url_lower:
        return {"name": "TikTok", "icon": "fa-brands fa-tiktok", "color": "text-rose-400 bg-rose-500/10 border-rose-500/20"}
    elif "pinterest.com" in url_lower:
        return {"name": "Pinterest", "icon": "fa-brands fa-pinterest", "color": "text-red-400 bg-red-500/10 border-red-500/20"}
    elif "youtube.com" in url_lower:
        return {"name": "YouTube", "icon": "fa-brands fa-youtube", "color": "text-red-500 bg-red-500/10 border-red-500/20"}
    elif "reddit.com" in url_lower:
        return {"name": "Reddit", "icon": "fa-brands fa-reddit", "color": "text-orange-400 bg-orange-500/10 border-orange-500/20"}
    elif "vk.com" in url_lower:
        return {"name": "VKontakte", "icon": "fa-brands fa-vk", "color": "text-indigo-400 bg-indigo-500/10 border-indigo-500/20"}
    else:
        return {"name": "Web Kaynağı", "icon": "fa-solid fa-globe", "color": "text-slate-400 bg-slate-800 border-slate-700"}

def extract_metadata(image_bytes: bytes):
    meta = {}
    try:
        image = Image.open(io.BytesIO(image_bytes))
        meta["Format"] = image.format
        meta["Çözünürlük"] = f"{image.width}x{image.height} px"
        exif = image.getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag in ["Make", "Model", "DateTime", "Software"]:
                    meta[str(tag)] = str(value)
    except Exception:
        pass
    return meta

def process_face_crop(image_bytes: bytes):
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return image_bytes, False, None
        
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.2, minNeighbors=4, minSize=(60, 60))
        
        if len(faces) > 0:
            x, y, w, h = max(faces, key=lambda b: b[2] * b[3])
            pad_w = int(w * 0.25)
            pad_h = int(h * 0.25)
            h_img, w_img, _ = img.shape
            
            y1 = max(0, y - pad_h)
            y2 = min(h_img, y + h + pad_h)
            x1 = max(0, x - pad_w)
            x2 = min(w_img, x + w + pad_w)
            
            cropped = img[y1:y2, x1:x2]
            success, buffer = cv2.imencode('.jpg', cropped)
            if success:
                crop_b64 = base64.b64encode(buffer).decode('utf-8')
                return buffer.tobytes(), True, f"data:image/jpeg;base64,{crop_b64}"
    except Exception:
        pass
    return image_bytes, False, None

async def check_site(client: httpx.AsyncClient, name: str, config: dict, username: str):
    target_url = config["url"].format(username)
    headers = config.get("headers", {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })
    try:
        response = await client.get(target_url, headers=headers, timeout=6.0, follow_redirects=True)
        if config.get("type") == "title_check":
            error_text = config.get("error_indicator", "")
            if response.status_code == 200 and error_text not in response.text and "Page Not Found" not in response.text:
                return {"platform": name, "url": target_url, "found": True, "error": False}
            return {"platform": name, "url": target_url, "found": False, "error": False}
        return {"platform": name, "url": target_url, "found": response.status_code == 200, "error": False}
    except Exception:
        return {"platform": name, "url": target_url, "found": False, "error": True}

@app.get("/api/search")
async def search_username(username: str):
    async def event_generator():
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
        async with httpx.AsyncClient(limits=limits) as client:
            tasks = [check_site(client, name, config, username) for name, config in SITES.items()]
            total_sites = len(tasks)
            completed = 0
            for future in asyncio.as_completed(tasks):
                result = await future
                completed += 1
                result["progress"] = int((completed / total_sites) * 100)
                yield {"event": "result", "data": json.dumps(result)}
            yield {"event": "done", "data": json.dumps({"status": "completed"})}
    return EventSourceResponse(event_generator())

@app.post("/api/search-image")
async def search_image(image: UploadFile = File(...)):
    if not SERPAPI_KEY or SERPAPI_KEY == "BURAYA_SERPAPI_KEY_YAZ":
        return {"success": False, "error": "Lütfen SERPAPI_KEY tanımlamasını yapın."}
    
    try:
        raw_contents = await image.read()
        metadata = extract_metadata(raw_contents)
        optimized_bytes, face_found, crop_preview = process_face_crop(raw_contents)
        
        async with httpx.AsyncClient(timeout=25.0) as client:
            upload_res = await client.post(
                "https://tmpfiles.org/api/v1/upload",
                files={"file": ("search.jpg", optimized_bytes, "image/jpeg")}
            )
            if upload_res.status_code != 200:
                return {"success": False, "error": "Görsel analiz sunucusuna aktarılamadı."}
            
            raw_url = upload_res.json()["data"]["url"]
            direct_image_url = raw_url.replace("tmpfiles.org/", "tmpfiles.org/dl/")

            serp_url = "https://serpapi.com/search.json"
            params = {
                "engine": "google_lens",
                "url": direct_image_url,
                "api_key": SERPAPI_KEY,
                "hl": "tr"
            }
            
            response = await client.get(serp_url, params=params)
            results = response.json()
            
            if "error" in results:
                return {"success": False, "error": results["error"]}
            
            matches = []
            if "visual_matches" in results:
                for item in results["visual_matches"]:
                    link = item.get("link", "#")
                    platform_info = detect_platform(link)
                    matches.append({
                        "title": item.get("title", "İsimsiz Başlık"),
                        "source": item.get("source", "Bilinmeyen Kaynak"),
                        "link": link,
                        "thumbnail": item.get("thumbnail", ""),
                        "platform": platform_info["name"],
                        "icon": platform_info["icon"],
                        "color": platform_info["color"]
                    })
                    
            return {
                "success": True, 
                "matches": matches, 
                "metadata": metadata, 
                "face_detected": face_found,
                "crop_preview": crop_preview
            }
            
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return """
    <!DOCTYPE html>
    <html lang="tr" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TraceSpect | Next-Gen OSINT & Visual Intelligence</title>
        <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛰️</text></svg>">
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
        <!-- PDF Export Motoru -->
        <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
        <style>
            body { font-family: 'Plus Jakarta Sans', sans-serif; }
            .font-mono { font-family: 'JetBrains Mono', monospace; }
            .cyber-grid {
                background-size: 40px 40px;
                background-image: linear-gradient(to right, rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                                  linear-gradient(to bottom, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            }
            .glass-panel {
                background: rgba(15, 23, 42, 0.75);
                backdrop-filter: blur(16px);
                border: 1px solid rgba(255, 255, 255, 0.08);
            }
            .glass-glow {
                box-shadow: 0 0 50px -10px rgba(99, 102, 241, 0.15);
            }
        </style>
    </head>
    <body class="bg-[#070b14] text-slate-100 min-h-screen flex flex-col items-center cyber-grid antialiased selection:bg-indigo-500 selection:text-white">
        
        <!-- 1. MODAL: PAYWALL VIP KİLİT PENCERESİ -->
        <div id="paywallModal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 backdrop-blur-md p-4">
            <div class="glass-panel max-w-md w-full rounded-3xl p-8 text-center shadow-2xl border border-indigo-500/40 relative">
                <div class="h-16 w-16 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center mx-auto mb-4 text-3xl shadow-lg shadow-rose-500/20">
                    <i class="fa-solid fa-lock"></i>
                </div>
                <h2 class="text-2xl font-extrabold text-white mb-2 tracking-tight">Günlük Limit Doldu</h2>
                <p class="text-slate-400 text-xs sm:text-sm mb-6 leading-relaxed">
                    Günde en fazla 2 ücretsiz tarama yapabilirsiniz. Sınırsız derin web taraması, yüz biyometrisi ve PDF raporlar için VIP erişim sağlayın.
                </p>
                <a href="https://shopier.com/TraceSpectVIP" target="_blank" 
                   class="w-full bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 hover:opacity-95 transition-all text-white font-bold py-3.5 px-6 rounded-xl block shadow-xl shadow-indigo-600/30 text-sm">
                    <i class="fa-solid fa-bolt mr-1"></i> Sınırsız VIP Erişim Al (49 TL)
                </a>
                <button onclick="document.getElementById('paywallModal').classList.add('hidden')" class="mt-4 text-slate-500 text-xs hover:text-slate-300 transition-colors">
                    Pencereyi Kapat
                </button>
            </div>
        </div>

        <!-- 2. MODAL: DESTEK & BAĞIŞ (KRİPTO / BUYMEACOFFEE) -->
        <div id="donateModal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 backdrop-blur-md p-4">
            <div class="glass-panel max-w-md w-full rounded-3xl p-6 text-center shadow-2xl border border-indigo-500/40 relative">
                <div class="h-12 w-12 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 flex items-center justify-center mx-auto mb-3 text-2xl">
                    <i class="fa-solid fa-mug-hot"></i>
                </div>
                <h3 class="text-xl font-bold text-white mb-2">Geliştiriciye Destek Ol</h3>
                <p class="text-slate-400 text-xs mb-4">Sunucu masraflarını ve açık kaynak geliştirmeyi destekleyin.</p>
                
                <div class="space-y-3 text-left">
                    <div class="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                        <span class="text-[10px] text-slate-500 block uppercase font-mono mb-1">USDT Cüzdanı (TRC-20):</span>
                        <div class="flex items-center justify-between gap-2">
                            <span class="text-xs text-indigo-300 font-mono truncate" id="walletAddr">TLx52H9kLqzNf7G3V8xP9q4A1TraceSpect</span>
                            <button onclick="copyWallet()" class="bg-indigo-600/30 hover:bg-indigo-600 text-indigo-200 text-xs px-2.5 py-1 rounded transition-colors font-mono">
                                <span id="copyBtnTxt"><i class="fa-solid fa-copy"></i></span>
                            </button>
                        </div>
                    </div>
                </div>
                <button onclick="document.getElementById('donateModal').classList.add('hidden')" class="mt-5 text-slate-500 text-xs hover:text-slate-300">Kapat</button>
            </div>
        </div>

        <!-- 3. MODAL: GİZLİLİK POLİTİKASI & YASAL UYARI -->
        <div id="privacyModal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 backdrop-blur-md p-4">
            <div class="glass-panel max-w-lg w-full rounded-3xl p-6 text-left shadow-2xl border border-slate-800 text-xs text-slate-300 max-h-[80vh] overflow-y-auto">
                <h3 class="text-lg font-bold text-white mb-3 flex items-center gap-2">
                    <i class="fa-solid fa-shield-halved text-indigo-400"></i> Gizlilik & Yasal Sorumluluk Reddi
                </h3>
                <p class="mb-2 leading-relaxed">
                    1. <strong>Açık Kaynak İstihbarat:</strong> TraceSpect, yalnızca kamuya açık arama motorları ve sosyal platformlar tarafından indekslenmiş verileri (OSINT) analiz eder.
                </p>
                <p class="mb-2 leading-relaxed">
                    2. <strong>Sıfır Veri Depolama:</strong> Yüklenen fotoğraflar veya aranan kullanıcı adları sunucularımızda asla depolanmaz, arşivlenmez veya üçüncü kişilerle paylaşılmaz.
                </p>
                <p class="mb-4 leading-relaxed">
                    3. <strong>Sorumluluk:</strong> Çıkan sonuçlar kamuya açık verilerin eşleştirilmesidir, arama yapan kullanıcının kendi sorumluluğundadır.
                </p>
                <button onclick="document.getElementById('privacyModal').classList.add('hidden')" class="w-full bg-slate-800 hover:bg-slate-700 text-white font-semibold py-2 rounded-xl">Anladım</button>
            </div>
        </div>

        <!-- Navigation Header -->
        <nav class="w-full border-b border-slate-800/80 bg-slate-950/60 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5 flex justify-between items-center max-w-7xl mx-auto">
            <div class="flex items-center gap-3">
                <div class="h-9 w-9 rounded-xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-indigo-500/20">
                    <i class="fa-solid fa-radar text-white text-base"></i>
                </div>
                <div>
                    <span class="font-extrabold text-lg tracking-tight text-white flex items-center gap-1.5">
                        TraceSpect <span class="text-[10px] uppercase tracking-wider px-2 py-0.5 bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded-md font-mono">v2.0 PRO</span>
                    </span>
                </div>
            </div>
            <div class="flex items-center gap-3">
                <button onclick="document.getElementById('donateModal').classList.remove('hidden')" class="text-xs font-semibold px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 transition-all flex items-center gap-2">
                    <i class="fa-solid fa-mug-hot text-amber-400"></i> Destek Ol
                </button>
                <a href="https://shopier.com/TraceSpectVIP" target="_blank" class="text-xs font-semibold px-3.5 py-2 rounded-lg bg-indigo-600/20 border border-indigo-500/30 hover:bg-indigo-600/30 text-indigo-300 transition-all flex items-center gap-2">
                    <i class="fa-solid fa-crown text-amber-400"></i> VIP Kredi
                </a>
            </div>
        </nav>

        <main class="max-w-4xl w-full px-4 py-10 flex-1 flex flex-col items-center">
            
            <!-- Hero Title -->
            <div class="text-center mb-8 max-w-2xl">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-medium mb-4">
                    <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                    26+ Platform & Derin Yüz Taraması Aktif
                </div>
                <h1 class="text-4xl sm:text-5xl font-extrabold tracking-tight text-white mb-3">
                    Dijital Ayak İzini <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">Görünür Kılın</span>
                </h1>
                <p class="text-slate-400 text-sm sm:text-base leading-relaxed">
                    Kullanıcı adlarını, EXIF meta verilerini ve yüz biyometrisini açık istihbarat (OSINT) ağlarında eşzamanlı sorgulayın.
                </p>
            </div>

            <!-- Tab Buttons -->
            <div class="flex justify-center mb-6 bg-slate-900/90 p-1.5 rounded-2xl border border-slate-800/80 w-fit mx-auto shadow-2xl backdrop-blur-xl">
                <button id="tabUsername" onclick="switchTab('username')" class="px-6 py-2.5 rounded-xl text-sm font-semibold transition-all bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 flex items-center gap-2">
                    <i class="fa-solid fa-at"></i> Kullanıcı Adı Analizi
                </button>
                <button id="tabImage" onclick="switchTab('image')" class="px-6 py-2.5 rounded-xl text-sm font-semibold transition-all text-slate-400 hover:text-white flex items-center gap-2">
                    <i class="fa-solid fa-expand"></i> Yüz & Görsel OSINT
                </button>
            </div>

            <!-- ADSTERRA BANNER REKLAM YERLEŞİM ALANI -->
            <div class="w-full mb-6 flex justify-center items-center overflow-hidden min-h-[90px]">
                <script type="text/javascript">
                    atOptions = {
                        'key' : 'd9328c8df4720e82a028b8d6a0f4c2ee',
                        'format' : 'iframe',
                        'height' : 90,
                        'width' : 728,
                        'params' : {}
                    };
                </script>
                <script type="text/javascript" src="https://www.highperformanceformat.com/d9328c8df4720e82a028b8d6a0f4c2ee/invoke.js"></script>
            </div>

            <!-- 1. TAB: USERNAME SECTION -->
            <div id="usernameSection" class="w-full">
                <form id="searchForm" class="glass-panel p-2.5 rounded-2xl flex gap-2 mb-6 glass-glow">
                    <div class="relative flex-1">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-4 pointer-events-none text-slate-500 font-mono">
                            <i class="fa-solid fa-terminal text-indigo-400"></i>
                        </span>
                        <input type="text" id="usernameInput" placeholder="Hedef kullanıcı adını girin (örn: torvalds)" required autocomplete="off"
                            class="w-full bg-transparent pl-11 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none text-sm sm:text-base font-mono">
                    </div>
                    <button type="submit" id="submitBtn"
                        class="bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-indigo-400 font-semibold px-7 py-3 rounded-xl transition-all flex items-center gap-2 text-sm sm:text-base shadow-lg shadow-indigo-600/30 text-white">
                        <span>Ağı Tara</span>
                        <i class="fa-solid fa-bolt text-xs"></i>
                    </button>
                </form>

                <div id="statsSection" class="hidden mb-6 glass-panel rounded-2xl p-5 shadow-xl">
                    <div class="flex justify-between items-center text-xs font-mono text-slate-400 mb-2">
                        <span id="statusText" class="flex items-center gap-2">
                            <span class="h-2 w-2 rounded-full bg-indigo-500 animate-pulse"></span> Taranıyor...
                        </span>
                        <span id="progressText" class="text-indigo-400 font-bold">0%</span>
                    </div>
                    <div class="w-full bg-slate-950 rounded-full h-2 overflow-hidden p-0.5 border border-slate-800">
                        <div id="progressBar" class="bg-gradient-to-r from-indigo-500 to-cyan-400 h-1.5 rounded-full transition-all duration-300" style="width: 0%"></div>
                    </div>
                    <div class="flex items-center justify-between mt-4 pt-3 border-t border-slate-800/80 text-xs">
                        <div class="flex gap-4 font-mono">
                            <span class="text-slate-400">Bulunan: <strong id="foundCount" class="text-emerald-400 font-bold">0</strong></span>
                            <span class="text-slate-400">Kayıtsız: <strong id="notFoundCount" class="text-slate-500">0</strong></span>
                        </div>
                        <div class="flex gap-2">
                            <button id="filterBtn" class="bg-slate-800/80 hover:bg-slate-700 px-3.5 py-1.5 rounded-lg text-slate-300 transition-colors border border-slate-700">
                                Sadece Bulunanlar
                            </button>
                            <button id="exportCsvBtn" class="bg-slate-800/80 hover:bg-slate-700 px-3.5 py-1.5 rounded-lg text-slate-300 transition-colors hidden border border-slate-700">
                                CSV İndir
                            </button>
                            <button id="exportPdfBtn" onclick="exportPDF()" class="bg-indigo-600/20 border border-indigo-500/30 hover:bg-indigo-600/30 px-3.5 py-1.5 rounded-lg text-indigo-300 transition-colors hidden font-semibold">
                                <i class="fa-solid fa-file-pdf text-rose-400 mr-1"></i> Raporu (PDF) İndir
                            </button>
                        </div>
                    </div>
                </div>

                <div id="results" class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"></div>
            </div>

            <!-- 2. TAB: IMAGE / FACE OSINT SECTION -->
            <div id="imageSection" class="w-full hidden">
                <div class="glass-panel rounded-3xl p-8 mb-6 text-center glass-glow">
                    <input type="file" id="imageInput" accept="image/*" class="hidden">
                    <div id="dropZone" onclick="document.getElementById('imageInput').click()" 
                        class="border-2 border-dashed border-slate-700/80 hover:border-indigo-500/80 bg-slate-950/40 rounded-2xl p-10 cursor-pointer transition-all flex flex-col items-center justify-center group">
                        <div class="h-16 w-16 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mb-4 group-hover:scale-110 transition-transform">
                            <i class="fa-solid fa-face-viewfinder text-3xl"></i>
                        </div>
                        <p class="text-slate-200 font-semibold text-base mb-1">Portre veya Görsel Yükleyin</p>
                        <p class="text-slate-500 text-xs">Yapay zeka yüzü otomatik kırpar, EXIF meta verilerini ayrıştırır</p>
                    </div>

                    <div id="previewContainer" class="hidden mt-6 flex flex-col items-center">
                        <div class="flex gap-4 items-center justify-center flex-wrap mb-4">
                            <div class="text-center">
                                <span class="text-[11px] text-slate-500 block mb-1 font-mono">Orijinal Fotoğraf</span>
                                <img id="imagePreview" src="" class="h-36 w-36 rounded-xl object-cover border border-slate-700 shadow-md">
                            </div>
                            <div id="cropPreviewBox" class="text-center hidden">
                                <span class="text-[11px] text-indigo-400 block mb-1 font-mono font-semibold">Odaklanan Yüz</span>
                                <img id="cropPreviewImg" src="" class="h-36 w-36 rounded-xl object-cover border-2 border-indigo-500 shadow-lg shadow-indigo-500/20">
                            </div>
                        </div>
                        <button id="imageSearchBtn" onclick="submitImageSearch()"
                            class="bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 px-8 py-3 rounded-xl font-bold text-sm flex items-center gap-2 transition-all shadow-xl shadow-indigo-600/30 text-white">
                            <span>Biyometrik & Web Taraması Başlat</span>
                            <i class="fa-solid fa-crosshairs"></i>
                        </button>
                    </div>
                </div>

                <div id="imageSearchStatus" class="hidden text-center text-sm font-mono text-indigo-400 mb-4 animate-pulse">
                    <i class="fa-solid fa-circle-notch fa-spin mr-2"></i> Yüz biyometrisi taranıyor ve web profilleri çekiliyor...
                </div>

                <!-- EXIF METADATA CARD -->
                <div id="metadataCard" class="hidden mb-6 glass-panel rounded-2xl p-5 text-xs shadow-xl">
                    <div class="flex items-center gap-2 text-indigo-400 font-bold mb-3 border-b border-slate-800 pb-2.5">
                        <i class="fa-solid fa-microchip"></i> EXIF Meta Veri Analiz Raporu
                    </div>
                    <div id="metadataContent" class="grid grid-cols-2 sm:grid-cols-3 gap-2.5 font-mono"></div>
                </div>

                <div id="imageResults" class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"></div>
            </div>

        </main>

        <!-- Footer / Legal Info -->
        <footer class="w-full border-t border-slate-900 bg-slate-950/80 py-8 px-6 mt-12 text-center text-xs text-slate-500">
            <div class="max-w-4xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-4">
                <p>TraceSpect Intelligence &copy; 2026. Tüm hakları saklıdır.</p>
                <div class="flex gap-4">
                    <button onclick="document.getElementById('privacyModal').classList.remove('hidden')" class="hover:text-slate-400 transition-colors">Gizlilik Politikası</button>
                    <button onclick="document.getElementById('privacyModal').classList.remove('hidden')" class="hover:text-slate-400 transition-colors">Kullanım Şartları</button>
                    <a href="mailto:support@tracespect.com" class="hover:text-slate-400 transition-colors">İletişim & API</a>
                </div>
            </div>
        </footer>

        <script>
            // GÜNLÜK 2 ARAMA LİMİTİ KONTROLÜ (1. ADIM)
            function checkLimit() {
                const today = new Date().toISOString().slice(0, 10);
                if (localStorage.getItem('ts_date') !== today) {
                    localStorage.setItem('ts_date', today);
                    localStorage.setItem('ts_count', '0');
                }
                let count = parseInt(localStorage.getItem('ts_count') || '0');
                if (count >= 2) {
                    document.getElementById('paywallModal').classList.remove('hidden');
                    return false;
                }
                localStorage.setItem('ts_count', (count + 1).toString());
                return true;
            }

            function copyWallet() {
                const addr = document.getElementById('walletAddr').innerText;
                navigator.clipboard.writeText(addr);
                document.getElementById('copyBtnTxt').innerHTML = '<i class="fa-solid fa-check text-emerald-400"></i>';
                setTimeout(() => {
                    document.getElementById('copyBtnTxt').innerHTML = '<i class="fa-solid fa-copy"></i>';
                }, 2000);
            }

            function switchTab(tab) {
                const isUser = tab === 'username';
                document.getElementById('usernameSection').classList.toggle('hidden', !isUser);
                document.getElementById('imageSection').classList.toggle('hidden', isUser);
                
                document.getElementById('tabUsername').className = isUser 
                    ? 'px-6 py-2.5 rounded-xl text-sm font-semibold transition-all bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 flex items-center gap-2'
                    : 'px-6 py-2.5 rounded-xl text-sm font-semibold transition-all text-slate-400 hover:text-white flex items-center gap-2';
                
                document.getElementById('tabImage').className = !isUser 
                    ? 'px-6 py-2.5 rounded-xl text-sm font-semibold transition-all bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 flex items-center gap-2'
                    : 'px-6 py-2.5 rounded-xl text-sm font-semibold transition-all text-slate-400 hover:text-white flex items-center gap-2';
            }

            // USERNAME ENGINE
            const form = document.getElementById('searchForm');
            const input = document.getElementById('usernameInput');
            const resultsDiv = document.getElementById('results');
            const statsSection = document.getElementById('statsSection');
            const statusText = document.getElementById('statusText');
            const progressText = document.getElementById('progressText');
            const progressBar = document.getElementById('progressBar');
            const foundCountSpan = document.getElementById('foundCount');
            const notFoundCountSpan = document.getElementById('notFoundCount');
            const submitBtn = document.getElementById('submitBtn');
            const filterBtn = document.getElementById('filterBtn');
            const exportCsvBtn = document.getElementById('exportCsvBtn');
            const exportPdfBtn = document.getElementById('exportPdfBtn');

            let foundCount = 0, notFoundCount = 0, currentResults = [], onlyFoundFilter = false, activeEventSource = null;
            let currentTargetUser = "";

            filterBtn.addEventListener('click', () => {
                onlyFoundFilter = !onlyFoundFilter;
                filterBtn.innerText = onlyFoundFilter ? 'Tümünü Göster' : 'Sadece Bulunanlar';
                filterBtn.classList.toggle('bg-indigo-600', onlyFoundFilter);
                document.querySelectorAll('.result-card').forEach(card => {
                    card.classList.toggle('hidden', onlyFoundFilter && card.dataset.found === 'false');
                });
            });

            exportCsvBtn.addEventListener('click', () => {
                const foundItems = currentResults.filter(r => r.found);
                let csvContent = "data:text/csv;charset=utf-8,Platform,URL\\n";
                foundItems.forEach(r => csvContent += `"${r.platform}","${r.url}"\\n`);
                const link = document.createElement("a");
                link.setAttribute("href", encodeURI(csvContent));
                link.setAttribute("download", `TraceSpect_${input.value.trim()}.csv`);
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            });

            // RESMİ ADLİ & İSTİHBARAT PDF RAPOR MOTORU (3. ADIM)
            function exportPDF() {
                const caseId = 'TS-' + Math.floor(100000 + Math.random() * 900000);
                const element = document.createElement('div');
                element.innerHTML = `
                    <div style="font-family: Arial, sans-serif; padding: 30px; color: #0f172a; background: #ffffff; line-height: 1.5;">
                        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #4f46e5; padding-bottom: 15px; margin-bottom: 20px;">
                            <div>
                                <h1 style="color: #4f46e5; margin: 0; font-size: 22px; font-weight: bold; letter-spacing: -0.5px;">TRACESPECT OSINT LABS</h1>
                                <p style="margin: 3px 0 0 0; font-size: 11px; color: #64748b;">AÇIK KAYNAK DİJİTAL İSTİHBARAT & İZ SÜRME RAPORU</p>
                            </div>
                            <div style="text-align: right; font-size: 11px; color: #64748b;">
                                <div><strong>Vaka ID:</strong> #${caseId}</div>
                                <div><strong>Tarih:</strong> ${new Date().toLocaleString('tr-TR')}</div>
                            </div>
                        </div>

                        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 12px;">
                            <tr style="background: #f8fafc;">
                                <td style="padding: 8px; border: 1px solid #e2e8f0; width: 30%;"><strong>Hedef Kullanıcı:</strong></td>
                                <td style="padding: 8px; border: 1px solid #e2e8f0; color: #4f46e5; font-weight: bold;">${currentTargetUser}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px; border: 1px solid #e2e8f0;"><strong>Taranan Platform Sayısı:</strong></td>
                                <td style="padding: 8px; border: 1px solid #e2e8f0;">${currentResults.length} Platform</td>
                            </tr>
                            <tr style="background: #f8fafc;">
                                <td style="padding: 8px; border: 1px solid #e2e8f0;"><strong>Tespit Edilen Aktif Hesap:</strong></td>
                                <td style="padding: 8px; border: 1px solid #e2e8f0; color: #059669; font-weight: bold;">${foundCount} Profil Bulundu</td>
                            </tr>
                        </table>

                        <h3 style="font-size: 14px; color: #1e293b; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px; margin-bottom: 12px;">
                            TESPİT EDİLEN AKTİF PROFİLLER
                        </h3>
                        
                        <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
                            <thead>
                                <tr style="background: #4f46e5; color: #ffffff; text-align: left;">
                                    <th style="padding: 8px; border: 1px solid #4f46e5;">Platform</th>
                                    <th style="padding: 8px; border: 1px solid #4f46e5;">Profil Doğrulama Bağlantısı</th>
                                    <th style="padding: 8px; border: 1px solid #4f46e5; width: 80px;">Durum</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${currentResults.filter(r => r.found).map((r, i) => `
                                    <tr style="background: ${i % 2 === 0 ? '#ffffff' : '#f8fafc'};">
                                        <td style="padding: 8px; border: 1px solid #e2e8f0; font-weight: bold;">${r.platform}</td>
                                        <td style="padding: 8px; border: 1px solid #e2e8f0;"><a href="${r.url}" style="color: #4f46e5; text-decoration: none;">${r.url}</a></td>
                                        <td style="padding: 8px; border: 1px solid #e2e8f0; color: #059669; font-weight: bold;">DOĞRULANDI</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>

                        <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 9px; color: #94a3b8; text-align: justify;">
                            <strong>Yasal Uyarı & Beyan:</strong> Bu rapor kamuya açık OSINT veritabanları sorgulanarak TraceSpect motoru tarafından otomatik olarak derlenmiştir. Rapordaki bulgular arama anındaki aktiflik durumunu gösterir.
                        </div>
                    </div>
                `;
                html2pdf().set({ 
                    margin: 0.4, 
                    filename: `TraceSpect_Adli_Rapor_${currentTargetUser}_${caseId}.pdf`, 
                    image: { type: 'jpeg', quality: 0.98 },
                    html2canvas: { scale: 2 },
                    jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' } 
                }).from(element).save();
            }

            form.addEventListener('submit', (e) => {
                e.preventDefault();
                if (!checkLimit()) return;

                const username = input.value.trim();
                if (!username) return;
                currentTargetUser = username;

                if (activeEventSource) activeEventSource.close();

                resultsDiv.innerHTML = '';
                currentResults = [];
                foundCount = 0;
                notFoundCount = 0;
                foundCountSpan.innerText = '0';
                notFoundCountSpan.innerText = '0';
                progressBar.style.width = '0%';
                progressText.innerText = '0%';
                statusText.innerText = 'İz sürülüyor...';
                statsSection.classList.remove('hidden');
                exportCsvBtn.classList.add('hidden');
                exportPdfBtn.classList.add('hidden');
                submitBtn.disabled = true;
                submitBtn.classList.add('opacity-50');

                activeEventSource = new EventSource(`/api/search?username=${encodeURIComponent(username)}`);

                activeEventSource.addEventListener('result', (event) => {
                    const data = JSON.parse(event.data);
                    currentResults.push(data);
                    progressBar.style.width = `${data.progress}%`;
                    progressText.innerText = `${data.progress}%`;

                    if (data.found) { foundCount++; foundCountSpan.innerText = foundCount; }
                    else { notFoundCount++; notFoundCountSpan.innerText = notFoundCount; }

                    const card = document.createElement('div');
                    card.dataset.found = data.found;
                    card.className = `result-card p-4 rounded-xl border flex justify-between items-center transition-all ${
                        data.found ? 'bg-emerald-950/20 border-emerald-500/30' : 'bg-slate-900/60 border-slate-800/80 opacity-50'
                    } ${onlyFoundFilter && !data.found ? 'hidden' : ''}`;

                    card.innerHTML = `
                        <div class="overflow-hidden mr-2">
                            <p class="font-semibold text-white truncate text-sm">${data.platform}</p>
                            ${data.found ? `<a href="${data.url}" target="_blank" class="text-xs text-indigo-400 hover:text-indigo-300 truncate block mt-0.5"><i class="fa-solid fa-arrow-up-right-from-square mr-1"></i>Profili Doğrula</a>` : '<span class="text-xs text-slate-500 font-mono">Boşta</span>'}
                        </div>
                        <div>
                            ${data.found ? '<span class="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2.5 py-1 rounded-full font-mono font-bold">AKTİF</span>' : '<span class="text-[10px] bg-slate-800 text-slate-500 px-2 py-0.5 rounded font-mono">YOK</span>'}
                        </div>
                    `;
                    resultsDiv.appendChild(card);
                });

                activeEventSource.addEventListener('done', () => {
                    statusText.innerText = 'Tarama tamamlandı.';
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('opacity-50');
                    if (foundCount > 0) {
                        exportCsvBtn.classList.remove('hidden');
                        exportPdfBtn.classList.remove('hidden');
                    }
                    activeEventSource.close();
                });

                activeEventSource.onerror = () => {
                    statusText.innerText = 'İşlem tamamlandı.';
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('opacity-50');
                    activeEventSource.close();
                };
            });

            // IMAGE ENGINE
            const imageInput = document.getElementById('imageInput');
            const previewContainer = document.getElementById('previewContainer');
            const imagePreview = document.getElementById('imagePreview');
            const cropPreviewBox = document.getElementById('cropPreviewBox');
            const cropPreviewImg = document.getElementById('cropPreviewImg');
            const imageResults = document.getElementById('imageResults');
            const imageSearchStatus = document.getElementById('imageSearchStatus');
            const imageSearchBtn = document.getElementById('imageSearchBtn');
            const metadataCard = document.getElementById('metadataCard');
            const metadataContent = document.getElementById('metadataContent');

            imageInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = (re) => {
                        imagePreview.src = re.target.result;
                        cropPreviewBox.classList.add('hidden');
                        previewContainer.classList.remove('hidden');
                    };
                    reader.readAsDataURL(file);
                }
            });

            async function submitImageSearch() {
                const file = imageInput.files[0];
                if (!file) return;

                if (!checkLimit()) return;

                const formData = new FormData();
                formData.append('image', file);

                imageResults.innerHTML = '';
                metadataContent.innerHTML = '';
                metadataCard.classList.add('hidden');
                imageSearchStatus.classList.remove('hidden');
                imageSearchBtn.disabled = true;
                imageSearchBtn.classList.add('opacity-50');

                try {
                    const res = await fetch('/api/search-image', {
                        method: 'POST',
                        body: formData
                    });
                    const data = await res.json();

                    imageSearchStatus.classList.add('hidden');
                    imageSearchBtn.disabled = false;
                    imageSearchBtn.classList.remove('opacity-50');

                    if (!data.success) {
                        alert('Hata: ' + data.error);
                        return;
                    }

                    if (data.crop_preview) {
                        cropPreviewImg.src = data.crop_preview;
                        cropPreviewBox.classList.remove('hidden');
                    }

                    if (data.metadata && Object.keys(data.metadata).length > 0) {
                        metadataCard.classList.remove('hidden');
                        for (const [k, v] of Object.entries(data.metadata)) {
                            metadataContent.innerHTML += `<div class="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80"><span class="text-slate-500 block text-[10px] uppercase">${k}</span><strong class="text-slate-200">${v}</strong></div>`;
                        }
                    }

                    if (data.matches.length === 0) {
                        imageResults.innerHTML = '<div class="col-span-2 text-center text-slate-500 py-6 font-mono">Eşleşen aktif profil bulunamadı.</div>';
                        return;
                    }

                    data.matches.forEach(item => {
                        const card = document.createElement('div');
                        card.className = 'glass-panel p-4 rounded-xl flex gap-3.5 items-center transition-all hover:border-indigo-500/50 hover:shadow-lg hover:shadow-indigo-500/10';
                        card.innerHTML = `
                            ${item.thumbnail ? `<img src="${item.thumbnail}" class="w-14 h-14 rounded-lg object-cover bg-slate-900 border border-slate-800 flex-shrink-0">` : '<div class="w-14 h-14 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-600"><i class="fa-solid fa-image"></i></div>'}
                            <div class="overflow-hidden flex-1">
                                <div class="flex items-center gap-1.5 mb-1">
                                    <span class="text-[10px] px-2 py-0.5 rounded-md border font-mono font-semibold flex items-center gap-1 ${item.color}">
                                        <i class="${item.icon}"></i> ${item.platform}
                                    </span>
                                </div>
                                <p class="text-white text-xs font-semibold truncate mb-0.5">${item.title}</p>
                                <a href="${item.link}" target="_blank" class="text-xs text-indigo-400 hover:text-indigo-300 font-mono inline-block">Profili Gör &rarr;</a>
                            </div>
                        `;
                        imageResults.appendChild(card);
                    });

                } catch (err) {
                    imageSearchStatus.classList.add('hidden');
                    imageSearchBtn.disabled = false;
                    imageSearchBtn.classList.remove('opacity-50');
                    alert('Arama sırasında bir hata oluştu.');
                }
            }
        </script>
    </body>
    </html>
    """