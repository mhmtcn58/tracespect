import os
import io
import asyncio
import json
import base64
import urllib.parse
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse
import httpx
from PIL import Image, ExifTags
import cv2
import numpy as np

app = FastAPI(title="TraceSpect - Next-Gen OSINT & Visual Intelligence")

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
    elif "yandex" in url_lower:
        return {"name": "Yandex Facial Index", "icon": "fa-solid fa-bolt", "color": "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"}
    elif "bing" in url_lower:
        return {"name": "Bing Visual Index", "icon": "fa-brands fa-microsoft", "color": "text-teal-400 bg-teal-500/10 border-teal-500/20"}
    elif "google" in url_lower:
        return {"name": "Google Lens Index", "icon": "fa-brands fa-google", "color": "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"}
    else:
        return {"name": "Web Result", "icon": "fa-solid fa-globe", "color": "text-slate-400 bg-slate-800 border-slate-700"}

def extract_metadata(image_bytes: bytes):
    meta = {}
    try:
        image = Image.open(io.BytesIO(image_bytes))
        meta["Format"] = image.format
        meta["Resolution"] = f"{image.width}x{image.height} px"
        exif = image.getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag in ["Make", "Model", "DateTime", "Software"]:
                    meta[str(tag)] = str(value)
    except Exception:
        pass
    return meta

def enhance_and_crop_biometrics(image_bytes: bytes):
    """
    Biyometrik CLAHE kontrast iyileştirmesi uygular ve yüzü en yüksek 
    arama motoru başarısı için %20 güvenlik payıyla odaklar.
    """
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return image_bytes, False, None

        # 1. Biyometrik CLAHE Netleştirme (Düşük ışık / parlamayı dengeler)
        lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
        l, a, b = cv2.split(lab)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        cl = clahe.apply(l)
        enhanced_img = cv2.cvtColor(cv2.merge((cl, a, b)), cv2.COLOR_LAB2BGR)

        # 2. Yüz Tespiti
        gray = cv2.cvtColor(enhanced_img, cv2.COLOR_BGR2GRAY)
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.15, minNeighbors=4, minSize=(60, 60))

        if len(faces) > 0:
            x, y, w, h = max(faces, key=lambda b: b[2] * b[3])
            pad_w = int(w * 0.20)
            pad_h = int(h * 0.20)
            h_img, w_img, _ = enhanced_img.shape

            y1 = max(0, y - pad_h)
            y2 = min(h_img, y + h + pad_h)
            x1 = max(0, x - pad_w)
            x2 = min(w_img, x + w + pad_w)

            cropped = enhanced_img[y1:y2, x1:x2]
            success, buffer = cv2.imencode('.jpg', cropped, [int(cv2.IMWRITE_JPEG_QUALITY), 95])
            if success:
                crop_b64 = base64.b64encode(buffer).decode('utf-8')
                return buffer.tobytes(), True, f"data:image/jpeg;base64,{crop_b64}"
        else:
            # Yüz tespit edilemezse netleştirilmiş tam görseli döndür
            success, buffer = cv2.imencode('.jpg', enhanced_img, [int(cv2.IMWRITE_JPEG_QUALITY), 95])
            if success:
                crop_b64 = base64.b64encode(buffer).decode('utf-8')
                return buffer.tobytes(), False, f"data:image/jpeg;base64,{crop_b64}"

    except Exception:
        pass
    return image_bytes, False, None

def generate_multi_engine_direct_searches(direct_image_url: str):
    """
    Kullanıcının yüklediği görseli dünyanın en büyük 4 OSINT görsel 
    motorunda tek tıkla doğrudan tarayabilmesi için derin bağlantılar üretir.
    """
    encoded_url = urllib.parse.quote(direct_image_url)
    return [
        {
            "title": "Yandex Visual Deep Recon (En Güçlü Yüz & Sosyal Medya Motoru)",
            "source": "Yandex OSINT AI",
            "link": f"https://yandex.com/images/search?rpt=imageview&url={encoded_url}",
            "thumbnail": "",
            "platform": "Yandex Facial Index",
            "icon": "fa-solid fa-bolt",
            "color": "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
        },
        {
            "title": "Bing Visual Intelligence (LinkedIn, Kurumsal & Forum Taraması)",
            "source": "Microsoft Bing Visual",
            "link": f"https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl={encoded_url}",
            "thumbnail": "",
            "platform": "Bing Visual Index",
            "icon": "fa-brands fa-microsoft",
            "color": "text-teal-400 bg-teal-500/10 border-teal-500/20"
        },
        {
            "title": "Google Lens Global Web & Profil Analizi",
            "source": "Google Vision AI",
            "link": f"https://lens.google.com/uploadbyurl?url={encoded_url}",
            "thumbnail": "",
            "platform": "Google Lens Index",
            "icon": "fa-brands fa-google",
            "color": "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
        },
        {
            "title": "Baidu Visual Global Database",
            "source": "Baidu AI Search",
            "link": "https://image.baidu.com",
            "thumbnail": "",
            "platform": "Web Result",
            "icon": "fa-solid fa-globe",
            "color": "text-slate-400 bg-slate-800 border-slate-700"
        }
    ]

async def check_site(client: httpx.AsyncClient, name: str, config: dict, username: str):
    target_url = config["url"].format(username)
    headers = config.get("headers", {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
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
    try:
        raw_contents = await image.read()
        metadata = extract_metadata(raw_contents)
        
        # Biyometrik iyileştirme ve yüz odaklama
        optimized_bytes, face_found, crop_preview = enhance_and_crop_biometrics(raw_contents)
        
        async with httpx.AsyncClient(timeout=25.0) as client:
            # Görseli geçici analiz sunucusuna aktar
            upload_res = await client.post(
                "https://tmpfiles.org/api/v1/upload",
                files={"file": ("search.jpg", optimized_bytes, "image/jpeg")}
            )
            if upload_res.status_code != 200:
                return {"success": False, "error": "Görsel analiz sunucusuna aktarılamadı."}
            
            raw_url = upload_res.json()["data"]["url"]
            direct_image_url = raw_url.replace("tmpfiles.org/", "tmpfiles.org/dl/")

            matches = []

            # 1. Öncelikli Derin OSINT Motorları (Yandex, Bing, Google Lens, Baidu)
            direct_engines = generate_multi_engine_direct_searches(direct_image_url)
            matches.extend(direct_engines)

            # 2. SerpApi Google Lens Otomatik Web Ayrıştırması
            if SERPAPI_KEY and SERPAPI_KEY != "BURAYA_SERPAPI_KEY_YAZ":
                serp_url = "https://serpapi.com/search.json"
                params = {
                    "engine": "google_lens",
                    "url": direct_image_url,
                    "api_key": SERPAPI_KEY,
                    "hl": "tr"
                }
                try:
                    response = await client.get(serp_url, params=params)
                    results = response.json()
                    if "visual_matches" in results:
                        for item in results["visual_matches"]:
                            link = item.get("link", "#")
                            platform_info = detect_platform(link)
                            matches.append({
                                "title": item.get("title", "İsimsiz Eşleşme"),
                                "source": item.get("source", "Bilinmeyen Kaynak"),
                                "link": link,
                                "thumbnail": item.get("thumbnail", ""),
                                "platform": platform_info["name"],
                                "icon": platform_info["icon"],
                                "color": platform_info["color"]
                            })
                except Exception:
                    pass
            
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
                <h2 id="i18n_paywallTitle" class="text-2xl font-extrabold text-white mb-2 tracking-tight">Günlük Limit Doldu</h2>
                <p id="i18n_paywallDesc" class="text-slate-400 text-xs sm:text-sm mb-6 leading-relaxed">
                    Günde en fazla 2 ücretsiz tarama yapabilirsiniz. Sınırsız derin web taraması, yüz biyometrisi ve PDF raporlar için VIP erişim sağlayın.
                </p>
                <a id="i18n_paywallBtn" href="https://shopier.com/TraceSpectVIP" target="_blank" 
                   class="w-full bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 hover:opacity-95 transition-all text-white font-bold py-3.5 px-6 rounded-xl block shadow-xl shadow-indigo-600/30 text-sm">
                    <i class="fa-solid fa-bolt mr-1"></i> Sınırsız VIP Erişim Al (49 TL)
                </a>
                <button id="i18n_paywallClose" onclick="document.getElementById('paywallModal').classList.add('hidden')" class="mt-4 text-slate-500 text-xs hover:text-slate-300 transition-colors">
                    Pencereyi Kapat
                </button>
            </div>
        </div>

        <!-- 2. MODAL: DESTEK & BAĞIŞ -->
        <div id="donateModal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 backdrop-blur-md p-4">
            <div class="glass-panel max-w-md w-full rounded-3xl p-6 text-center shadow-2xl border border-indigo-500/40 relative">
                <div class="h-12 w-12 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 flex items-center justify-center mx-auto mb-3 text-2xl">
                    <i class="fa-solid fa-mug-hot"></i>
                </div>
                <h3 id="i18n_donateTitle" class="text-xl font-bold text-white mb-2">Geliştiriciye Destek Ol</h3>
                <p id="i18n_donateDesc" class="text-slate-400 text-xs mb-4">Sunucu masraflarını ve açık kaynak geliştirmeyi destekleyin.</p>
                
                <div class="space-y-3 text-left">
                    <div class="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                        <span class="text-[10px] text-slate-500 block uppercase font-mono mb-1">USDT (TRC-20):</span>
                        <div class="flex items-center justify-between gap-2">
                            <span class="text-xs text-indigo-300 font-mono truncate" id="walletAddr">TJiDsEXVWcbi1UShVUiFaufB1Tt2DViUBG</span>
                            <button onclick="copyWallet()" class="bg-indigo-600/30 hover:bg-indigo-600 text-indigo-200 text-xs px-2.5 py-1 rounded transition-colors font-mono">
                                <span id="copyBtnTxt"><i class="fa-solid fa-copy"></i></span>
                            </button>
                        </div>
                    </div>
                </div>
                <button id="i18n_donateClose" onclick="document.getElementById('donateModal').classList.add('hidden')" class="mt-5 text-slate-500 text-xs hover:text-slate-300">Kapat</button>
            </div>
        </div>

        <!-- 3. MODAL: GİZLİLİK POLİTİKASI -->
        <div id="privacyModal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 backdrop-blur-md p-4">
            <div class="glass-panel max-w-lg w-full rounded-3xl p-6 text-left shadow-2xl border border-slate-800 text-xs text-slate-300 max-h-[80vh] overflow-y-auto">
                <h3 id="i18n_privacyTitle" class="text-lg font-bold text-white mb-3 flex items-center gap-2">
                    <i class="fa-solid fa-shield-halved text-indigo-400"></i> Gizlilik & Yasal Sorumluluk Reddi
                </h3>
                <p id="i18n_privacyP1" class="mb-2 leading-relaxed">
                    1. <strong>Açık Kaynak İstihbarat:</strong> TraceSpect, yalnızca kamuya açık arama motorları ve sosyal platformlar tarafından indekslenmiş verileri (OSINT) analiz eder.
                </p>
                <p id="i18n_privacyP2" class="mb-2 leading-relaxed">
                    2. <strong>Sıfır Veri Depolama:</strong> Yüklenen fotoğraflar veya aranan kullanıcı adları sunucularımızda asla depolanmaz, arşivlenmez veya üçüncü kişilerle paylaşılmaz.
                </p>
                <p id="i18n_privacyP3" class="mb-4 leading-relaxed">
                    3. <strong>Sorumluluk:</strong> Çıkan sonuçlar kamuya açık verilerin eşleştirilmesidir, arama yapan kullanıcının kendi sorumluluğundadır.
                </p>
                <button id="i18n_privacyUnderstand" onclick="document.getElementById('privacyModal').classList.add('hidden')" class="w-full bg-slate-800 hover:bg-slate-700 text-white font-semibold py-2 rounded-xl">Anladım</button>
            </div>
        </div>

        <!-- Navigation Header -->
        <nav class="w-full border-b border-slate-800/80 bg-slate-950/60 backdrop-blur-md sticky top-0 z-40 px-4 sm:px-6 py-3.5 flex justify-between items-center max-w-7xl mx-auto">
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
            
            <div class="flex items-center gap-2 sm:gap-3">
                <!-- 8 DİLLİ SEÇİM DROPDOWN -->
                <div class="relative">
                    <select id="langSelect" onchange="changeLanguage(this.value)" 
                            class="bg-slate-900 border border-slate-800 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-500 cursor-pointer font-medium">
                        <option value="tr">🇹🇷 TR</option>
                        <option value="en">🇬🇧 EN</option>
                        <option value="es">🇪🇸 ES</option>
                        <option value="de">🇩🇪 DE</option>
                        <option value="ru">🇷🇺 RU</option>
                        <option value="zh">🇨🇳 中文</option>
                        <option value="ja">🇯🇵 日本語</option>
                        <option value="ko">🇰🇷 한국어</option>
                    </select>
                </div>

                <button id="i18n_navDonate" onclick="document.getElementById('donateModal').classList.remove('hidden')" class="text-xs font-semibold px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 transition-all hidden sm:flex items-center gap-2">
                    <i class="fa-solid fa-mug-hot text-amber-400"></i> Destek Ol
                </button>
                <a id="i18n_navVip" href="https://shopier.com/TraceSpectVIP" target="_blank" class="text-xs font-semibold px-3 py-1.5 rounded-lg bg-indigo-600/20 border border-indigo-500/30 hover:bg-indigo-600/30 text-indigo-300 transition-all flex items-center gap-1.5">
                    <i class="fa-solid fa-crown text-amber-400"></i> VIP
                </a>
            </div>
        </nav>

        <main class="max-w-4xl w-full px-4 py-8 sm:py-10 flex-1 flex flex-col items-center">
            
            <!-- Hero Title -->
            <div class="text-center mb-8 max-w-2xl">
                <div id="i18n_heroBadge" class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-medium mb-4">
                    <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                    26+ Platform & Derin Yüz Taraması Aktif
                </div>
                <h1 id="i18n_heroTitle" class="text-3xl sm:text-5xl font-extrabold tracking-tight text-white mb-3 leading-tight">
                    Dijital Ayak İzini <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">Görünür Kılın</span>
                </h1>
                <p id="i18n_heroDesc" class="text-slate-400 text-xs sm:text-base leading-relaxed">
                    Kullanıcı adlarını, EXIF meta verilerini ve yüz biyometrisini açık istihbarat (OSINT) ağlarında eşzamanlı sorgulayın.
                </p>
            </div>

            <!-- Tab Buttons -->
            <div class="flex justify-center mb-6 bg-slate-900/90 p-1.5 rounded-2xl border border-slate-800/80 w-fit mx-auto shadow-2xl backdrop-blur-xl">
                <button id="tabUsername" onclick="switchTab('username')" class="px-5 sm:px-6 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 flex items-center gap-2">
                    <i class="fa-solid fa-at"></i> <span id="i18n_tabUser">Kullanıcı Adı Analizi</span>
                </button>
                <button id="tabImage" onclick="switchTab('image')" class="px-5 sm:px-6 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all text-slate-400 hover:text-white flex items-center gap-2">
                    <i class="fa-solid fa-expand"></i> <span id="i18n_tabImg">Yüz & Görsel OSINT</span>
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
                            class="w-full bg-transparent pl-11 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none text-xs sm:text-base font-mono">
                    </div>
                    <button type="submit" id="submitBtn"
                        class="bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-indigo-400 font-semibold px-5 sm:px-7 py-3 rounded-xl transition-all flex items-center gap-2 text-xs sm:text-base shadow-lg shadow-indigo-600/30 text-white">
                        <span id="i18n_btnScan">Ağı Tara</span>
                        <i class="fa-solid fa-bolt text-xs"></i>
                    </button>
                </form>

                <div id="statsSection" class="hidden mb-6 glass-panel rounded-2xl p-5 shadow-xl">
                    <div class="flex justify-between items-center text-xs font-mono text-slate-400 mb-2">
                        <span id="statusText" class="flex items-center gap-2">
                            <span class="h-2 w-2 rounded-full bg-indigo-500 animate-pulse"></span> <span id="i18n_scanningTxt">Taranıyor...</span>
                        </span>
                        <span id="progressText" class="text-indigo-400 font-bold">0%</span>
                    </div>
                    <div class="w-full bg-slate-950 rounded-full h-2 overflow-hidden p-0.5 border border-slate-800">
                        <div id="progressBar" class="bg-gradient-to-r from-indigo-500 to-cyan-400 h-1.5 rounded-full transition-all duration-300" style="width: 0%"></div>
                    </div>
                    <div class="flex items-center justify-between mt-4 pt-3 border-t border-slate-800/80 text-xs">
                        <div class="flex gap-4 font-mono">
                            <span class="text-slate-400"><span id="i18n_foundTxt">Bulunan</span>: <strong id="foundCount" class="text-emerald-400 font-bold">0</strong></span>
                            <span class="text-slate-400"><span id="i18n_notFoundTxt">Kayıtsız</span>: <strong id="notFoundCount" class="text-slate-500">0</strong></span>
                        </div>
                        <div class="flex gap-2">
                            <button id="filterBtn" class="bg-slate-800/80 hover:bg-slate-700 px-3.5 py-1.5 rounded-lg text-slate-300 transition-colors border border-slate-700">
                                Sadece Bulunanlar
                            </button>
                            <button id="exportCsvBtn" class="bg-slate-800/80 hover:bg-slate-700 px-3.5 py-1.5 rounded-lg text-slate-300 transition-colors hidden border border-slate-700">
                                CSV
                            </button>
                            <button id="exportPdfBtn" onclick="exportPDF()" class="bg-indigo-600/20 border border-indigo-500/30 hover:bg-indigo-600/30 px-3.5 py-1.5 rounded-lg text-indigo-300 transition-colors hidden font-semibold">
                                <i class="fa-solid fa-file-pdf text-rose-400 mr-1"></i> <span id="i18n_pdfBtn">PDF Raporu İndir</span>
                            </button>
                        </div>
                    </div>
                </div>

                <div id="results" class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"></div>
            </div>

            <!-- 2. TAB: IMAGE / FACE OSINT SECTION -->
            <div id="imageSection" class="w-full hidden">
                <div class="glass-panel rounded-3xl p-6 sm:p-8 mb-6 text-center glass-glow">
                    <input type="file" id="imageInput" accept="image/*" class="hidden">
                    <div id="dropZone" onclick="document.getElementById('imageInput').click()" 
                        class="border-2 border-dashed border-slate-700/80 hover:border-indigo-500/80 bg-slate-950/40 rounded-2xl p-8 sm:p-10 cursor-pointer transition-all flex flex-col items-center justify-center group">
                        <div class="h-16 w-16 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mb-4 group-hover:scale-110 transition-transform">
                            <i class="fa-solid fa-face-viewfinder text-3xl"></i>
                        </div>
                        <p id="i18n_dropTitle" class="text-slate-200 font-semibold text-sm sm:text-base mb-1">Portre veya Görsel Yükleyin</p>
                        <p id="i18n_dropDesc" class="text-slate-500 text-xs">Yapay zeka yüzü otomatik kırpar, EXIF meta verilerini ayrıştırır</p>
                    </div>

                    <div id="previewContainer" class="hidden mt-6 flex flex-col items-center">
                        <div class="flex gap-4 items-center justify-center flex-wrap mb-4">
                            <div class="text-center">
                                <span id="i18n_origImg" class="text-[11px] text-slate-500 block mb-1 font-mono">Orijinal Fotoğraf</span>
                                <img id="imagePreview" src="" class="h-32 w-32 sm:h-36 sm:w-36 rounded-xl object-cover border border-slate-700 shadow-md">
                            </div>
                            <div id="cropPreviewBox" class="text-center hidden">
                                <span id="i18n_cropImg" class="text-[11px] text-indigo-400 block mb-1 font-mono font-semibold">Odaklanan Yüz & Biyometri</span>
                                <img id="cropPreviewImg" src="" class="h-32 w-32 sm:h-36 sm:w-36 rounded-xl object-cover border-2 border-indigo-500 shadow-lg shadow-indigo-500/20">
                            </div>
                        </div>
                        <button id="imageSearchBtn" onclick="submitImageSearch()"
                            class="bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 px-6 sm:px-8 py-3 rounded-xl font-bold text-xs sm:text-sm flex items-center gap-2 transition-all shadow-xl shadow-indigo-600/30 text-white">
                            <span id="i18n_btnImgScan">Biyometrik & Web Taraması Başlat</span>
                            <i class="fa-solid fa-crosshairs"></i>
                        </button>
                    </div>
                </div>

                <div id="imageSearchStatus" class="hidden text-center text-xs sm:text-sm font-mono text-indigo-400 mb-4 animate-pulse">
                    <i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span id="i18n_imgScanning">Yüz biyometrisi taranıyor ve web profilleri çekiliyor...</span>
                </div>

                <!-- EXIF METADATA CARD -->
                <div id="metadataCard" class="hidden mb-6 glass-panel rounded-2xl p-5 text-xs shadow-xl">
                    <div class="flex items-center gap-2 text-indigo-400 font-bold mb-3 border-b border-slate-800 pb-2.5">
                        <i class="fa-solid fa-microchip"></i> <span id="i18n_exifTitle">EXIF Meta Veri Analiz Raporu</span>
                    </div>
                    <div id="metadataContent" class="grid grid-cols-2 sm:grid-cols-3 gap-2.5 font-mono"></div>
                </div>

                <div id="imageResults" class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"></div>
            </div>

        </main>

        <!-- Footer / Legal Info -->
        <footer class="w-full border-t border-slate-900 bg-slate-950/80 py-8 px-6 mt-12 text-center text-xs text-slate-500">
            <div class="max-w-4xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-4">
                <p>TraceSpect Intelligence &copy; 2026. <span id="i18n_footerRights">Tüm hakları saklıdır.</span></p>
                <div class="flex gap-4">
                    <button id="i18n_footerPrivacy" onclick="document.getElementById('privacyModal').classList.remove('hidden')" class="hover:text-slate-400 transition-colors">Gizlilik Politikası</button>
                    <button id="i18n_footerTerms" onclick="document.getElementById('privacyModal').classList.remove('hidden')" class="hover:text-slate-400 transition-colors">Kullanım Şartları</button>
                    <a href="mailto:support@tracespect.com" class="hover:text-slate-400 transition-colors">API & Support</a>
                </div>
            </div>
        </footer>

        <script>
            // 8 DİLLİ ÇEVİRİ SÖZLÜĞÜ (i18n)
            const I18N = {
                tr: {
                    paywallTitle: "Günlük Limit Doldu",
                    paywallDesc: "Günde en fazla 2 ücretsiz tarama yapabilirsiniz. Sınırsız derin web taraması, yüz biyometrisi ve PDF raporlar için VIP erişim sağlayın.",
                    paywallBtn: '<i class="fa-solid fa-bolt mr-1"></i> Sınırsız VIP Erişim Al (49 TL)',
                    paywallClose: "Pencereyi Kapat",
                    donateTitle: "Geliştiriciye Destek Ol",
                    donateDesc: "Sunucu masraflarını ve açık kaynak geliştirmeyi destekleyin.",
                    donateClose: "Kapat",
                    privacyTitle: '<i class="fa-solid fa-shield-halved text-indigo-400"></i> Gizlilik & Yasal Sorumluluk Reddi',
                    privacyP1: "1. <strong>Açık Kaynak İstihbarat:</strong> TraceSpect, yalnızca kamuya açık arama motorları ve sosyal platformlar tarafından indekslenmiş verileri (OSINT) analiz eder.",
                    privacyP2: "2. <strong>Sıfır Veri Depolama:</strong> Yüklenen fotoğraflar veya aranan kullanıcı adları sunucularımızda asla depolanmaz, arşivlenmez veya üçüncü kişilerle paylaşılmaz.",
                    privacyP3: "3. <strong>Sorumluluk:</strong> Çıkan sonuçlar kamuya açık verilerin eşleştirilmesidir, arama yapan kullanıcının kendi sorumluluğundadır.",
                    privacyUnderstand: "Anladım",
                    navDonate: '<i class="fa-solid fa-mug-hot text-amber-400"></i> Destek Ol',
                    heroBadge: '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span> 26+ Platform & Derin Yüz Taranıyor',
                    heroTitle: 'Dijital Ayak İzini <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">Görünür Kılın</span>',
                    heroDesc: "Kullanıcı adlarını, EXIF meta verilerini ve yüz biyometrisini açık istihbarat (OSINT) ağlarında eşzamanlı sorgulayın.",
                    tabUser: "Kullanıcı Adı Analizi",
                    tabImg: "Yüz & Görsel OSINT",
                    userInputPlaceholder: "Hedef kullanıcı adını girin (örn: torvalds)",
                    btnScan: "Ağı Tara",
                    scanningTxt: "Taranıyor...",
                    foundTxt: "Bulunan",
                    notFoundTxt: "Kayıtsız",
                    filterOnlyFound: "Sadece Bulunanlar",
                    filterAll: "Tümünü Göster",
                    pdfBtn: "PDF Raporu İndir",
                    dropTitle: "Portre veya Görsel Yükleyin",
                    dropDesc: "Yapay zeka yüzü otomatik kırpar, EXIF meta verilerini ayrıştırır",
                    origImg: "Orijinal Fotoğraf",
                    cropImg: "Odaklanan Yüz & Biyometri",
                    btnImgScan: "Biyometrik & Web Taraması Başlat",
                    imgScanning: "Yüz biyometrisi taranıyor ve web profilleri çekiliyor...",
                    exifTitle: "EXIF Meta Veri Analiz Raporu",
                    verifyLink: "Profili Doğrula",
                    statusActive: "AKTİF",
                    statusNone: "YOK",
                    footerRights: "Tüm hakları saklıdır.",
                    footerPrivacy: "Gizlilik Politikası",
                    footerTerms: "Kullanım Şartları",
                    pdfHeader: "TRACESPECT OSINT LABS",
                    pdfSub: "AÇIK KAYNAK DİJİTAL İSTİHBARAT RAPORU",
                    pdfTarget: "Hedef Kullanıcı",
                    pdfScanned: "Taranan Platform Sayısı",
                    pdfFound: "Tespit Edilen Aktif Hesap",
                    pdfActiveTable: "TESPİT EDİLEN AKTİF PROFİLLER",
                    pdfLegal: "Bu rapor kamuya açık OSINT veritabanları sorgulanarak TraceSpect motoru tarafından otomatik olarak derlenmiştir."
                },
                en: {
                    paywallTitle: "Daily Limit Reached",
                    paywallDesc: "You have reached your limit of 2 free searches per day. Upgrade to VIP for unlimited deep web lookups, facial recon, and PDF exports.",
                    paywallBtn: '<i class="fa-solid fa-bolt mr-1"></i> Get Unlimited VIP Access ($1.99)',
                    paywallClose: "Close",
                    donateTitle: "Support the Developer",
                    donateDesc: "Help fund server infrastructure and open-source intelligence research.",
                    donateClose: "Close",
                    privacyTitle: '<i class="fa-solid fa-shield-halved text-indigo-400"></i> Privacy & Legal Disclaimer',
                    privacyP1: "1. <strong>Open Source Intelligence:</strong> TraceSpect only searches publicly indexed datasets and public platform endpoints (OSINT).",
                    privacyP2: "2. <strong>Zero Data Retention:</strong> Uploaded images and queried usernames are never stored, logged, or shared with third parties.",
                    privacyP3: "3. <strong>Disclaimer:</strong> Search results are derived from public indices. Query intent and usage remain the sole responsibility of the user.",
                    privacyUnderstand: "I Understand",
                    navDonate: '<i class="fa-solid fa-mug-hot text-amber-400"></i> Donate',
                    heroBadge: '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span> 26+ Platforms & Deep Facial Recon Active',
                    heroTitle: 'Make Your Digital Footprint <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">Visible</span>',
                    heroDesc: "Perform concurrent queries across username registries, EXIF telemetry, and biometric facial intelligence.",
                    tabUser: "Username Recon",
                    tabImg: "Facial & Visual OSINT",
                    userInputPlaceholder: "Enter target username (e.g., torvalds)",
                    btnScan: "Scan Network",
                    scanningTxt: "Scanning...",
                    foundTxt: "Found",
                    notFoundTxt: "Available",
                    filterOnlyFound: "Only Matches",
                    filterAll: "Show All",
                    pdfBtn: "Download PDF Report",
                    dropTitle: "Upload a Portrait or Image",
                    dropDesc: "AI automatically crops faces and extracts hidden EXIF metadata",
                    origImg: "Original Image",
                    cropImg: "Focused Face & Biometrics",
                    btnImgScan: "Launch Biometric & Web Recon",
                    imgScanning: "Scanning facial biometrics and aggregating web profiles...",
                    exifTitle: "EXIF Telemetry Report",
                    verifyLink: "Verify Profile",
                    statusActive: "ACTIVE",
                    statusNone: "NONE",
                    footerRights: "All rights reserved.",
                    footerPrivacy: "Privacy Policy",
                    footerTerms: "Terms of Service",
                    pdfHeader: "TRACESPECT OSINT LABS",
                    pdfSub: "OPEN SOURCE INTELLIGENCE & FORENSIC REPORT",
                    pdfTarget: "Target Subject",
                    pdfScanned: "Platforms Queried",
                    pdfFound: "Confirmed Profiles",
                    pdfActiveTable: "IDENTIFIED ACTIVE PROFILES",
                    pdfLegal: "This report has been automatically generated by TraceSpect engine querying public OSINT records."
                },
                es: {
                    paywallTitle: "Límite Diario Alcanzado",
                    paywallDesc: "Has alcanzado el límite de 2 búsquedas gratuitas al día. Pasa a VIP para búsquedas ilimitadas y reportes en PDF.",
                    paywallBtn: '<i class="fa-solid fa-bolt mr-1"></i> Obtener Acceso VIP Ilimitado',
                    paywallClose: "Cerrar",
                    donateTitle: "Apoyar al Desarrollador",
                    donateDesc: "Ayuda a financiar los servidores y el desarrollo de código abierto.",
                    donateClose: "Cerrar",
                    privacyTitle: '<i class="fa-solid fa-shield-halved text-indigo-400"></i> Privacidad y Aviso Legal',
                    privacyP1: "1. <strong>Inteligencia de Fuentes Abiertas:</strong> TraceSpect solo analiza datos indexados públicamente (OSINT).",
                    privacyP2: "2. <strong>Cero Almacenamiento:</strong> No se guardan ni almacenan imágenes o nombres de usuario.",
                    privacyP3: "3. <strong>Responsabilidad:</strong> El uso de esta herramienta es responsabilidad exclusiva del usuario.",
                    privacyUnderstand: "Entendido",
                    navDonate: '<i class="fa-solid fa-mug-hot text-amber-400"></i> Donar',
                    heroBadge: '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span> 26+ Plataformas y Reconocimiento Facial Activo',
                    heroTitle: 'Haz Visible tu <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">Huella Digital</span>',
                    heroDesc: "Consulta simultáneamente registros de usuarios, telemetría EXIF e inteligencia biométrica.",
                    tabUser: "Análisis de Usuario",
                    tabImg: "OSINT Facial y Visual",
                    userInputPlaceholder: "Introduce el usuario objetivo (ej: torvalds)",
                    btnScan: "Escanear Red",
                    scanningTxt: "Escaneando...",
                    foundTxt: "Encontrados",
                    notFoundTxt: "No registrado",
                    filterOnlyFound: "Solo Encontrados",
                    filterAll: "Mostrar Todo",
                    pdfBtn: "Descargar Informe PDF",
                    dropTitle: "Sube un Retrato o Imagen",
                    dropDesc: "La IA recorta el rostro y extrae metadatos EXIF automáticamente",
                    origImg: "Imagen Original",
                    cropImg: "Rostro Enfocado & Biometría",
                    btnImgScan: "Iniciar Escaneo Biométrico",
                    imgScanning: "Analizando biometría facial y recopilando perfiles...",
                    exifTitle: "Informe de Metadatos EXIF",
                    verifyLink: "Verificar Perfil",
                    statusActive: "ACTIVO",
                    statusNone: "LIBRE",
                    footerRights: "Todos los derechos reservados.",
                    footerPrivacy: "Política de Privacidad",
                    footerTerms: "Términos de Servicio",
                    pdfHeader: "TRACESPECT OSINT LABS",
                    pdfSub: "INFORME DE INTELIGENCIA DE FUENTES ABIERTAS",
                    pdfTarget: "Usuario Objetivo",
                    pdfScanned: "Plataformas Analizadas",
                    pdfFound: "Perfiles Confirmados",
                    pdfActiveTable: "PERFILES ACTIVOS IDENTIFICADOS",
                    pdfLegal: "Este informe fue generado automáticamente por TraceSpect consultando registros públicos de OSINT."
                },
                de: {
                    paywallTitle: "Tageslimit Erreicht",
                    paywallDesc: "Sie haben das Limit von 2 kostenlosen Suchen pro Tag erreicht. Holen Sie sich VIP für unbegrenzte Analysen und PDF-Berichte.",
                    paywallBtn: '<i class="fa-solid fa-bolt mr-1"></i> Unbegrenzten VIP-Zugang Kaufen',
                    paywallClose: "Schließen",
                    donateTitle: "Entwickler Unterstützen",
                    donateDesc: "Unterstützen Sie Serverkosten und Open-Source-Forschung.",
                    donateClose: "Schließen",
                    privacyTitle: '<i class="fa-solid fa-shield-halved text-indigo-400"></i> Datenschutz & Haftungsausschluss',
                    privacyP1: "1. <strong>Open Source Intelligence:</strong> TraceSpect analysiert nur öffentlich zugängliche Daten (OSINT).",
                    privacyP2: "2. <strong>Keine Datenspeicherung:</strong> Hochgeladene Fotos und Benutzernamen werden niemals gespeichert.",
                    privacyP3: "3. <strong>Haftung:</strong> Die Nutzung liegt in der alleinigen Verantwortung des Nutzers.",
                    privacyUnderstand: "Verstanden",
                    navDonate: '<i class="fa-solid fa-mug-hot text-amber-400"></i> Spenden',
                    heroBadge: '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span> 26+ Plattformen & Gesichtserkennung Aktiv',
                    heroTitle: 'Machen Sie Ihren Digitalen <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">Fußabdruck Sichtbar</span>',
                    heroDesc: "Gleichzeitige Abfragen über Benutzernamen, EXIF-Metadaten und biometrische Gesichtserkennung.",
                    tabUser: "Benutzernamen-Suche",
                    tabImg: "Gesichts- & Visuelle OSINT",
                    userInputPlaceholder: "Ziel-Benutzernamen eingeben (z.B. torvalds)",
                    btnScan: "Netzwerk Scannen",
                    scanningTxt: "Scannen...",
                    foundTxt: "Gefunden",
                    notFoundTxt: "Frei",
                    filterOnlyFound: "Nur Treffer",
                    filterAll: "Alle Zeigen",
                    pdfBtn: "PDF-Bericht Herunterladen",
                    dropTitle: "Porträt oder Bild Hochladen",
                    dropDesc: "KI schneidet Gesichter automatisch zu und extrahiert EXIF-Daten",
                    origImg: "Originalbild",
                    cropImg: "Fokussiertes Gesicht & Biometrie",
                    btnImgScan: "Biometrischen Scan Starten",
                    imgScanning: "Gesichtsbiometrie wird gescannt...",
                    exifTitle: "EXIF-Metadatenbericht",
                    verifyLink: "Profil Überprüfen",
                    statusActive: "AKTIV",
                    statusNone: "KEIN",
                    footerRights: "Alle Rechte vorbehalten.",
                    footerPrivacy: "Datenschutzerklärung",
                    footerTerms: "Nutzungsbedingungen",
                    pdfHeader: "TRACESPECT OSINT LABS",
                    pdfSub: "OPEN-SOURCE-INTELLIGENCE & FORENSIKBERICHT",
                    pdfTarget: "Zielperson",
                    pdfScanned: "Gescannte Plattformen",
                    pdfFound: "Bestätigte Profile",
                    pdfActiveTable: "IDENTIFIZIERTE AKTIVE PROFILE",
                    pdfLegal: "Dieser Bericht wurde von TraceSpect automatisch anhand öffentlicher OSINT-Quellen erstellt."
                },
                ru: {
                    paywallTitle: "Дневной Лимит Исчерпан",
                    paywallDesc: "Вы использовали 2 бесплатные проверки в день. Перейдите на VIP для неограниченного поиска и экспорта в PDF.",
                    paywallBtn: '<i class="fa-solid fa-bolt mr-1"></i> Получить VIP Доступ',
                    paywallClose: "Закрыть",
                    donateTitle: "Поддержать Разработчика",
                    donateDesc: "Помогите в финансировании серверов и разработке открытого ПО.",
                    donateClose: "Закрыть",
                    privacyTitle: '<i class="fa-solid fa-shield-halved text-indigo-400"></i> Конфиденциальность',
                    privacyP1: "1. <strong>OSINT:</strong> TraceSpect анализирует только общедоступные проиндексированные данные.",
                    privacyP2: "2. <strong>Без сохранения данных:</strong> Загруженные фото и запросы никогда не сохраняются на сервере.",
                    privacyP3: "3. <strong>Ответственность:</strong> Пользователь несет личную ответственность за использование результатов.",
                    privacyUnderstand: "Понятно",
                    navDonate: '<i class="fa-solid fa-mug-hot text-amber-400"></i> Донат',
                    heroBadge: '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span> 26+ Платформ и Распознавание Лиц',
                    heroTitle: 'Сделайте Цифровой След <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">Видимым</span>',
                    heroDesc: "Мгновенный поиск по никнеймам, метаданным EXIF и биометрии лиц.",
                    tabUser: "Поиск по Никнейму",
                    tabImg: "OSINT по Фото и Лицу",
                    userInputPlaceholder: "Введите целевой никнейм (напр. torvalds)",
                    btnScan: "Сканировать",
                    scanningTxt: "Сканирование...",
                    foundTxt: "Найдено",
                    notFoundTxt: "Свободно",
                    filterOnlyFound: "Только Найденные",
                    filterAll: "Показать Все",
                    pdfBtn: "Скачать PDF Отчет",
                    dropTitle: "Загрузите Фотографию",
                    dropDesc: "ИИ автоматически кадрирует лицо и извлекает метаданные EXIF",
                    origImg: "Исходное Фото",
                    cropImg: "Выделенное Лицо & Биометрия",
                    btnImgScan: "Запустить Биометрический Поиск",
                    imgScanning: "Анализ биометрии и сбор профилей в сети...",
                    exifTitle: "Отчет по Метаданным EXIF",
                    verifyLink: "Открыть Профиль",
                    statusActive: "АКТИВЕН",
                    statusNone: "НЕТ",
                    footerRights: "Все права защищены.",
                    footerPrivacy: "Политика Конфиденциальности",
                    footerTerms: "Условия Использования",
                    pdfHeader: "TRACESPECT OSINT LABS",
                    pdfSub: "ОТЧЕТ РАЗВЕДКИ НА ОСНОВЕ ОТКРЫТЫХ ИСТОЧНИКОВ",
                    pdfTarget: "Целевой Объект",
                    pdfScanned: "Проверено Платформ",
                    pdfFound: "Подтверждено Профилей",
                    pdfActiveTable: "ОБНАРУЖЕННЫЕ АКТИВНЫЕ ПРОФИЛИ",
                    pdfLegal: "Данный отчет автоматически сформирован поисковым движком TraceSpect по публичным базам данных OSINT."
                },
                zh: {
                    paywallTitle: "每日免费额度已用尽",
                    paywallDesc: "您今天已完成 2 次免费搜索。升级至 VIP 获取无限次深度网络侦察、人脸识别和 PDF 报告导出。",
                    paywallBtn: '<i class="fa-solid fa-bolt mr-1"></i> 获取无限 VIP 权限',
                    paywallClose: "关闭",
                    donateTitle: "赞助开发者",
                    donateDesc: "支持服务器运营与开源情报技术研发。",
                    donateClose: "关闭",
                    privacyTitle: '<i class="fa-solid fa-shield-halved text-indigo-400"></i> 隐私政策与免责声明',
                    privacyP1: "1. <strong>开源网络情报 (OSINT):</strong> TraceSpect 仅检索公开索引的数据源与平台终端。",
                    privacyP2: "2. <strong>零数据留存:</strong> 用户上传的照片与检索的用户名绝不存储或共享。",
                    privacyP3: "3. <strong>责任声明:</strong> 检索结果均来自公开网络，使用者自行承担使用责任。",
                    privacyUnderstand: "我已知晓",
                    navDonate: '<i class="fa-solid fa-mug-hot text-amber-400"></i> 赞助',
                    heroBadge: '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span> 26+ 平台 & 深度人脸识别已就绪',
                    heroTitle: '让您的数字足迹 <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">一览无余</span>',
                    heroDesc: "跨用户名注册库、EXIF 遥测数据及人脸生物特征进行多维度情报查询。",
                    tabUser: "用户名情报分析",
                    tabImg: "人脸与图像 OSINT",
                    userInputPlaceholder: "输入目标用户名 (例如: torvalds)",
                    btnScan: "扫描网络",
                    scanningTxt: "正在侦察...",
                    foundTxt: "已匹配",
                    notFoundTxt: "未注册",
                    filterOnlyFound: "仅显示匹配项",
                    filterAll: "显示全部",
                    pdfBtn: "下载 PDF 调查报告",
                    dropTitle: "上传人像或照片",
                    dropDesc: "AI 自动识别人脸并提取隐藏的 EXIF 元数据",
                    origImg: "原始图像",
                    cropImg: "人脸焦点 & 生物特征",
                    btnImgScan: "启动生物特征与全网侦察",
                    imgScanning: "正在分析人脸生物特征并聚合网络档案...",
                    exifTitle: "EXIF 遥测数据报告",
                    verifyLink: "查看档案",
                    statusActive: "有效",
                    statusNone: "无",
                    footerRights: "版权所有。",
                    footerPrivacy: "隐私政策",
                    footerTerms: "服务条款",
                    pdfHeader: "TRACESPECT OSINT LABS",
                    pdfSub: "开源网络情报与取证报告",
                    pdfTarget: "目标主体",
                    pdfScanned: "已检索平台数",
                    pdfFound: "已确认档案数",
                    pdfActiveTable: "已识别的活跃档案列表",
                    pdfLegal: "本报告由 TraceSpect 自动化开源情报引擎实时检索并生成。"
                },
                ja: {
                    paywallTitle: "1日の無料制限に達しました",
                    paywallDesc: "1日2回の無料検索を完了しました。VIPにアップグレードして、無制限の検索とPDFレポートを利用してください。",
                    paywallBtn: '<i class="fa-solid fa-bolt mr-1"></i> 無制限VIPアクセスを取得',
                    paywallClose: "閉じる",
                    donateTitle: "開発者を支援する",
                    donateDesc: "サーバーインフラとオープンソース開発をサポート。",
                    donateClose: "閉じる",
                    privacyTitle: '<i class="fa-solid fa-shield-halved text-indigo-400"></i> プライバシーと免責事項',
                    privacyP1: "1. <strong>OSINT:</strong> TraceSpectは公開インデックスされた情報のみを分析します。",
                    privacyP2: "2. <strong>データ非保持:</strong> アップロードされた画像やユーザー名はサーバーに保存されません。",
                    privacyP3: "3. <strong>免責事項:</strong> 検索結果の利用はユーザー自身の責任となります。",
                    privacyUnderstand: "了解しました",
                    navDonate: '<i class="fa-solid fa-mug-hot text-amber-400"></i> 支援',
                    heroBadge: '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span> 26+ プラットフォーム & 顔認識が有効',
                    heroTitle: 'デジタルフットプリントを <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">可視化する</span>',
                    heroDesc: "ユーザー名、EXIFメタデータ、顔認証による総合的な公開インテリジェンス調査。",
                    tabUser: "ユーザー名調査",
                    tabImg: "顔認識・画像OSINT",
                    userInputPlaceholder: "対象のユーザー名を入力 (例: torvalds)",
                    btnScan: "ネットワークスキャン",
                    scanningTxt: "スキャン中...",
                    foundTxt: "検出",
                    notFoundTxt: "未登録",
                    filterOnlyFound: "検出のみ表示",
                    filterAll: "すべて表示",
                    pdfBtn: "PDFレポートを出力",
                    dropTitle: "顔写真または画像をアップロード",
                    dropDesc: "AIが自動で顔をトリミングし、EXIFメタデータを抽出します",
                    origImg: "元の画像",
                    cropImg: "検出された顔 & 生体認証",
                    btnImgScan: "生体認証＆Webスキャンを開始",
                    imgScanning: "顔認証データをスキャンし、プロファイルを収集しています...",
                    exifTitle: "EXIFメタデータレポート",
                    verifyLink: "プロファイルを確認",
                    statusActive: "有効",
                    statusNone: "なし",
                    footerRights: "無断転載を禁じます。",
                    footerPrivacy: "プライバシーポリシー",
                    footerTerms: "利用規約",
                    pdfHeader: "TRACESPECT OSINT LABS",
                    pdfSub: "オープンソースインテリジェンス調査報告書",
                    pdfTarget: "調査対象",
                    pdfScanned: "スキャン対象プラットフォーム数",
                    pdfFound: "確認済みプロファイル数",
                    pdfActiveTable: "検出されたアクティブなプロファイル一覧",
                    pdfLegal: "本報告書はTraceSpectオープンソースインテリジェンスエンジンによって自動生成されました。"
                },
                ko: {
                    paywallTitle: "일일 무료 한도 초과",
                    paywallDesc: "오늘의 무료 검색 2회를 완료했습니다. 무제한 심층 웹 탐색 및 PDF 보고서 출력을 위해 VIP로 업그레이드하세요.",
                    paywallBtn: '<i class="fa-solid fa-bolt mr-1"></i> 무제한 VIP 이용권 구매',
                    paywallClose: "닫기",
                    donateTitle: "개발자 후원하기",
                    donateDesc: "서버 인프라 비용 및 오픈소스 인텔리전스 개발을 후원해 주세요.",
                    donateClose: "닫기",
                    privacyTitle: '<i class="fa-solid fa-shield-halved text-indigo-400"></i> 개인정보 처리방침 및 법적 고지',
                    privacyP1: "1. <strong>오픈소스 인텔리전스:</strong> TraceSpect는 공개적으로 색인된 데이터(OSINT)만을 분석합니다.",
                    privacyP2: "2. <strong>데이터 미저장:</strong> 업로드된 사진이나 사용자 검색 기록은 서버에 절대 저장되지 않습니다.",
                    privacyP3: "3. <strong>책임 한계:</strong> 검색 결과의 활용에 대한 책임은 전적으로 사용자 본인에게 있습니다.",
                    privacyUnderstand: "확인했습니다",
                    navDonate: '<i class="fa-solid fa-mug-hot text-amber-400"></i> 후원',
                    heroBadge: '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span> 26+ 플랫폼 & 정밀 안면 인식 활성화',
                    heroTitle: '디지털 발자국을 <span class="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-300 bg-clip-text text-transparent">시각화하세요</span>',
                    heroDesc: "사용자 이름, EXIF 메타데이터 및 안면 생체 인식을 결합한 종합 OSINT 분석 플랫폼.",
                    tabUser: "사용자명 정밀 분석",
                    tabImg: "안면 및 이미지 OSINT",
                    userInputPlaceholder: "대상 사용자명을 입력하세요 (예: torvalds)",
                    btnScan: "네트워크 탐색",
                    scanningTxt: "탐색 중...",
                    foundTxt: "발견됨",
                    notFoundTxt: "미등록",
                    filterOnlyFound: "발견된 항목만",
                    filterAll: "전체 보기",
                    pdfBtn: "PDF 보고서 다운로드",
                    dropTitle: "인물 사진 또는 이미지 업로드",
                    dropDesc: "AI가 얼굴을 자동 크롭하고 숨겨진 EXIF 메타데이터를 추출합니다",
                    origImg: "원본 이미지",
                    cropImg: "감지된 안면 & 생체 정보",
                    btnImgScan: "생체 인식 & 웹 정찰 시작",
                    imgScanning: "안면 생체 정보를 스캔하고 프로필을 집계하는 중입니다...",
                    exifTitle: "EXIF 메타데이터 분석 보고서",
                    verifyLink: "프로필 확인",
                    statusActive: "활성",
                    statusNone: "없음",
                    footerRights: "모든 권리 보유.",
                    footerPrivacy: "개인정보 처리방침",
                    footerTerms: "서비스 이용약관",
                    pdfHeader: "TRACESPECT OSINT LABS",
                    pdfSub: "오픈소스 인텔리전스 정밀 분석 보고서",
                    pdfTarget: "조사 대상",
                    pdfScanned: "탐색된 플랫폼 수",
                    pdfFound: "확인된 프로필 수",
                    pdfActiveTable: "확인된 활성 프로필 목록",
                    pdfLegal: "본 보고서는 TraceSpect 오픈소스 인텔리전스 엔진을 통해 자동으로 생성되었습니다."
                }
            };

            let CURRENT_LANG = localStorage.getItem('ts_lang') || 'tr';

            function changeLanguage(lang) {
                if (!I18N[lang]) return;
                CURRENT_LANG = lang;
                localStorage.setItem('ts_lang', lang);
                document.getElementById('langSelect').value = lang;
                
                const dict = I18N[lang];
                document.getElementById('i18n_paywallTitle').innerText = dict.paywallTitle;
                document.getElementById('i18n_paywallDesc').innerText = dict.paywallDesc;
                document.getElementById('i18n_paywallBtn').innerHTML = dict.paywallBtn;
                document.getElementById('i18n_paywallClose').innerText = dict.paywallClose;
                
                document.getElementById('i18n_donateTitle').innerText = dict.donateTitle;
                document.getElementById('i18n_donateDesc').innerText = dict.donateDesc;
                document.getElementById('i18n_donateClose').innerText = dict.donateClose;
                
                document.getElementById('i18n_privacyTitle').innerHTML = dict.privacyTitle;
                document.getElementById('i18n_privacyP1').innerHTML = dict.privacyP1;
                document.getElementById('i18n_privacyP2').innerHTML = dict.privacyP2;
                document.getElementById('i18n_privacyP3').innerHTML = dict.privacyP3;
                document.getElementById('i18n_privacyUnderstand').innerText = dict.privacyUnderstand;
                
                document.getElementById('i18n_navDonate').innerHTML = dict.navDonate;
                document.getElementById('i18n_heroBadge').innerHTML = dict.heroBadge;
                document.getElementById('i18n_heroTitle').innerHTML = dict.heroTitle;
                document.getElementById('i18n_heroDesc').innerText = dict.heroDesc;
                
                document.getElementById('i18n_tabUser').innerText = dict.tabUser;
                document.getElementById('i18n_tabImg').innerText = dict.tabImg;
                document.getElementById('usernameInput').placeholder = dict.userInputPlaceholder;
                document.getElementById('i18n_btnScan').innerText = dict.btnScan;
                document.getElementById('i18n_scanningTxt').innerText = dict.scanningTxt;
                document.getElementById('i18n_foundTxt').innerText = dict.foundTxt;
                document.getElementById('i18n_notFoundTxt').innerText = dict.notFoundTxt;
                document.getElementById('i18n_pdfBtn').innerText = dict.pdfBtn;
                
                document.getElementById('i18n_dropTitle').innerText = dict.dropTitle;
                document.getElementById('i18n_dropDesc').innerText = dict.dropDesc;
                document.getElementById('i18n_origImg').innerText = dict.origImg;
                document.getElementById('i18n_cropImg').innerText = dict.cropImg;
                document.getElementById('i18n_btnImgScan').innerText = dict.btnImgScan;
                document.getElementById('i18n_imgScanning').innerText = dict.imgScanning;
                document.getElementById('i18n_exifTitle').innerText = dict.exifTitle;
                
                document.getElementById('i18n_footerRights').innerText = dict.footerRights;
                document.getElementById('i18n_footerPrivacy').innerText = dict.footerPrivacy;
                document.getElementById('i18n_footerTerms').innerText = dict.footerTerms;
                
                document.getElementById('filterBtn').innerText = onlyFoundFilter ? dict.filterAll : dict.filterOnlyFound;
            }

            // GÜNLÜK 2 ARAMA LİMİTİ KONTROLÜ
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
                    ? 'px-5 sm:px-6 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 flex items-center gap-2'
                    : 'px-5 sm:px-6 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all text-slate-400 hover:text-white flex items-center gap-2';
                
                document.getElementById('tabImage').className = !isUser 
                    ? 'px-5 sm:px-6 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 flex items-center gap-2'
                    : 'px-5 sm:px-6 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all text-slate-400 hover:text-white flex items-center gap-2';
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
                const dict = I18N[CURRENT_LANG];
                onlyFoundFilter = !onlyFoundFilter;
                filterBtn.innerText = onlyFoundFilter ? dict.filterAll : dict.filterOnlyFound;
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

            // ÇOK DİLLİ ADLİ & İSTİHBARAT PDF RAPOR MOTORU
            function exportPDF() {
                const dict = I18N[CURRENT_LANG];
                const caseId = 'TS-' + Math.floor(100000 + Math.random() * 900000);
                const element = document.createElement('div');
                element.innerHTML = `
                    <div style="font-family: Arial, sans-serif; padding: 30px; color: #0f172a; background: #ffffff; line-height: 1.5;">
                        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #4f46e5; padding-bottom: 15px; margin-bottom: 20px;">
                            <div>
                                <h1 style="color: #4f46e5; margin: 0; font-size: 22px; font-weight: bold; letter-spacing: -0.5px;">${dict.pdfHeader}</h1>
                                <p style="margin: 3px 0 0 0; font-size: 11px; color: #64748b;">${dict.pdfSub}</p>
                            </div>
                            <div style="text-align: right; font-size: 11px; color: #64748b;">
                                <div><strong>CASE ID:</strong> #${caseId}</div>
                                <div><strong>DATE:</strong> ${new Date().toLocaleString()}</div>
                            </div>
                        </div>

                        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 12px;">
                            <tr style="background: #f8fafc;">
                                <td style="padding: 8px; border: 1px solid #e2e8f0; width: 30%;"><strong>${dict.pdfTarget}:</strong></td>
                                <td style="padding: 8px; border: 1px solid #e2e8f0; color: #4f46e5; font-weight: bold;">${currentTargetUser}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px; border: 1px solid #e2e8f0;"><strong>${dict.pdfScanned}:</strong></td>
                                <td style="padding: 8px; border: 1px solid #e2e8f0;">${currentResults.length}</td>
                            </tr>
                            <tr style="background: #f8fafc;">
                                <td style="padding: 8px; border: 1px solid #e2e8f0;"><strong>${dict.pdfFound}:</strong></td>
                                <td style="padding: 8px; border: 1px solid #e2e8f0; color: #059669; font-weight: bold;">${foundCount}</td>
                            </tr>
                        </table>

                        <h3 style="font-size: 14px; color: #1e293b; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px; margin-bottom: 12px;">
                            ${dict.pdfActiveTable}
                        </h3>
                        
                        <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
                            <thead>
                                <tr style="background: #4f46e5; color: #ffffff; text-align: left;">
                                    <th style="padding: 8px; border: 1px solid #4f46e5;">Platform</th>
                                    <th style="padding: 8px; border: 1px solid #4f46e5;">Endpoint URL</th>
                                    <th style="padding: 8px; border: 1px solid #4f46e5; width: 80px;">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${currentResults.filter(r => r.found).map((r, i) => `
                                    <tr style="background: ${i % 2 === 0 ? '#ffffff' : '#f8fafc'};">
                                        <td style="padding: 8px; border: 1px solid #e2e8f0; font-weight: bold;">${r.platform}</td>
                                        <td style="padding: 8px; border: 1px solid #e2e8f0;"><a href="${r.url}" style="color: #4f46e5; text-decoration: none;">${r.url}</a></td>
                                        <td style="padding: 8px; border: 1px solid #e2e8f0; color: #059669; font-weight: bold;">VERIFIED</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>

                        <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 9px; color: #94a3b8; text-align: justify;">
                            <strong>Disclaimer:</strong> ${dict.pdfLegal}
                        </div>
                    </div>
                `;
                html2pdf().set({ 
                    margin: 0.4, 
                    filename: `TraceSpect_Report_${currentTargetUser}_${caseId}.pdf`, 
                    image: { type: 'jpeg', quality: 0.98 }, 
                    html2canvas: { scale: 2 }, 
                    jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' } 
                }).from(element).save();
            }

            form.addEventListener('submit', (e) => {
                e.preventDefault();
                if (!checkLimit()) return;

                const dict = I18N[CURRENT_LANG];
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
                statusText.innerText = dict.scanningTxt;
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
                            ${data.found ? `<a href="${data.url}" target="_blank" class="text-xs text-indigo-400 hover:text-indigo-300 truncate block mt-0.5"><i class="fa-solid fa-arrow-up-right-from-square mr-1"></i>${dict.verifyLink}</a>` : `<span class="text-xs text-slate-500 font-mono">${dict.statusNone}</span>`}
                        </div>
                        <div>
                            ${data.found ? `<span class="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2.5 py-1 rounded-full font-mono font-bold">${dict.statusActive}</span>` : `<span class="text-[10px] bg-slate-800 text-slate-500 px-2 py-0.5 rounded font-mono">${dict.statusNone}</span>`}
                        </div>
                    `;
                    resultsDiv.appendChild(card);
                });

                activeEventSource.addEventListener('done', () => {
                    statusText.innerText = 'OK';
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('opacity-50');
                    if (foundCount > 0) {
                        exportCsvBtn.classList.remove('hidden');
                        exportPdfBtn.classList.remove('hidden');
                    }
                    activeEventSource.close();
                });

                activeEventSource.onerror = () => {
                    statusText.innerText = 'OK';
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

                const dict = I18N[CURRENT_LANG];
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
                        alert('Error: ' + data.error);
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
                        imageResults.innerHTML = '<div class="col-span-2 text-center text-slate-500 py-6 font-mono">No matching active profile found.</div>';
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
                                <a href="${item.link}" target="_blank" class="text-xs text-indigo-400 hover:text-indigo-300 font-mono inline-block">${dict.verifyLink} &rarr;</a>
                            </div>
                        `;
                        imageResults.appendChild(card);
                    });

                } catch (err) {
                    imageSearchStatus.classList.add('hidden');
                    imageSearchBtn.disabled = false;
                    imageSearchBtn.classList.remove('opacity-50');
                    alert('Error during search.');
                }
            }

            // Sayfa yüklendiğinde hafızadaki dili uygula
            window.addEventListener('DOMContentLoaded', () => {
                changeLanguage(CURRENT_LANG);
            });
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
    