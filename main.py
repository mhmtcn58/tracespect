import os
import io
import asyncio
import json
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse
import httpx
from PIL import Image, ExifTags
import cv2
import numpy as np

app = FastAPI(title="TraceSpect - OSINT & Visual Intelligence")

# SerpAPI anahtarını ortam değişkeninden alır veya varsayılanı kullanır
SERPAPI_KEY = os.getenv("SERPAPI_KEY", "ba1cb11f55022f3ae3bc19abc8ac7c6fca407eaf8973aa9cb26afd6a582cd003")

# 26 Platform ve Doğrulama Kuralları
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

# EXIF Meta Veri Çıkarıcı
def extract_metadata(image_bytes: bytes):
    meta = {}
    try:
        image = Image.open(io.BytesIO(image_bytes))
        meta["Format"] = image.format
        meta["Boyut"] = f"{image.width}x{image.height} px"
        
        exif = image.getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag in ["Make", "Model", "DateTime", "Software"]:
                    meta[str(tag)] = str(value)
    except Exception:
        pass
    return meta

# Otomatik Yüz Kırpma Motoru
def process_face_crop(image_bytes: bytes):
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return image_bytes, False
        
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.2, minNeighbors=4, minSize=(60, 60))
        
        if len(faces) > 0:
            # En belirgin yüzü al
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
                return buffer.tobytes(), True
    except Exception:
        pass
    return image_bytes, False

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

# --- GÖRSEL, YÜZ VE METAVERİ ARAMA API ENDPOINT ---
@app.post("/api/search-image")
async def search_image(image: UploadFile = File(...)):
    if not SERPAPI_KEY or SERPAPI_KEY == "BURAYA_SERPAPI_KEY_YAZ":
        return {"success": False, "error": "Lütfen SERPAPI_KEY tanımlamasını yapın."}
    
    try:
        raw_contents = await image.read()
        
        # 1. Meta verileri (EXIF) çıkar
        metadata = extract_metadata(raw_contents)
        
        # 2. Yüz algılama ve odak kırpma yap
        optimized_bytes, face_found = process_face_crop(raw_contents)
        
        async with httpx.AsyncClient(timeout=25.0) as client:
            # 3. Optimize edilmiş görseli geçici sunucuya yükle
            upload_res = await client.post(
                "https://tmpfiles.org/api/v1/upload",
                files={"file": ("search.jpg", optimized_bytes, "image/jpeg")}
            )
            if upload_res.status_code != 200:
                return {"success": False, "error": "Görsel analiz sunucusuna aktarılamadı."}
            
            raw_url = upload_res.json()["data"]["url"]
            direct_image_url = raw_url.replace("tmpfiles.org/", "tmpfiles.org/dl/")

            # 4. Google Lens üzerinden görsel eşleşmeleri çek
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
                "face_detected": face_found
            }
            
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TraceSpect | OSINT & Visual Intelligence</title>
        <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛰️</text></svg>">
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col items-center py-10 px-4 antialiased">
        <div class="max-w-3xl w-full">
            
            <!-- Header -->
            <div class="text-center mb-6">
                <div class="inline-flex items-center justify-center p-3.5 bg-indigo-500/10 border border-indigo-500/20 rounded-2xl mb-4 text-indigo-400 shadow-inner">
                    <i class="fa-solid fa-fingerprint text-3xl"></i>
                </div>
                <h1 class="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mb-2">TraceSpect</h1>
                <p class="text-slate-400 text-sm sm:text-base">Kullanıcı adı, EXIF meta veri ve yüz analiziyle dijital ayak izi taraması.</p>
            </div>

            <!-- Tab Buttons -->
            <div class="flex justify-center mb-6 bg-slate-900 p-1.5 rounded-xl border border-slate-800 w-fit mx-auto shadow-lg">
                <button id="tabUsername" onclick="switchTab('username')" class="px-5 py-2.5 rounded-lg text-sm font-medium transition-all bg-indigo-600 text-white flex items-center gap-2">
                    <i class="fa-solid fa-at"></i> Kullanıcı Adı
                </button>
                <button id="tabImage" onclick="switchTab('image')" class="px-5 py-2.5 rounded-lg text-sm font-medium transition-all text-slate-400 hover:text-white flex items-center gap-2">
                    <i class="fa-solid fa-camera"></i> Yüz / Görsel OSINT
                </button>
            </div>

            <!-- 1. TAB: USERNAME SEARCH -->
            <div id="usernameSection">
                <form id="searchForm" class="bg-slate-900/80 p-2 rounded-2xl border border-slate-800 flex gap-2 mb-6 shadow-xl backdrop-blur-md">
                    <div class="relative flex-1">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-4 pointer-events-none text-slate-500">
                            <i class="fa-solid fa-magnifying-glass"></i>
                        </span>
                        <input type="text" id="usernameInput" placeholder="Hedef kullanıcı adı (örn: torvalds)" required autocomplete="off"
                            class="w-full bg-transparent pl-10 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none text-sm sm:text-base">
                    </div>
                    <button type="submit" id="submitBtn"
                        class="bg-indigo-600 hover:bg-indigo-500 font-medium px-6 py-3 rounded-xl transition-all flex items-center gap-2 text-sm sm:text-base shadow-lg shadow-indigo-600/30">
                        <span>Tara</span>
                        <i class="fa-solid fa-bolt text-xs"></i>
                    </button>
                </form>

                <div id="statsSection" class="hidden mb-6 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg">
                    <div class="flex justify-between items-center text-xs font-semibold text-slate-400 mb-2">
                        <span id="statusText">İz sürülüyor...</span>
                        <span id="progressText">0%</span>
                    </div>
                    <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div id="progressBar" class="bg-indigo-500 h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
                    </div>
                    <div class="flex items-center justify-between mt-4 pt-3 border-t border-slate-800/80 text-xs">
                        <div class="flex gap-4">
                            <span class="text-slate-400">Aktif Profil: <strong id="foundCount" class="text-emerald-400">0</strong></span>
                            <span class="text-slate-400">Kayıtsız: <strong id="notFoundCount" class="text-slate-300">0</strong></span>
                        </div>
                        <div class="flex gap-2">
                            <button id="filterBtn" class="bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg text-slate-300 transition-colors">
                                Sadece Bulunanlar
                            </button>
                            <button id="exportBtn" class="bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg text-slate-300 transition-colors hidden">
                                <i class="fa-solid fa-file-arrow-down mr-1"></i> CSV İndir
                            </button>
                        </div>
                    </div>
                </div>

                <div id="results" class="grid grid-cols-1 sm:grid-cols-2 gap-3"></div>
            </div>

            <!-- 2. TAB: IMAGE / FACE SEARCH -->
            <div id="imageSection" class="hidden">
                <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 mb-6 text-center shadow-xl backdrop-blur-md">
                    <input type="file" id="imageInput" accept="image/*" class="hidden">
                    <div id="dropZone" onclick="document.getElementById('imageInput').click()" 
                        class="border-2 border-dashed border-slate-700 hover:border-indigo-500 rounded-xl p-8 cursor-pointer transition-colors flex flex-col items-center justify-center">
                        <i class="fa-solid fa-expand text-4xl text-indigo-400 mb-3"></i>
                        <p class="text-slate-200 font-medium mb-1">Fotoğraf seçin veya sürükleyin</p>
                        <p class="text-slate-500 text-xs">Yüz algılama ve EXIF meta analizi otomatik uygulanır</p>
                    </div>

                    <div id="previewContainer" class="hidden mt-4 flex flex-col items-center">
                        <img id="imagePreview" src="" class="h-44 rounded-xl object-cover border border-slate-700 mb-3 shadow-lg">
                        <button id="imageSearchBtn" onclick="submitImageSearch()"
                            class="bg-indigo-600 hover:bg-indigo-500 px-6 py-2.5 rounded-xl font-medium text-sm flex items-center gap-2 transition-all shadow-lg shadow-indigo-600/30">
                            <span>Analiz Et ve Ağları Tara</span>
                            <i class="fa-solid fa-radar"></i>
                        </button>
                    </div>
                </div>

                <div id="imageSearchStatus" class="hidden text-center text-sm font-medium text-indigo-400 mb-4 animate-pulse">
                    <i class="fa-solid fa-spinner fa-spin mr-2"></i> Yüz odaklanıyor, meta veriler çıkarılıyor ve ağlar taranıyor...
                </div>

                <!-- EXIF Meta Bilgi Kartı -->
                <div id="metadataCard" class="hidden mb-6 bg-slate-900/90 border border-indigo-500/30 rounded-xl p-4 text-xs">
                    <div class="flex items-center gap-2 text-indigo-400 font-semibold mb-2 border-b border-slate-800 pb-2">
                        <i class="fa-solid fa-circle-info"></i> Fotoğraf Meta Veri Analizi (EXIF)
                    </div>
                    <div id="metadataContent" class="grid grid-cols-2 sm:grid-cols-3 gap-2 text-slate-300"></div>
                </div>

                <div id="imageResults" class="grid grid-cols-1 sm:grid-cols-2 gap-3"></div>
            </div>

            <!-- Footer -->
            <div class="text-center mt-12 text-xs text-slate-600">
                TraceSpect OSINT Platform &copy; 2026 — Açık Kaynak Dijital İstihbarat Aracı
            </div>

        </div>

        <script>
            function switchTab(tab) {
                const isUser = tab === 'username';
                document.getElementById('usernameSection').classList.toggle('hidden', !isUser);
                document.getElementById('imageSection').classList.toggle('hidden', isUser);
                
                document.getElementById('tabUsername').className = isUser 
                    ? 'px-5 py-2.5 rounded-lg text-sm font-medium transition-all bg-indigo-600 text-white flex items-center gap-2'
                    : 'px-5 py-2.5 rounded-lg text-sm font-medium transition-all text-slate-400 hover:text-white flex items-center gap-2';
                
                document.getElementById('tabImage').className = !isUser 
                    ? 'px-5 py-2.5 rounded-lg text-sm font-medium transition-all bg-indigo-600 text-white flex items-center gap-2'
                    : 'px-5 py-2.5 rounded-lg text-sm font-medium transition-all text-slate-400 hover:text-white flex items-center gap-2';
            }

            // USERNAME SCRIPT
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
            const exportBtn = document.getElementById('exportBtn');

            let foundCount = 0, notFoundCount = 0, currentResults = [], onlyFoundFilter = false, activeEventSource = null;

            filterBtn.addEventListener('click', () => {
                onlyFoundFilter = !onlyFoundFilter;
                filterBtn.innerText = onlyFoundFilter ? 'Tümünü Göster' : 'Sadece Bulunanlar';
                filterBtn.classList.toggle('bg-indigo-600', onlyFoundFilter);
                document.querySelectorAll('.result-card').forEach(card => {
                    card.classList.toggle('hidden', onlyFoundFilter && card.dataset.found === 'false');
                });
            });

            exportBtn.addEventListener('click', () => {
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

            form.addEventListener('submit', (e) => {
                e.preventDefault();
                const username = input.value.trim();
                if (!username) return;
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
                exportBtn.classList.add('hidden');
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
                        data.found ? 'bg-emerald-950/20 border-emerald-500/30' : 'bg-slate-900 border-slate-800 opacity-60'
                    } ${onlyFoundFilter && !data.found ? 'hidden' : ''}`;

                    card.innerHTML = `
                        <div class="overflow-hidden mr-2">
                            <p class="font-semibold text-white truncate text-sm">${data.platform}</p>
                            ${data.found ? `<a href="${data.url}" target="_blank" class="text-xs text-indigo-400 hover:text-indigo-300 truncate block mt-0.5"><i class="fa-solid fa-arrow-up-right-from-square mr-1"></i>Profili Aç</a>` : '<span class="text-xs text-slate-500">Profil Yok / Boşta</span>'}
                        </div>
                        <div>
                            ${data.found ? '<span class="text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2.5 py-1 rounded-full font-medium">Aktif</span>' : '<span class="text-[11px] bg-slate-800 text-slate-400 px-2.5 py-1 rounded-full">Boş</span>'}
                        </div>
                    `;
                    resultsDiv.appendChild(card);
                });

                activeEventSource.addEventListener('done', () => {
                    statusText.innerText = 'Tarama tamamlandı.';
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('opacity-50');
                    if (foundCount > 0) exportBtn.classList.remove('hidden');
                    activeEventSource.close();
                });

                activeEventSource.onerror = () => {
                    statusText.innerText = 'İşlem tamamlandı.';
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('opacity-50');
                    activeEventSource.close();
                };
            });

            // IMAGE SCRIPT
            const imageInput = document.getElementById('imageInput');
            const previewContainer = document.getElementById('previewContainer');
            const imagePreview = document.getElementById('imagePreview');
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
                        previewContainer.classList.remove('hidden');
                    };
                    reader.readAsDataURL(file);
                }
            });

            async function submitImageSearch() {
                const file = imageInput.files[0];
                if (!file) return;

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

                    // Metadata kartını doldur
                    if (data.metadata && Object.keys(data.metadata).length > 0) {
                        metadataCard.classList.remove('hidden');
                        for (const [k, v] of Object.entries(data.metadata)) {
                            metadataContent.innerHTML += `<div class="bg-slate-950/60 p-2 rounded border border-slate-800"><span class="text-slate-500 block text-[10px]">${k}</span><strong class="text-white">${v}</strong></div>`;
                        }
                        if (data.face_detected) {
                            metadataContent.innerHTML += `<div class="bg-indigo-950/40 p-2 rounded border border-indigo-500/30 col-span-2 sm:col-span-3 text-indigo-300"><i class="fa-solid fa-user-check mr-1"></i> Yüz başarıyla algılandı ve odaklanarak tarandı.</div>`;
                        }
                    }

                    if (data.matches.length === 0) {
                        imageResults.innerHTML = '<div class="col-span-2 text-center text-slate-500 py-6">Bu fotoğrafa ait internette eşleşen bir profil veya kaynak bulunamadı.</div>';
                        return;
                    }

                    data.matches.forEach(item => {
                        const card = document.createElement('div');
                        card.className = 'bg-slate-900 border border-slate-800 hover:border-indigo-500/50 p-4 rounded-xl flex gap-3 items-center transition-all shadow-md';
                        card.innerHTML = `
                            ${item.thumbnail ? `<img src="${item.thumbnail}" class="w-14 h-14 rounded-lg object-cover bg-slate-800 flex-shrink-0">` : '<div class="w-14 h-14 rounded-lg bg-slate-800 flex items-center justify-center text-slate-600"><i class="fa-solid fa-image"></i></div>'}
                            <div class="overflow-hidden flex-1">
                                <div class="flex items-center gap-1.5 mb-1">
                                    <span class="text-[10px] px-2 py-0.5 rounded-full border font-medium flex items-center gap-1 ${item.color}">
                                        <i class="${item.icon}"></i> ${item.platform}
                                    </span>
                                </div>
                                <p class="text-white text-xs font-semibold truncate mb-0.5">${item.title}</p>
                                <a href="${item.link}" target="_blank" class="text-xs text-indigo-400 hover:underline inline-block">Bağlantıyı Aç &rarr;</a>
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