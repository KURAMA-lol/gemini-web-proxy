import os, json, hmac
from http.cookies import SimpleCookie
from playwright.async_api import async_playwright
import server

browser = None

def parse_gemini_cookies(raw):
    raw = raw.strip()
    if not raw:
        return []
    cookies = []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("cookies", data.get("data", []))
        if isinstance(data, list):
            for item in data:
                domain = str(item.get("domain") or ".google.com").lower()
                if "google.com" not in domain:
                    continue
                c = {"name": str(item["name"]), "value": str(item["value"]),
                     "domain": domain if domain.startswith(".") else "." + domain,
                     "path": item.get("path") or "/", "secure": bool(item.get("secure", True)),
                     "httpOnly": bool(item.get("httpOnly", item.get("httponly", False)))}
                same = item.get("sameSite")
                if same in ("Strict", "Lax", "None"):
                    c["sameSite"] = same
                expiry = item.get("expires", item.get("expirationDate"))
                if expiry and float(expiry) > 0:
                    c["expires"] = float(expiry)
                cookies.append(c)
            return cookies
    except (ValueError, TypeError, KeyError):
        pass

    for line in raw.splitlines():
        line = line.strip()
        if not line or (line.startswith("#") and not line.startswith("#HttpOnly_")):
            continue
        http_only = line.startswith("#HttpOnly_")
        if http_only:
            line = line[len("#HttpOnly_"):]
        parts = line.split("\t")
        if len(parts) >= 7:
            domain, _, path, secure, expiry, name, value = parts[:7]
            if "google.com" not in domain.lower():
                continue
            c = {"name": name, "value": value, "domain": domain.lower(),
                 "path": path or "/", "secure": secure.upper() == "TRUE", "httpOnly": http_only}
            if expiry.isdigit() and int(expiry) > 0:
                c["expires"] = int(expiry)
            cookies.append(c)
    if cookies:
        return cookies

    jar = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:
        pass
    for name, morsel in jar.items():
        cookies.append({"name": name, "value": morsel.value, "domain": ".google.com",
                        "path": "/", "secure": True, "httpOnly": False})
    return cookies

async def render_init_browser():
    global browser
    cookies = parse_gemini_cookies(os.getenv("GEMINI_COOKIES", ""))
    if not cookies:
        server.is_ready = False
        print("Gemini session not configured. Set GEMINI_COOKIES in Render environment.")
        return
    server.playwright_instance = await async_playwright().start()
    browser = await server.playwright_instance.chromium.launch(
        headless=True, args=["--no-sandbox", "--disable-dev-shm-usage",
        "--disable-blink-features=AutomationControlled"])
    server.context = await browser.new_context(viewport={"width": 1280, "height": 900})
    await server.context.add_cookies(cookies)
    page = await server.context.new_page()
    await page.goto("https://gemini.google.com/app", wait_until="domcontentloaded", timeout=90000)
    try:
        await page.wait_for_selector("rich-textarea", timeout=60000)
        server.is_ready = True
        print("Gemini Web session initialized.")
    except Exception:
        server.is_ready = False
        print("Gemini session did not authenticate. Check cookie format or expiration.")
    finally:
        await page.close()

server.init_browser = render_init_browser

@server.app.middleware("http")
async def require_api_key(request, call_next):
    if request.url.path == "/health" or request.method == "OPTIONS":
        return await call_next(request)
    expected = os.getenv("API_KEY", "")
    supplied = request.headers.get("authorization", "")
    token = supplied[7:].strip() if supplied.lower().startswith("bearer ") else ""
    if not expected or not token or not hmac.compare_digest(token, expected):
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": {"message": "Invalid or missing API key", "type": "authentication_error"}}, status_code=401)
    return await call_next(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.app, host="0.0.0.0", port=int(os.getenv("PORT", "10000")), log_level="info")
