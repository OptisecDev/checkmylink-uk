from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.modules.scan_engine import scan_url
from app.modules.stats import get_stats, record_scan

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="CheckMyLink UK")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    stats = get_stats()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "stats": stats},
    )


@app.post("/check", response_class=HTMLResponse)
def check(request: Request, link: str = Form(...)):
    link = (link or "").strip()

    if not link:
        stats = get_stats()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "stats": stats, "error": "Please paste a link before checking."},
        )

    result = scan_url(link)
    stats = record_scan(result.verdict)

    verdict_display = {
        "SAFE": {"label": "Looks Safe", "colour": "safe"},
        "CAUTION": {"label": "Use Caution", "colour": "caution"},
        "DANGER": {"label": "Danger", "colour": "danger"},
    }[result.verdict]

    return templates.TemplateResponse(
        "result.html",
        {
            "request": request,
            "result": result,
            "verdict_display": verdict_display,
            "stats": stats,
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}
