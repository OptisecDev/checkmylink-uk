from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.modules.feedback import save_feedback
from app.modules.scan_engine import scan_message
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

    result = scan_message(link)
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


@app.get("/how-it-works", response_class=HTMLResponse)
def how_it_works(request: Request):
    return templates.TemplateResponse("how_it_works.html", {"request": request})


@app.get("/about", response_class=HTMLResponse)
def about(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})


@app.get("/changelog", response_class=HTMLResponse)
def changelog(request: Request):
    return templates.TemplateResponse("changelog.html", {"request": request})


@app.get("/feedback", response_class=HTMLResponse)
def feedback_form(request: Request):
    return templates.TemplateResponse("feedback.html", {"request": request})


@app.post("/feedback", response_class=HTMLResponse)
def feedback_submit(
    request: Request,
    name: str = Form(""),
    email: str = Form(""),
    message: str = Form(...),
):
    name = (name or "").strip()
    email = (email or "").strip()
    message = (message or "").strip()

    if not message:
        return templates.TemplateResponse(
            "feedback.html",
            {
                "request": request,
                "error": "Please describe the issue before sending.",
                "name": name,
                "email": email,
            },
        )

    save_feedback(name=name, email=email, message=message)
    return templates.TemplateResponse(
        "feedback.html",
        {"request": request, "success": True},
    )


@app.get("/health")
def health():
    return {"status": "ok"}
