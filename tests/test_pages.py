import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.modules import feedback as feedback_module

client = TestClient(app)


@pytest.fixture
def temp_feedback_file(tmp_path, monkeypatch):
    path = tmp_path / "feedback.json"
    monkeypatch.setattr(feedback_module, "FEEDBACK_FILE", path)
    return path


class TestNewPagesReturn200:
    @pytest.mark.parametrize(
        "path",
        ["/how-it-works", "/about", "/changelog", "/feedback"],
    )
    def test_page_returns_200(self, path):
        response = client.get(path)
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_how_it_works_mentions_key_data_sources(self):
        body = client.get("/how-it-works").text
        for term in ["URLhaus", "OpenPhish", "Spamhaus", "domain age", "SSL"]:
            assert term.lower() in body.lower()

    def test_about_mentions_limitations_and_take_five(self):
        body = client.get("/about").text
        assert "take five" in body.lower()
        assert "own judgement" in body.lower() or "own judgment" in body.lower()

    def test_changelog_mentions_initial_launch(self):
        body = client.get("/changelog").text
        assert "initial launch" in body.lower()

    def test_feedback_page_has_a_form(self):
        body = client.get("/feedback").text
        assert "<form" in body.lower()
        assert 'name="message"' in body

    def test_navigation_links_present_on_homepage(self):
        body = client.get("/").text
        for path in ["/how-it-works", "/about", "/changelog", "/feedback"]:
            assert f'href="{path}"' in body


class TestFeedbackSubmission:
    def test_submitting_feedback_writes_to_json_log(self, temp_feedback_file):
        response = client.post(
            "/feedback",
            data={"name": "Jane", "email": "jane@example.com", "message": "This link was wrongly flagged."},
        )
        assert response.status_code == 200
        assert "thank you" in response.text.lower()

        entries = json.loads(temp_feedback_file.read_text())
        assert len(entries) == 1
        assert entries[0]["name"] == "Jane"
        assert entries[0]["email"] == "jane@example.com"
        assert entries[0]["message"] == "This link was wrongly flagged."
        assert "submitted_at" in entries[0]

    def test_submitting_feedback_without_name_or_email_still_works(self, temp_feedback_file):
        response = client.post("/feedback", data={"message": "A false negative on a scam link."})
        assert response.status_code == 200

        entries = json.loads(temp_feedback_file.read_text())
        assert len(entries) == 1
        assert entries[0]["name"] == ""
        assert entries[0]["email"] == ""

    def test_multiple_submissions_append_rather_than_overwrite(self, temp_feedback_file):
        client.post("/feedback", data={"message": "First report."})
        client.post("/feedback", data={"message": "Second report."})

        entries = json.loads(temp_feedback_file.read_text())
        assert len(entries) == 2
        assert entries[0]["message"] == "First report."
        assert entries[1]["message"] == "Second report."

    def test_empty_message_is_rejected_and_not_written(self, temp_feedback_file):
        response = client.post("/feedback", data={"name": "Jane", "message": "   "})
        assert response.status_code == 200
        assert "please describe" in response.text.lower()
        assert not temp_feedback_file.exists()
