from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

CRITICAL_MESSAGE = (
    "Our AI trading bot guarantees 40% returns every month with ZERO risk. "
    "Send $500 in USDT to the wallet below and don't tell your bank."
)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_returns_the_frontend_contract():
    response = client.post(
        "/analyze",
        json={"message": CRITICAL_MESSAGE, "url": "https://vip-crypto-returns.example/join"},
    )
    assert response.status_code == 200
    body = response.json()

    assert isinstance(body["risk_score"], int)
    assert 0 <= body["risk_score"] <= 100
    assert body["risk_level"] == "critical"
    assert isinstance(body["warnings"], list) and body["warnings"]
    warning = body["warnings"][0]
    assert isinstance(warning["title"], str) and warning["title"]
    assert warning["severity"] in {"low", "medium", "high", "critical"}
    assert isinstance(warning["evidence"], list)


def test_url_is_optional_and_null_is_accepted():
    response = client.post("/analyze", json={"message": "Hello there.", "url": None})
    assert response.status_code == 200
    assert response.json()["risk_level"] == "low"


def test_empty_message_is_rejected():
    response = client.post("/analyze", json={"message": "   ", "url": None})
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)


def test_unsupported_url_scheme_is_rejected():
    response = client.post(
        "/analyze",
        json={"message": "Check this out.", "url": "ftp://example.com/file"},
    )
    assert response.status_code == 422


def test_message_over_limit_is_rejected():
    response = client.post("/analyze", json={"message": "a" * 5001})
    assert response.status_code == 422


def test_oversized_body_is_rejected_before_parsing():
    response = client.post("/analyze", content=b"{" + b"a" * 40_000 + b"}")
    assert response.status_code == 413


def test_cors_preflight_for_a_separate_frontend_origin():
    response = client.options(
        "/analyze",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_response_has_request_id():
    response = client.post("/analyze", json={"message": "Hello there."})
    assert response.headers["x-request-id"]
