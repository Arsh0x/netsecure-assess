import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEST_DB = Path(__file__).parent / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["DEMO_MODE"] = "true"
os.environ["SECRET_KEY"] = "test-secret-that-is-long-and-not-for-production"

from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def researcher_headers(client: TestClient):
    response = client.post("/api/auth/login", json={"email":"researcher@netsecure.local","password":"ResearchDemo!2026"})
    assert response.status_code == 200
    return {"Authorization":f"Bearer {response.json()['access_token']}"}

