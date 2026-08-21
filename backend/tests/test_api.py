from fastapi.testclient import TestClient


def test_login_and_dashboard(client: TestClient, researcher_headers: dict):
    response = client.get("/api/dashboard", headers=researcher_headers)
    assert response.status_code == 200
    assert response.json()["metrics"]["assets"] >= 4


def test_scan_requires_consent(client: TestClient, researcher_headers: dict):
    project = client.get("/api/projects", headers=researcher_headers).json()[0]
    response = client.post("/api/scans", headers=researcher_headers, json={
        "project_id":project["id"],"target":"10.20.0.12","profile":"common_services",
        "purpose":"Authorized classroom baseline","approved_scope":project["scope"],
        "authorization_confirmed":False,"policy_accepted":True,"demo":True,
    })
    assert response.status_code == 422


def test_public_scan_is_rejected(client: TestClient, researcher_headers: dict):
    project = client.get("/api/projects", headers=researcher_headers).json()[0]
    response = client.post("/api/scans", headers=researcher_headers, json={
        "project_id":project["id"],"target":"8.8.8.8","profile":"common_services",
        "purpose":"This should never be allowed","approved_scope":project["scope"],
        "authorization_confirmed":True,"policy_accepted":True,"demo":False,
    })
    assert response.status_code == 422


def test_student_cannot_read_admin_audit(client: TestClient):
    login = client.post("/api/auth/login", json={"email":"student@netsecure.local","password":"StudentDemo!2026"}).json()
    response = client.get("/api/audit-logs", headers={"Authorization":f"Bearer {login['access_token']}"})
    assert response.status_code == 403


def test_pdf_report_contains_validation_statement(client: TestClient, researcher_headers: dict):
    project = client.get("/api/projects", headers=researcher_headers).json()[0]
    created = client.post("/api/reports", headers=researcher_headers, json={"project_id":project["id"],"report_type":"executive","format":"pdf"})
    assert created.status_code == 201
    download = client.get(f"/api/reports/{created.json()['id']}/download", headers=researcher_headers)
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/pdf"
    assert download.content.startswith(b"%PDF")
