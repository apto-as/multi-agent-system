"""
Basic health check tests for TMWS.
"""


def test_health_check(client):
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "tmws-mcp-api"
    assert "version" in data


def test_database_connection(client):
    """Test database connectivity through detailed health endpoint."""
    response = client.get("/api/v1/health/detailed")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded", "unhealthy"]
    assert "components" in data
    assert "database" in data["components"]
    assert data["components"]["database"]["status"] in ["healthy", "unhealthy"]
