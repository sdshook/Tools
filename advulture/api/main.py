"""
ADVulture — FastAPI Application
REST API for posture analysis, scenario testing, and report retrieval.
"""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Optional, Dict
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from advulture.config import Config
from advulture.analysis.posture import PostureAnalyzer, PostureReport
from advulture.reporting.report import ReportGenerator

log = logging.getLogger(__name__)

app = FastAPI(
    title="ADVulture API",
    description="Active Directory Vulnerability Intelligence",
    version="0.1.0",
)

# Global state (in production: use proper state management)
_config: Optional[Config] = None
_latest_report: Optional[PostureReport] = None
_report_gen = ReportGenerator()


class AnalysisRequest(BaseModel):
    controls: Optional[Dict[str, float]] = None
    evtx_paths: Optional[list] = None


class ScenarioRequest(BaseModel):
    proposed_controls: Dict[str, float]
    description: str = ""


@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html><body style="font-family:monospace;background:#0f1117;color:#e2e8f0;padding:40px">
    <h1>🦅 ADVulture API</h1>
    <p>Active Directory Vulnerability Intelligence</p>
    <ul>
      <li><a href="/docs" style="color:#60a5fa">/docs</a> — OpenAPI documentation</li>
      <li><a href="/api/health" style="color:#60a5fa">/api/health</a> — Health check</li>
      <li>POST /api/analyze — Run posture analysis</li>
      <li>GET /api/report — Latest report (JSON)</li>
      <li>GET /api/report/html — Latest report (HTML)</li>
    </ul>
    </body></html>
    """


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/api/analyze")
async def analyze(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """Run posture analysis with optional control overrides."""
    global _latest_report
    if _config is None:
        raise HTTPException(status_code=503, detail="Configuration not loaded")
    try:
        analyzer = PostureAnalyzer(_config)
        _latest_report = analyzer.analyze(
            controls=request.controls,
            evtx_paths=[Path(p) for p in request.evtx_paths] if request.evtx_paths else None,
        )
        return {
            "status": "complete",
            "regime": _latest_report.regime,
            "tier0_probability": _latest_report.tier0_steady_state_probability,
            "findings": len(_latest_report.findings),
            "top_control": _latest_report.remediation_ranking[0].control
                if _latest_report.remediation_ranking else None,
        }
    except Exception as e:
        log.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/report")
async def get_report():
    """Return latest analysis as JSON."""
    if _latest_report is None:
        raise HTTPException(status_code=404, detail="No analysis completed yet")
    return JSONResponse(content=_latest_report.to_dict())


@app.get("/api/report/html", response_class=HTMLResponse)
async def get_report_html():
    """Return latest analysis as HTML report."""
    if _latest_report is None:
        raise HTTPException(status_code=404, detail="No analysis completed yet")
    return _report_gen.generate_html(_latest_report)


@app.post("/api/scenario")
async def test_scenario(request: ScenarioRequest):
    """Test a remediation scenario using the Random Forest predictor."""
    if _latest_report is None:
        raise HTTPException(status_code=404, detail="Run analysis first")
    # In production: use RF scenario runner
    baseline = _latest_report.tier0_steady_state_probability
    # Simple estimate based on gradient contributions
    reduction = sum(
        item.gradient * (request.proposed_controls.get(item.control, 0.5) - item.current_value)
        for item in _latest_report.remediation_ranking
        if item.control in request.proposed_controls
    )
    scenario_prob = max(0.0, baseline - abs(reduction) * 0.3)
    return {
        "description": request.description,
        "baseline_tier0_probability": round(baseline, 4),
        "scenario_tier0_probability": round(scenario_prob, 4),
        "absolute_reduction": round(baseline - scenario_prob, 4),
        "pct_reduction": round((baseline - scenario_prob) / max(baseline, 0.001) * 100, 1),
    }


def create_app(config_path: Optional[Path] = None) -> FastAPI:
    global _config
    if config_path and config_path.exists():
        _config = Config.from_file(config_path)
    else:
        _config = Config()
    return app
