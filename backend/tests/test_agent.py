"""Tests for AI Agent planner, reasoning loop, dedup guard, and anti-hallucination validator."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.agent.client import AgentResponse, MockLLMClient, ToolCall
from app.agent.orchestrator import AgentOrchestrator
from app.agent.validation import validate_grounding
from app.db import create_database_engine, create_session_factory, initialize_database
from app.main import create_app
from app.models.schemas import AssessmentCreate
from app.repo.assessments import create_assessment
from app.scope.engine import register_scope
from app.scope.models import ScopeRules
from app.settings import Settings


@pytest.fixture
def test_env(tmp_path: Path):
    settings = Settings(
        _env_file=None,
        db_url=f"sqlite:///{tmp_path / 'agent.db'}",
        data_dir=tmp_path / "data",
        lab_cidr="172.30.0.0/24",
    )
    engine = create_database_engine(settings)
    initialize_database(engine)
    sessions = create_session_factory(engine)
    return settings, engine, sessions


def test_agent_propose_plan_with_rationales(test_env):
    """Agent outputs a structured plan with rationales for each step."""
    settings, engine, sessions = test_env
    mock_llm = MockLLMClient()
    orchestrator = AgentOrchestrator(client=mock_llm, settings=settings)

    # Queue mock response proposing a 2-step plan
    mock_llm.queue_response(
        AgentResponse(
            content="[INFERENCE] I propose an initial discovery and service scan plan.",
            tool_calls=[
                ToolCall(
                    id="call_1",
                    name="propose_plan",
                    arguments={
                        "title": "Lab Assessment Plan",
                        "steps": [
                            {
                                "action": "nmap",
                                "target": "172.30.0.10",
                                "rationale": "Discover active hosts and open TCP ports.",
                                "arguments": {"top_ports": 100},
                            },
                            {
                                "action": "zap",
                                "target": "http://172.30.0.10",
                                "rationale": "Passive web vulnerability crawl on HTTP service.",
                                "arguments": {},
                            },
                        ],
                    },
                )
            ],
        )
    )

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Plan Test"))
        resp, hallucinations = asyncio.run(
            orchestrator.run_turn(
                session=session,
                assessment_id=assessment.id,
                user_message="Assess 172.30.0.10",
            )
        )

    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].name == "propose_plan"
    assert hallucinations == []
    assert (
        len(orchestrator.get_state(assessment.id).completed_steps) == 0
    )  # plan is proposed, not executed yet


def test_dedup_guard_prevents_redundant_scans(test_env):
    """Duplicate step guard prevents running identical (tool, target) twice
    and increments avoided_repeats.
    """
    settings, engine, sessions = test_env
    mock_llm = MockLLMClient()
    orchestrator = AgentOrchestrator(client=mock_llm, settings=settings)

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Dedup Test"))
        register_scope(
            session,
            assessment.id,
            ScopeRules(
                allowed_targets=["172.30.0.10"],
                allowed_tools=["nmap"],
                allowed_action_classes=["discovery"],
            ),
            settings=settings,
        )

    # First turn: calls run_nmap
    mock_llm.queue_response(
        AgentResponse(
            content="Running initial Nmap scan.",
            tool_calls=[
                ToolCall(
                    id="call_1",
                    name="run_nmap",
                    arguments={"target": "172.30.0.10", "top_ports": 100},
                )
            ],
        )
    )
    # Second turn: attempts identical run_nmap call
    mock_llm.queue_response(
        AgentResponse(
            content="Running Nmap again.",
            tool_calls=[
                ToolCall(
                    id="call_2",
                    name="run_nmap",
                    arguments={"target": "172.30.0.10", "top_ports": 100},
                )
            ],
        )
    )

    # Mock the adapter execution inside execute_agent_tool so it doesn't fail on network
    from unittest.mock import AsyncMock, patch

    from app.adapters.nmap import NmapAdapter

    with patch.object(NmapAdapter, "execute", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = (
            Path(__file__).parent / "fixtures" / "nmap_sample.xml"
        ).read_bytes()

        with sessions.begin() as session:
            # Turn 1
            asyncio.run(
                orchestrator.run_turn(
                    session=session,
                    assessment_id=assessment.id,
                    user_message="Scan target",
                )
            )

        state = orchestrator.get_state(assessment.id)
        assert len(state.executed_scans) == 1
        assert state.avoided_repeats == 0

        with sessions.begin() as session:
            # Turn 2: Attempt duplicate
            asyncio.run(
                orchestrator.run_turn(
                    session=session,
                    assessment_id=assessment.id,
                    user_message="Scan target again",
                )
            )

        # Dedup guard must have triggered!
        assert state.avoided_repeats == 1


def test_anti_hallucination_validator(test_env):
    """Validator catches and strips fabricated CVEs not present in assessment findings."""
    settings, engine, sessions = test_env

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Hallucination Test"))

    text_with_hallucination = (
        "We observed severe vulnerability CVE-2099-9999 and CWE-9999 in the web service."
    )

    with sessions() as session:
        cleaned, hallucinations = validate_grounding(
            session=session,
            assessment_id=assessment.id,
            text=text_with_hallucination,
        )

    assert "CVE-2099-9999" in hallucinations
    assert "CWE-9999" in hallucinations
    assert "UNGROUNDED_CLAIM" in cleaned


def test_agent_chat_api(test_env):
    """Test POST /assessments/{id}/chat endpoint."""
    settings, engine, sessions = test_env
    app = create_app(settings=settings, engine=engine)

    with sessions.begin() as session:
        assessment = create_assessment(session, AssessmentCreate(name="Chat API Test"))

    with TestClient(app) as client:
        resp = client.post(
            f"/assessments/{assessment.id}/chat",
            json={"message": "Hello agent, what is in scope?"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "content" in data
        assert "tool_calls" in data
        assert data["avoided_repeats"] == 0
