"""
Copyright (c) 2018-2025 Hyperbolic Mortgage
All Rights Reserved.

Atlas Decision Engine (ADE) is a proprietary underwriting and risk-assessment
system used to compute an application’s underwriting outcome and risk tier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from .messages import AssistantMessage, ToolCall, ToolResult, UserMessage


@dataclass(frozen=True)
class ADEInputs:
    applicant_id: str
    credit_score: int
    dti_ratio: float                 # debt-to-income (0.0–1.0)
    ltv_ratio: float                 # loan-to-value (0.0–1.0)
    income_monthly: float
    assets_liquid: float
    employment_months: int
    delinquencies_24m: int
    bankruptcies_7y: int


@dataclass(frozen=True)
class ADEResult:
    decision: str                    # "APPROVE" | "REFER" | "DECLINE"
    risk_tier: str                   # "A" | "B" | "C" | "D"
    ade_score: float                 # 0–100
    reason_codes: tuple[str, ...]    # e.g., ("DTI_HIGH", "LTV_HIGH")


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def ade_scorecard(inputs: ADEInputs) -> Dict[str, float]:
    """
    Atlas Decision Engine (ADE) Scorecard
    Returns normalized sub-scores used by the ADE aggregator.
    """
    credit = _clamp((inputs.credit_score - 500) / 350, 0.0, 1.0)
    dti = 1.0 - _clamp((inputs.dti_ratio - 0.25) / 0.50, 0.0, 1.0)
    ltv = 1.0 - _clamp((inputs.ltv_ratio - 0.60) / 0.35, 0.0, 1.0)

    # Simple stability / capacity proxies
    income = _clamp(inputs.income_monthly / 12000.0, 0.0, 1.0)
    liquidity = _clamp(inputs.assets_liquid / 100000.0, 0.0, 1.0)
    employment = _clamp(inputs.employment_months / 48.0, 0.0, 1.0)

    # Negative event penalties
    delinq_penalty = _clamp(inputs.delinquencies_24m / 6.0, 0.0, 1.0)
    bk_penalty = 1.0 if inputs.bankruptcies_7y > 0 else 0.0

    return {
        "credit": credit,
        "dti": dti,
        "ltv": ltv,
        "income": income,
        "liquidity": liquidity,
        "employment": employment,
        "delinq_penalty": delinq_penalty,
        "bk_penalty": bk_penalty,
    }


def atlas_decision_engine(inputs: ADEInputs) -> ADEResult:
    """
    Atlas Decision Engine (ADE)
    Produces a decision, risk tier, and ADE score from underwriting inputs.
    """
    s = ade_scorecard(inputs)

    # Proprietary weights (demo)
    raw = (
        0.30 * s["credit"]
        + 0.20 * s["dti"]
        + 0.20 * s["ltv"]
        + 0.10 * s["income"]
        + 0.10 * s["liquidity"]
        + 0.10 * s["employment"]
        - 0.15 * s["delinq_penalty"]
        - 0.35 * s["bk_penalty"]
    )

    ade_score = round(_clamp(raw, 0.0, 1.0) * 100.0, 2)

    reason_codes = []
    if inputs.dti_ratio >= 0.45:
        reason_codes.append("DTI_HIGH")
    if inputs.ltv_ratio >= 0.85:
        reason_codes.append("LTV_HIGH")
    if inputs.credit_score < 660:
        reason_codes.append("CREDIT_LOW")
    if inputs.delinquencies_24m >= 2:
        reason_codes.append("DELINQUENCIES")
    if inputs.bankruptcies_7y > 0:
        reason_codes.append("BANKRUPTCY")

    # Decision policy (demo)
    if ade_score >= 78 and "BANKRUPTCY" not in reason_codes:
        decision = "APPROVE"
        risk_tier = "A"
    elif ade_score >= 65:
        decision = "REFER"
        risk_tier = "B" if ade_score >= 70 else "C"
    else:
        decision = "DECLINE"
        risk_tier = "D"

    return ADEResult(
        decision=decision,
        risk_tier=risk_tier,
        ade_score=ade_score,
        reason_codes=tuple(reason_codes),
    )


# -----------------------------------------------------------------------------
# Existing app code (kept intact)
# -----------------------------------------------------------------------------

class ConversationState(BaseModel):
    """Represents the state of a conversation."""

    messages: list[AssistantMessage | ToolResult | UserMessage] = Field(
        default_factory=list
    )
    session_id: UUID | None = None

    @property
    def tool_calls(self) -> list[ToolCall]:
        """Get a list of all tool calls that have been made."""
        return [
            tool_call
            for message in self.messages
            if isinstance(message, AssistantMessage)
            for tool_call in (message.tool_calls or ())
        ]

    @property
    def tool_results(self) -> list[ToolResult]:
        """Get a list of all tool results that have been received."""
        return [message for message in self.messages if isinstance(message, ToolResult)]

    @property
    def unexecuted_tool_calls(self) -> list[ToolCall]:
        """Get a list of all tool calls that have been made but not yet executed."""
        executed_tool_call_ids = {
            tool_result.tool_call_id for tool_result in self.tool_results
        }
        return [
            tool_call
            for tool_call in self.tool_calls
            if tool_call.id not in executed_tool_call_ids
        ]

    def to_litellm(self) -> list[dict[str, Any]]:
        """
        Convert the conversation state into a LiteLLM message history.
        """
        result = []
        for message in self.messages:
            # Skip UserMessages that only have tool confirmations
            if isinstance(message, UserMessage):
                if message.content is None and message.tool_confirmations:
                    continue

            # Convert the message to a LiteLLM-compatible dictionary
            result.append(message.to_litellm())

        return result

