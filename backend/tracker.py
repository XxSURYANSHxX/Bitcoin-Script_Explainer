"""
Anonymous usage tracking module for Bitcoin Script Explainer.

Provides privacy-safe tracking of page visits and script explanations.
No personal data is collected - only anonymous session UUIDs and event types.
"""

import json
import os
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class EventType(str, Enum):
    """Supported tracking event types."""
    PAGE_VISIT = "page_visit"
    SCRIPT_EXPLAINED = "script_explained"


class TrackingEvent(BaseModel):
    """Model for a single tracking event."""
    session_id: str = Field(..., description="Anonymous UUID session identifier")
    event_type: EventType = Field(..., description="Type of event tracked")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class TrackRequest(BaseModel):
    """Request model for POST /track endpoint."""
    session_id: str
    event_type: str


class StatsResponse(BaseModel):
    """Response model for GET /stats endpoint."""
    lifetime_views: int
    total_scripts_explained: int
    current_active_users: int


class ActivityResponse(BaseModel):
    """Response model for GET /activity endpoint."""
    recent_events: List[dict]


# Path to the visits.json file
VISITS_FILE = os.path.join(os.path.dirname(__file__), "visits.json")


def load_events() -> List[dict]:
    """Load events from visits.json file."""
    if not os.path.exists(VISITS_FILE):
        return []
    
    try:
        with open(VISITS_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []
            return json.loads(content)
    except (json.JSONDecodeError, IOError):
        return []


def save_events(events: List[dict]) -> None:
    """Save events to visits.json file."""
    try:
        with open(VISITS_FILE, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
    except IOError:
        pass  # Silently fail to avoid crashing the app


def add_event(session_id: str, event_type: str) -> bool:
    """
    Add a new tracking event.
    
    Args:
        session_id: Anonymous UUID session identifier
        event_type: Type of event (page_visit or script_explained)
    
    Returns:
        True if event was added successfully, False otherwise
    """
    # Validate event type
    if event_type not in [e.value for e in EventType]:
        return False
    
    # Validate session_id is not empty
    if not session_id or not session_id.strip():
        return False
    
    event = {
        "session_id": session_id.strip(),
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    events = load_events()
    events.append(event)
    save_events(events)
    
    return True


def get_stats() -> StatsResponse:
    """
    Get usage statistics.
    
    Returns:
        StatsResponse with lifetime_views, total_scripts_explained, current_active_users
    """
    events = load_events()
    
    # Count lifetime views (page_visit events)
    lifetime_views = sum(1 for e in events if e.get("event_type") == EventType.PAGE_VISIT.value)
    
    # Count total scripts explained
    total_scripts_explained = sum(1 for e in events if e.get("event_type") == EventType.SCRIPT_EXPLAINED.value)
    
    # Count active users (unique sessions in last 5 minutes)
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    active_sessions = set()
    
    for event in events:
        try:
            timestamp_str = event.get("timestamp", "")
            # Handle both formats: with and without microseconds
            if "." in timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", ""))
            else:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", ""))
            
            if timestamp > five_minutes_ago:
                active_sessions.add(event.get("session_id"))
        except (ValueError, TypeError):
            continue
    
    return StatsResponse(
        lifetime_views=lifetime_views,
        total_scripts_explained=total_scripts_explained,
        current_active_users=len(active_sessions)
    )


def get_recent_activity(limit: int = 10) -> ActivityResponse:
    """
    Get recent activity events.
    
    Args:
        limit: Maximum number of events to return (default 10)
    
    Returns:
        ActivityResponse with list of recent events (event_type and timestamp only)
    """
    events = load_events()
    
    # Sort by timestamp descending and take last 'limit' events
    sorted_events = sorted(
        events,
        key=lambda e: e.get("timestamp", ""),
        reverse=True
    )[:limit]
    
    # Return only event_type and timestamp (no session_id for privacy)
    recent = [
        {
            "event_type": e.get("event_type"),
            "timestamp": e.get("timestamp")
        }
        for e in sorted_events
    ]
    
    return ActivityResponse(recent_events=recent)
