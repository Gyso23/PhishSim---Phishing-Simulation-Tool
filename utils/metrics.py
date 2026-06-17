"""
Metrics logging module for PhishSim.
Ensures that all critical campaign events are logged as structured JSON
independent of the database to ensure resilience and recoverability.
"""
import os
import json
import logging
import threading
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
METRICS_FILE = os.path.join(DATA_DIR, 'campaign_metrics.jsonl')

_metrics_lock = threading.Lock()

def log_metric(event_type: str, campaign_id: int, email: str, token: str, extra_data: dict = None):
    """
    Log a metric event to the JSONL metrics file.
    
    Args:
        event_type (str): Type of event (e.g., 'sent', 'opened', 'clicked', 'submitted', 'reported', 'compromised').
        campaign_id (int): The ID of the campaign.
        email (str): Target's email address.
        token (str): Tracking token.
        extra_data (dict): Optional dict for additional data.
    """
    try:
        metric = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'campaign_id': campaign_id,
            'email': email,
            'token': token
        }
        
        if extra_data:
            metric['extra_data'] = extra_data
            
        json_line = json.dumps(metric)
        
        with _metrics_lock:
            with open(METRICS_FILE, 'a', encoding='utf-8') as f:
                f.write(json_line + '\n')
                
    except Exception as e:
        logger.error(f"Failed to log metric ({event_type}) for {email}: {e}")
