import os
import json
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to get data dir from config
try:
    from config import DATA_DIR
    ACTION_LOG_PATH = os.path.join(DATA_DIR, 'action_log.jsonl')
except ImportError:
    ACTION_LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'action_log.jsonl')

_lock = threading.Lock()

def log_action(event_type, campaign_id=None, email=None, token=None, extra_data=None):
    """
    Log an event to the structured JSON Lines action log.
    Used for disaster recovery and building state from raw events.
    """
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event_type': event_type,
        'campaign_id': campaign_id,
        'email': email,
        'token': token
    }
    
    if extra_data:
        event.update(extra_data)
        
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(ACTION_LOG_PATH), exist_ok=True)
        
        with _lock:
            with open(ACTION_LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write to action_log.jsonl: {e}")

