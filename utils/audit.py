"""
Audit logging module for PhishSim.
Tracks all user actions for security and compliance purposes.
"""

import os
import json
import logging
from datetime import datetime
from functools import wraps
from flask import request, session, g
from logging.handlers import RotatingFileHandler

# Create logs directory
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure audit logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False  # Don't send to root logger

# Rotating file handler - max 10MB per file, keep 10 backups
audit_handler = RotatingFileHandler(
    os.path.join(LOGS_DIR, 'audit.log'),
    maxBytes=10*1024*1024,  # 10 MB
    backupCount=10,
    encoding='utf-8'
)
audit_handler.setLevel(logging.INFO)

# JSON formatter for structured logging
class AuditFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'message': record.getMessage(),
        }
        # Add extra fields if present
        if hasattr(record, 'audit_data'):
            log_data.update(record.audit_data)
        return json.dumps(log_data)

audit_handler.setFormatter(AuditFormatter())
audit_logger.addHandler(audit_handler)

# Also log to a human-readable file
readable_handler = RotatingFileHandler(
    os.path.join(LOGS_DIR, 'audit_readable.log'),
    maxBytes=10*1024*1024,
    backupCount=10,
    encoding='utf-8'
)
readable_handler.setLevel(logging.INFO)
readable_formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
readable_handler.setFormatter(readable_formatter)
audit_logger.addHandler(readable_handler)


def get_client_ip():
    """Get the real client IP, handling proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def log_audit(action, details=None, success=True, user=None):
    """
    Log an audit event.
    
    Args:
        action: The action being performed (e.g., 'LOGIN', 'CREATE_CAMPAIGN')
        details: Additional details about the action
        success: Whether the action succeeded
        user: The user performing the action (defaults to session user)
    """
    audit_data = {
        'action': action,
        'user': user or session.get('user', 'anonymous'),
        'ip': get_client_ip(),
        'user_agent': request.headers.get('User-Agent', 'unknown')[:200],
        'method': request.method,
        'path': request.path,
        'success': success,
    }
    
    if details:
        audit_data['details'] = details
    
    # Add query parameters (exclude sensitive data)
    if request.args:
        safe_args = {k: v for k, v in request.args.items() 
                     if k.lower() not in ('password', 'token', 'secret')}
        if safe_args:
            audit_data['query_params'] = safe_args
    
    # Create log message
    status = "SUCCESS" if success else "FAILED"
    message = f"[{status}] {action} by {audit_data['user']} from {audit_data['ip']} - {request.method} {request.path}"
    if details:
        message += f" | {details}"
    
    # Log with extra data for JSON formatter
    record = audit_logger.makeRecord(
        audit_logger.name, logging.INFO, '', 0, message, (), None
    )
    record.audit_data = audit_data
    audit_logger.handle(record)


def audit_action(action_name, get_details=None):
    """
    Decorator to automatically audit route actions.
    
    Args:
        action_name: Name of the action for logging
        get_details: Optional function to extract details from request/response
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                result = f(*args, **kwargs)
                
                # Extract details if function provided
                details = None
                if get_details:
                    try:
                        details = get_details(request, result, *args, **kwargs)
                    except Exception:
                        pass
                
                log_audit(action_name, details=details, success=True)
                return result
                
            except Exception as e:
                log_audit(action_name, details=str(e), success=False)
                raise
        
        return decorated_function
    return decorator


# Pre-defined action constants
class AuditActions:
    # Authentication
    LOGIN_ATTEMPT = "LOGIN_ATTEMPT"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    CHANGE_PASSWORD = "CHANGE_PASSWORD"
    
    # Dashboard
    VIEW_DASHBOARD = "VIEW_DASHBOARD"
    EXPORT_DATA = "EXPORT_DATA"
    
    # Campaigns
    VIEW_CAMPAIGNS = "VIEW_CAMPAIGNS"
    CREATE_CAMPAIGN = "CREATE_CAMPAIGN"
    EDIT_CAMPAIGN = "EDIT_CAMPAIGN"
    DELETE_CAMPAIGN = "DELETE_CAMPAIGN"
    LAUNCH_CAMPAIGN = "LAUNCH_CAMPAIGN"
    VIEW_CAMPAIGN_RESULTS = "VIEW_CAMPAIGN_RESULTS"
    
    # Templates
    VIEW_TEMPLATES = "VIEW_TEMPLATES"
    CREATE_TEMPLATE = "CREATE_TEMPLATE"
    EDIT_TEMPLATE = "EDIT_TEMPLATE"
    DELETE_TEMPLATE = "DELETE_TEMPLATE"
    SEND_TEST_EMAIL = "SEND_TEST_EMAIL"
    
    # Targets
    VIEW_TARGETS = "VIEW_TARGETS"
    ADD_TARGET = "ADD_TARGET"
    EDIT_TARGET = "EDIT_TARGET"
    DELETE_TARGET = "DELETE_TARGET"
    BULK_ADD_TARGETS = "BULK_ADD_TARGETS"
    
    # User Management
    ADD_USER = "ADD_USER"
    DELETE_USER = "DELETE_USER"
    BULK_DELETE_TARGETS = "BULK_DELETE_TARGETS"
    
    # Results
    UPDATE_RESULT = "UPDATE_RESULT"
    MARK_REPORTED = "MARK_REPORTED"
    MARK_COMPROMISED = "MARK_COMPROMISED"
    
    # Landing Pages
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    VIEW = "VIEW"


def get_audit_logs(limit=100, user_filter=None, action_filter=None, date_from=None, date_to=None):
    """
    Retrieve audit logs with optional filtering.
    
    Returns list of log entries as dictionaries.
    """
    logs = []
    log_file = os.path.join(LOGS_DIR, 'audit.log')
    
    if not os.path.exists(log_file):
        return logs
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Process in reverse order (newest first)
        for line in reversed(lines):
            if len(logs) >= limit:
                break
            
            try:
                entry = json.loads(line.strip())
                
                # Apply filters
                if user_filter and entry.get('user') != user_filter:
                    continue
                if action_filter and entry.get('action') != action_filter:
                    continue
                if date_from:
                    entry_date = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                    if entry_date < date_from:
                        continue
                if date_to:
                    entry_date = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                    if entry_date > date_to:
                        continue
                
                logs.append(entry)
                
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
    
    except Exception as e:
        audit_logger.error(f"Error reading audit logs: {e}")
    
    return logs
