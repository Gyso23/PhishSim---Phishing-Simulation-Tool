from flask import Blueprint, request, send_file, render_template, current_app, make_response
import io
from pathlib import Path
from datetime import datetime
from .metrics import log_metric

tracking_bp = Blueprint('tracking', __name__)


@tracking_bp.route('/track')
def track():
    """Track link clicks and update database."""
    token = request.args.get('token')
    if token:
        # Log to file for backup
        Path('data').mkdir(exist_ok=True)
        with open('data/clicks.log', 'a') as f:
            f.write(f'Token {token} clicked the link at {datetime.now()}.\n')
        
        # Update database
        try:
            from .models import db, Result
            result = Result.query.filter_by(token=token).first()
            if result:
                result.clicked = True
                result.clicked_at = datetime.now()
                # Also track open - if they clicked, they must have opened the email!
                if not result.opened:
                    result.opened = True
                    result.opened_at = datetime.now()
                    log_metric('opened', result.campaign_id, result.email, token, {'method': 'implicit_from_click'})
                db.session.commit()
                log_metric('clicked', result.campaign_id, result.email, token, {})
        except Exception as e:
            current_app.logger.error(f"Failed to update click tracking for token {token}: {e}")
        
        # Render the landing page
        return render_template('track_result.html')
    return "Token not found.", 400


@tracking_bp.route('/pixel')
def pixel():
    """Track email opens via tracking pixel and update database."""
    token = request.args.get('token')
    
    if token:
        # Log to file for backup
        Path('data').mkdir(exist_ok=True)
        with open('data/opens.log', 'a') as f:
            f.write(f'Token {token} opened the email at {datetime.now()}.\n')
        
        # Update database
        try:
            from .models import db, Result
            result = Result.query.filter_by(token=token).first()
            if result:
                result.opened = True
                if not result.opened_at:  # Only set first open time
                    result.opened_at = datetime.now()
                db.session.commit()
                log_metric('opened', result.campaign_id, result.email, token, {'method': 'pixel'})
        except Exception as e:
            current_app.logger.error(f"Failed to update open tracking for token {token}: {e}")
    
    # Return a 1x1 transparent GIF pixel with aggressive anti-cache headers.
    pixel_bytes = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00\x3b'
    response = make_response(pixel_bytes)
    response.headers['Content-Type'] = 'image/gif'
    response.headers['Content-Length'] = str(len(pixel_bytes))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Surrogate-Control'] = 'no-store'
    response.headers['X-Accel-Expires'] = '0'
    response.headers['Last-Modified'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    response.headers.pop('ETag', None)
    return response


@tracking_bp.route('/track-image/<path:image_name>')
def tracked_image(image_name):
    """Serve an actual image (logo, banner) while tracking email opens.
    
    This is more reliable than a 1x1 pixel because:
    1. Users are more likely to load visible content images
    2. Some email clients trust larger/visible images more than tiny pixels
    
    Usage in email template:
    <img src="https://server/img/logo.png?token=xxx" alt="Company Logo">
    """
    import os
    
    token = request.args.get('token')
    
    # Track the open (same logic as pixel)
    if token:
        Path('data').mkdir(exist_ok=True)
        with open('data/opens.log', 'a') as f:
            f.write(f'Token {token} opened (via {image_name}) at {datetime.now()}.\n')
        
        try:
            from .models import db, Result
            result = Result.query.filter_by(token=token).first()
            if result:
                result.opened = True
                if not result.opened_at:
                    result.opened_at = datetime.now()
                db.session.commit()
                log_metric('opened', result.campaign_id, result.email, token, {'method': 'tracked_image', 'image': image_name})
        except Exception as e:
            current_app.logger.error(f"Failed to track open for token {token}: {e}")
    
    # Serve the actual image from email_images folder
    image_path = os.path.join(current_app.root_path, 'email_images', image_name)
    
    # Determine mime type
    if image_name.lower().endswith('.png'):
        mime = 'image/png'
    elif image_name.lower().endswith('.jpg') or image_name.lower().endswith('.jpeg'):
        mime = 'image/jpeg'
    elif image_name.lower().endswith('.gif'):
        mime = 'image/gif'
    else:
        mime = 'application/octet-stream'
    
    if os.path.exists(image_path):
        response = send_file(image_path, mimetype=mime)
    else:
        # Fallback: return a simple placeholder or the pixel
        img = io.BytesIO(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00\x3b')
        response = send_file(img, mimetype='image/gif')
    
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Surrogate-Control'] = 'no-store'
    response.headers['X-Accel-Expires'] = '0'
    response.headers['Last-Modified'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    response.headers.pop('ETag', None)
    return response

