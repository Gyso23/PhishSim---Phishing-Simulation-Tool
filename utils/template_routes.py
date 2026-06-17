from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, Response
from functools import wraps
from .models import db, EmailTemplate, TemplateImage, TemplateAttachment
from datetime import datetime
import base64
import re

templates_bp = Blueprint('templates', __name__, url_prefix='/templates')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@templates_bp.route('/', methods=['GET'])
@login_required
def list_templates():
    templates = EmailTemplate.query.order_by(EmailTemplate.updated_at.desc()).all()
    return render_template('templates_page.html', templates=templates)

@templates_bp.route('/', methods=['POST'])
@login_required
def create_template():
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({'error': 'Name is required'}), 400
        
    template = EmailTemplate(
        name=data['name'],
        subject=data.get('subject'),
        html_content=data.get('html_content'),
        tags=data.get('tags'),
        sender_name=data.get('sender_name'),
        sender_email=data.get('sender_email'),
    )
    db.session.add(template)
    db.session.commit()
    return jsonify({'success': True, 'id': template.id})

@templates_bp.route('/get/<int:id>', methods=['GET'])
@login_required
def get_template(id):
    template = EmailTemplate.query.get_or_404(id)
    images = [{'cid': img.cid, 'filename': img.filename, 'mime_type': img.mime_type, 'id': img.id}
              for img in template.images]
    return jsonify({
        'id': template.id,
        'name': template.name,
        'subject': template.subject,
        'html_content': template.html_content,
        'tags': template.tags,
        'sender_name': template.sender_name,
        'sender_email': template.sender_email,
        'images': images,
        'updated_at': template.updated_at.isoformat() if template.updated_at else None
    })

@templates_bp.route('/<int:id>', methods=['GET'])
@login_required
def get_template_alt(id):
    return get_template(id)

@templates_bp.route('/<int:id>', methods=['PUT'])
@login_required
def update_template(id):
    template = EmailTemplate.query.get_or_404(id)
    data = request.get_json()
    
    if 'name' in data:
        template.name = data['name']
    if 'subject' in data:
        template.subject = data['subject']
    if 'html_content' in data:
        template.html_content = data['html_content']
    if 'tags' in data:
        template.tags = data['tags']
    if 'sender_name' in data:
        template.sender_name = data['sender_name']
    if 'sender_email' in data:
        template.sender_email = data['sender_email']
        
    template.updated_at = datetime.now()
    db.session.commit()
    return jsonify({'success': True})

@templates_bp.route('/<int:id>', methods=['DELETE'])
@login_required
def delete_template(id):
    template = EmailTemplate.query.get_or_404(id)
    db.session.delete(template)
    db.session.commit()
    return jsonify({'success': True})

@templates_bp.route('/list', methods=['GET'])
@login_required
def list_templates_json():
    templates = EmailTemplate.query.order_by(EmailTemplate.updated_at.desc()).all()
    return jsonify([{
        'id': t.id,
        'name': t.name,
        'subject': t.subject,
        'html_content': t.html_content,
        'tags': t.tags,
        'sender_name': t.sender_name,
        'sender_email': t.sender_email,
        'updated_at': t.updated_at.isoformat() if t.updated_at else None
    } for t in templates])

@templates_bp.route('/<int:id>/duplicate', methods=['POST'])
@login_required
def duplicate_template(id):
    template = EmailTemplate.query.get_or_404(id)
    new_template = EmailTemplate(
        name=f"{template.name} (Copy)",
        subject=template.subject,
        html_content=template.html_content,
        tags=template.tags,
        sender_name=template.sender_name,
        sender_email=template.sender_email,
    )
    db.session.add(new_template)
    db.session.commit()
    # Duplicate images too
    for img in template.images:
        new_img = TemplateImage(
            template_id=new_template.id,
            cid=img.cid,
            filename=img.filename,
            mime_type=img.mime_type,
            data=img.data,
        )
        db.session.add(new_img)
    db.session.commit()
    return jsonify({'success': True, 'id': new_template.id})

# ── Image management ──────────────────────────────────────────────────────────

@templates_bp.route('/<int:id>/images', methods=['GET'])
@login_required
def list_images(id):
    """List all CID images attached to a template."""
    template = EmailTemplate.query.get_or_404(id)
    return jsonify([{
        'id': img.id,
        'cid': img.cid,
        'filename': img.filename,
        'mime_type': img.mime_type,
        'preview': f'/templates/{id}/images/{img.id}/preview',
    } for img in template.images])


@templates_bp.route('/<int:id>/images', methods=['POST'])
@login_required
def upload_image(id):
    """Upload an image and attach it to a template as a CID.
    
    Accepts multipart/form-data with fields:
        file  – the image file
        cid   – (optional) desired CID, defaults to filename stem
    """
    template = EmailTemplate.query.get_or_404(id)
    file = request.files.get('file')
    if not file or file.filename == '':
        return jsonify({'error': 'No file provided'}), 400

    # Determine MIME type
    mime_type = file.content_type or 'image/png'
    if not mime_type.startswith('image/'):
        return jsonify({'error': 'Only image files are allowed'}), 400

    filename = file.filename
    # Build CID: use the provided cid, or derive from the full filename (keep extension,
    # sanitise everything except letters, digits, underscores, hyphens and dots).
    # Keeping the extension means <img src="cid:photo.jpg"> works without any adjustment.
    cid_raw = request.form.get('cid', '') or filename
    cid = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', cid_raw)

    # If a CID with this name already exists for the template, replace it
    existing = TemplateImage.query.filter_by(template_id=id, cid=cid).first()
    if existing:
        existing.filename = filename
        existing.mime_type = mime_type
        existing.data = file.read()
        db.session.commit()
        img_id = existing.id
    else:
        img = TemplateImage(
            template_id=id,
            cid=cid,
            filename=filename,
            mime_type=mime_type,
            data=file.read(),
        )
        db.session.add(img)
        db.session.commit()
        img_id = img.id

    return jsonify({
        'success': True,
        'id': img_id,
        'cid': cid,
        'filename': filename,
        'mime_type': mime_type,
        'html_snippet': f'<img src="cid:{cid}" alt="{cid}" />',
        'preview': f'/templates/{id}/images/{img_id}/preview',
    })


@templates_bp.route('/<int:template_id>/images/<int:image_id>/preview', methods=['GET'])
@login_required
def preview_image(template_id, image_id):
    """Serve the raw image so the template editor can display a preview."""
    img = TemplateImage.query.filter_by(id=image_id, template_id=template_id).first_or_404()
    return Response(img.data, mimetype=img.mime_type)


@templates_bp.route('/<int:template_id>/images/<int:image_id>', methods=['DELETE'])
@login_required
def delete_image(template_id, image_id):
    """Delete a CID image from a template."""
    img = TemplateImage.query.filter_by(id=image_id, template_id=template_id).first_or_404()
    db.session.delete(img)
    db.session.commit()
    return jsonify({'success': True})


# ── File Attachment management ────────────────────────────────────────────────

ALLOWED_ATTACHMENT_MIME = {
    'application/pdf', 'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain', 'text/csv',
    'application/zip', 'application/x-zip-compressed',
    'application/octet-stream',
    'image/png', 'image/jpeg', 'image/gif',
}

@templates_bp.route('/<int:id>/attachments', methods=['GET'])
@login_required
def list_attachments(id):
    """List all file attachments for a template."""
    template = EmailTemplate.query.get_or_404(id)
    return jsonify([{
        'id': a.id,
        'filename': a.filename,
        'mime_type': a.mime_type,
        'size': a.size,
        'size_kb': round((a.size or 0) / 1024, 1),
    } for a in template.attachments])


@templates_bp.route('/<int:id>/attachments', methods=['POST'])
@login_required
def upload_attachment(id):
    """Upload a file attachment to a template (PDF, DOCX, etc.)."""
    template = EmailTemplate.query.get_or_404(id)
    file = request.files.get('file')
    if not file or file.filename == '':
        return jsonify({'error': 'No file provided'}), 400

    from werkzeug.utils import secure_filename
    filename = secure_filename(file.filename)
    data = file.read()
    size = len(data)
    mime_type = file.content_type or 'application/octet-stream'

    # Max 10 MB
    if size > 10 * 1024 * 1024:
        return jsonify({'error': 'File too large (max 10 MB)'}), 400

    att = TemplateAttachment(
        template_id=id,
        filename=filename,
        mime_type=mime_type,
        data=data,
        size=size,
    )
    db.session.add(att)
    db.session.commit()
    return jsonify({
        'success': True,
        'id': att.id,
        'filename': filename,
        'mime_type': mime_type,
        'size': size,
        'size_kb': round(size / 1024, 1),
    }), 201


@templates_bp.route('/<int:template_id>/attachments/<int:att_id>', methods=['DELETE'])
@login_required
def delete_attachment(template_id, att_id):
    """Delete a file attachment from a template."""
    att = TemplateAttachment.query.filter_by(id=att_id, template_id=template_id).first_or_404()
    db.session.delete(att)
    db.session.commit()
    return jsonify({'success': True})
