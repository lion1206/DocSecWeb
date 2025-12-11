"""
Documents blueprint for the secure document workflow system
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from .models import db, Document, DocumentType, DocumentAction, WorkflowStage
from .utils.crypto_algorithms import MAGMA, Streebog, GOST3410
from datetime import datetime
import secrets

documents_bp = Blueprint('documents', __name__)

@documents_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_document():
    document_types = DocumentType.query.all()
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        type_id = request.form['type_id']
        
        # Get document type
        doc_type = DocumentType.query.get_or_404(type_id)
        
        # Generate encryption key for this document
        doc_encryption_key = secrets.token_bytes(32)  # 256-bit key for MAGMA
        
        # Encrypt the content
        magma = MAGMA(doc_encryption_key)
        encrypted_content = magma.encrypt(content.encode('utf-8'))
        
        # Calculate hash of original content
        streebog = Streebog(bit_size=256)
        streebog.update(content.encode('utf-8'))
        content_hash = streebog.hexdigest()
        
        # Create the document
        document = Document(
            title=title,
            content_encrypted=encrypted_content,
            content_hash=content_hash,
            author_id=current_user.id,
            type_id=type_id,
            status='pending'  # Start in pending status
        )
        
        # If the document type has a workflow, set the first stage
        if doc_type.workflow and doc_type.workflow.stages:
            first_stage = min(doc_type.workflow.stages, key=lambda s: s.order)
            document.current_stage_id = first_stage.id
        
        # Create initial document action
        action = DocumentAction(
            document=document,
            user=current_user,
            action='create',
            comment='Document created'
        )
        
        db.session.add(document)
        db.session.add(action)
        db.session.commit()
        
        # Generate digital signature for the document
        if current_user.private_key_encrypted:
            # In a real implementation, we would decrypt the private key first
            # For this example, we'll generate a signature using the GOST implementation
            gost = GOST3410()
            
            # For demonstration, we'll use a temporary private key
            # In a real implementation, we would decrypt the stored private key
            temp_private_key, temp_public_key = gost.generate_keypair()
            
            # Sign the content hash
            r, s = gost.sign(content_hash.encode('utf-8'), temp_private_key)
            
            # Store the signature as bytes
            signature_bytes = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
            document.signature = signature_bytes
            document.signature_valid = True
            document.signed_at = datetime.utcnow()
            
            db.session.commit()
        
        flash('Document created successfully', 'success')
        return redirect(url_for('documents.view_document', id=document.id))
    
    return render_template('documents/create.html', document_types=document_types)

@documents_bp.route('/<int:id>')
@login_required
def view_document(id):
    document = Document.query.get_or_404(id)
    
    # Check if user has access to this document
    if document.author_id != current_user.id and current_user.id not in [r.id for r in document.recipients]:
        flash('Access denied to this document', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Verify signature if present
    signature_valid = document.verify_signature() if document.signature else False
    
    # Get document content (decrypted)
    content = document.get_content(current_user)
    
    # Get document actions (history)
    actions = Document.query.get_or_404(id).actions
    
    return render_template('documents/view.html', 
                          document=document, 
                          content=content, 
                          signature_valid=signature_valid,
                          actions=actions)

@documents_bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_document(id):
    document = Document.query.get_or_404(id)
    
    # Only the author can edit the document (if it's still in draft)
    if document.author_id != current_user.id or document.status != 'draft':
        flash('You cannot edit this document', 'error')
        return redirect(url_for('documents.view_document', id=id))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        # Re-encrypt the content
        magma = MAGMA(secrets.token_bytes(32))  # New key for security
        encrypted_content = magma.encrypt(content.encode('utf-8'))
        
        # Recalculate hash
        streebog = Streebog(bit_size=256)
        streebog.update(content.encode('utf-8'))
        content_hash = streebog.hexdigest()
        
        # Update document
        document.title = title
        document.content_encrypted = encrypted_content
        document.content_hash = content_hash
        
        # Update signature
        gost = GOST3410()
        temp_private_key, temp_public_key = gost.generate_keypair()
        r, s = gost.sign(content_hash.encode('utf-8'), temp_private_key)
        signature_bytes = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        document.signature = signature_bytes
        document.signature_valid = True
        document.signed_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Document updated successfully', 'success')
        return redirect(url_for('documents.view_document', id=id))
    
    return render_template('documents/edit.html', document=document)

@documents_bp.route('/<int:id>/action', methods=['POST'])
@login_required
def document_action(id):
    document = Document.query.get_or_404(id)
    action = request.form['action']
    comment = request.form.get('comment', '')
    
    # Check if user can perform this action at current stage
    current_stage = document.current_stage
    if not current_stage:
        flash('Document has no current stage', 'error')
        return redirect(url_for('documents.view_document', id=id))
    
    # Check if user has permission for this stage
    can_perform_action = False
    if current_stage.role_required and current_user.has_role(current_stage.role_required):
        can_perform_action = True
    elif current_stage.user_id == current_user.id:
        can_perform_action = True
    
    if not can_perform_action:
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('documents.view_document', id=id))
    
    # Validate action
    valid_actions = []
    if current_stage.can_approve and action == 'approve':
        valid_actions.append('approve')
    if current_stage.can_reject and action == 'reject':
        valid_actions.append('reject')
    if current_stage.can_return and action == 'return':
        valid_actions.append('return')
    
    if action not in valid_actions:
        flash(f'Action {action} not allowed at this stage', 'error')
        return redirect(url_for('documents.view_document', id=id))
    
    # Create document action record
    doc_action = DocumentAction(
        document_id=id,
        user_id=current_user.id,
        stage_id=current_stage.id,
        action=action,
        comment=comment
    )
    db.session.add(doc_action)
    
    # Update document based on action
    if action == 'approve':
        # Move to next stage if available
        next_stage = None
        if current_stage.workflow.stages:
            next_stage = next((s for s in current_stage.workflow.stages if s.order > current_stage.order), None)
        
        if next_stage:
            document.current_stage_id = next_stage.id
            document.status = 'pending'
            flash(f'Document approved and moved to stage: {next_stage.name}', 'success')
        else:
            # No more stages, document is approved
            document.status = 'approved'
            flash('Document fully approved', 'success')
    
    elif action == 'reject':
        document.status = 'rejected'
        flash('Document rejected', 'info')
    
    elif action == 'return':
        # Return to previous stage or back to author
        prev_stage = None
        if current_stage.workflow.stages:
            prev_stage = next((s for s in current_stage.workflow.stages if s.order < current_stage.order), None)
        
        if prev_stage:
            document.current_stage_id = prev_stage.id
        else:
            # Return to author
            document.current_stage_id = None
            document.status = 'draft'
        
        flash('Document returned for revision', 'info')
    
    db.session.commit()
    return redirect(url_for('documents.view_document', id=id))

@documents_bp.route('/my-documents')
@login_required
def my_documents():
    created_docs = Document.query.filter_by(author_id=current_user.id).all()
    return render_template('documents/my_documents.html', documents=created_docs)

@documents_bp.route('/inbox')
@login_required
def inbox():
    # Documents assigned to current user for action
    # This is a simplified version - in reality, this would be more complex
    documents = Document.query.filter_by(current_stage_id=1).all()  # Placeholder
    return render_template('documents/inbox.html', documents=documents)

@documents_bp.route('/outbox')
@login_required
def outbox():
    # Documents sent by current user
    documents = Document.query.filter_by(author_id=current_user.id).all()
    return render_template('documents/outbox.html', documents=documents)

@documents_bp.route('/archive')
@login_required
def archive():
    # Archived documents
    documents = Document.query.filter_by(status='archived').all()
    return render_template('documents/archive.html', documents=documents)