"""
Admin blueprint for the secure document workflow system
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from .models import db, User, Document, DocumentType, Workflow, WorkflowStage, SystemLog
from .utils.crypto_algorithms import GOST3410
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/dashboard')
@login_required
def admin_dashboard():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Get system statistics
    total_users = User.query.count()
    total_docs = Document.query.count()
    total_workflows = Workflow.query.count()
    recent_logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                          total_users=total_users,
                          total_docs=total_docs,
                          total_workflows=total_workflows,
                          recent_logs=recent_logs)

@admin_bp.route('/users')
@login_required
def users():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        user.first_name = request.form.get('first_name', '')
        user.last_name = request.form.get('last_name', '')
        user.is_active = 'is_active' in request.form
        
        # Change password if provided
        new_password = request.form.get('password', '')
        if new_password:
            user.set_password(new_password)
        
        db.session.commit()
        flash(f'User {user.username} updated successfully', 'success')
        return redirect(url_for('admin.users'))
    
    return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/users/<int:id>/delete', methods=['POST'])
@login_required
def delete_user(id):
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    user = User.query.get_or_404(id)
    
    if user.id == current_user.id:
        flash('You cannot delete yourself', 'error')
        return redirect(url_for('admin.users'))
    
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted successfully', 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/workflows')
@login_required
def workflows():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    workflows = Workflow.query.all()
    return render_template('admin/workflows.html', workflows=workflows)

@admin_bp.route('/workflows/create', methods=['GET', 'POST'])
@login_required
def create_workflow():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        
        workflow = Workflow(name=name, description=description)
        db.session.add(workflow)
        db.session.commit()
        
        flash(f'Workflow {name} created successfully', 'success')
        return redirect(url_for('admin.edit_workflow', id=workflow.id))
    
    return render_template('admin/create_workflow.html')

@admin_bp.route('/workflows/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_workflow(id):
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    workflow = Workflow.query.get_or_404(id)
    
    if request.method == 'POST':
        workflow.name = request.form['name']
        workflow.description = request.form.get('description', '')
        workflow.is_active = 'is_active' in request.form
        
        # Update stages
        stages_data = []
        i = 0
        while f'stage_name_{i}' in request.form:
            stage_name = request.form[f'stage_name_{i}']
            if stage_name.strip():  # Only process non-empty stages
                role_required = request.form.get(f'stage_role_{i}', '')
                can_approve = 'stage_approve_%d' % i in request.form
                can_reject = 'stage_reject_%d' % i in request.form
                can_return = 'stage_return_%d' % i in request.form
                
                stages_data.append({
                    'name': stage_name,
                    'role_required': role_required,
                    'order': i,
                    'can_approve': can_approve,
                    'can_reject': can_reject,
                    'can_return': can_return
                })
            i += 1
        
        # Delete existing stages
        for stage in workflow.stages:
            db.session.delete(stage)
        
        # Create new stages
        for stage_data in stages_data:
            stage = WorkflowStage(
                workflow_id=workflow.id,
                name=stage_data['name'],
                role_required=stage_data['role_required'],
                order=stage_data['order'],
                can_approve=stage_data['can_approve'],
                can_reject=stage_data['can_reject'],
                can_return=stage_data['can_return']
            )
            db.session.add(stage)
        
        db.session.commit()
        flash(f'Workflow {workflow.name} updated successfully', 'success')
        return redirect(url_for('admin.workflows'))
    
    return render_template('admin/edit_workflow.html', workflow=workflow)

@admin_bp.route('/workflows/<int:id>/delete', methods=['POST'])
@login_required
def delete_workflow(id):
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    workflow = Workflow.query.get_or_404(id)
    
    db.session.delete(workflow)
    db.session.commit()
    flash(f'Workflow {workflow.name} deleted successfully', 'success')
    return redirect(url_for('admin.workflows'))

@admin_bp.route('/document-types')
@login_required
def document_types():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    doc_types = DocumentType.query.all()
    return render_template('admin/document_types.html', document_types=doc_types)

@admin_bp.route('/document-types/create', methods=['GET', 'POST'])
@login_required
def create_document_type():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    workflows = Workflow.query.all()
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        workflow_id = request.form.get('workflow_id', type=int)
        
        doc_type = DocumentType(
            name=name,
            description=description,
            workflow_id=workflow_id if workflow_id else None
        )
        
        # Handle form fields
        field_names = request.form.getlist('field_name')
        field_types = request.form.getlist('field_type')
        field_required = request.form.getlist('field_required')
        
        fields = []
        for i, name in enumerate(field_names):
            if name.strip():  # Only add non-empty fields
                field_type = field_types[i] if i < len(field_types) else 'text'
                required = str(i) in field_required
                fields.append({
                    'name': name,
                    'type': field_type,
                    'required': required
                })
        
        doc_type.set_form_fields(fields)
        
        db.session.add(doc_type)
        db.session.commit()
        
        flash(f'Document type {name} created successfully', 'success')
        return redirect(url_for('admin.document_types'))
    
    return render_template('admin/create_document_type.html', workflows=workflows)

@admin_bp.route('/document-types/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_document_type(id):
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    doc_type = DocumentType.query.get_or_404(id)
    workflows = Workflow.query.all()
    
    if request.method == 'POST':
        doc_type.name = request.form['name']
        doc_type.description = request.form.get('description', '')
        doc_type.workflow_id = request.form.get('workflow_id', type=int) or None
        
        # Handle form fields
        field_names = request.form.getlist('field_name')
        field_types = request.form.getlist('field_type')
        field_required = request.form.getlist('field_required')
        
        fields = []
        for i, name in enumerate(field_names):
            if name.strip():  # Only add non-empty fields
                field_type = field_types[i] if i < len(field_types) else 'text'
                required = str(i) in field_required
                fields.append({
                    'name': name,
                    'type': field_type,
                    'required': required
                })
        
        doc_type.set_form_fields(fields)
        
        db.session.commit()
        flash(f'Document type {doc_type.name} updated successfully', 'success')
        return redirect(url_for('admin.document_types'))
    
    return render_template('admin/edit_document_type.html', 
                          doc_type=doc_type, 
                          workflows=workflows)

@admin_bp.route('/document-types/<int:id>/delete', methods=['POST'])
@login_required
def delete_document_type(id):
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    doc_type = DocumentType.query.get_or_404(id)
    
    db.session.delete(doc_type)
    db.session.commit()
    flash(f'Document type {doc_type.name} deleted successfully', 'success')
    return redirect(url_for('admin.document_types'))

@admin_bp.route('/system-logs')
@login_required
def system_logs():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    logs = SystemLog.query.order_by(SystemLog.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False)
    
    return render_template('admin/system_logs.html', logs=logs)

@admin_bp.route('/key-management')
@login_required
def key_management():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    users = User.query.all()
    return render_template('admin/key_management.html', users=users)

@admin_bp.route('/key-management/<int:user_id>/reset', methods=['POST'])
@login_required
def reset_keys(user_id):
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # Generate new key pair
    gost = GOST3410()
    private_key, public_key = gost.generate_keypair()
    
    # For simplicity in this demo, we're not actually encrypting the private key
    # In a real implementation, we would encrypt it with a system master key
    user.private_key_encrypted = private_key.to_bytes(32, byteorder='big')
    user.public_key = public_key[0].to_bytes(32, byteorder='big') + public_key[1].to_bytes(32, byteorder='big')
    
    db.session.commit()
    flash(f'Keys reset for user {user.username}', 'success')
    return redirect(url_for('admin.key_management'))