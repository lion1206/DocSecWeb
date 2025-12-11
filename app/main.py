"""
Main blueprint for the secure document workflow system
"""
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from .models import db, Document, DocumentType, Workflow, SystemLog

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    # Get documents for the current user
    created_docs = Document.query.filter_by(author_id=current_user.id).all()
    received_docs = current_user.received_documents
    
    # Get document statistics
    total_docs = Document.query.count()
    pending_docs = Document.query.filter_by(status='pending').count()
    approved_docs = Document.query.filter_by(status='approved').count()
    rejected_docs = Document.query.filter_by(status='rejected').count()
    
    return render_template('main/dashboard.html', 
                          created_docs=created_docs,
                          received_docs=received_docs,
                          total_docs=total_docs,
                          pending_docs=pending_docs,
                          approved_docs=approved_docs,
                          rejected_docs=rejected_docs)

@main_bp.route('/profile')
@login_required
def profile():
    return render_template('main/profile.html', user=current_user)