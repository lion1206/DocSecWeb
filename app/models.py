"""
Database models for the secure document workflow system
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
from .utils.crypto_algorithms import MAGMA, Streebog, GOST3410

db = SQLAlchemy()

# Association table for document recipients
document_recipients = db.Table('document_recipients',
    db.Column('document_id', db.Integer, db.ForeignKey('document.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    """
    User model with role-based access control
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, user, approver
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Key storage (encrypted with system master key)
    private_key_encrypted = db.Column(db.LargeBinary, nullable=True)  # Encrypted private key for digital signatures
    public_key = db.Column(db.LargeBinary, nullable=True)  # Public key for verification
    encryption_key_encrypted = db.Column(db.LargeBinary, nullable=True)  # Encrypted key for document encryption
    
    # Relationships
    created_documents = db.relationship('Document', foreign_keys='Document.author_id', backref='author', lazy=True)
    received_documents = db.relationship('Document', secondary=document_recipients, lazy='subquery',
                                        backref=db.backref('recipients', lazy=True))
    document_actions = db.relationship('DocumentAction', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        return self.role == role
    
    def __repr__(self):
        return f'<User {self.username}>'


class DocumentType(db.Model):
    """
    Document type with associated form fields and workflow
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # e.g., "Order", "Contract", "Memo"
    description = db.Column(db.Text, nullable=True)
    form_fields = db.Column(db.Text, nullable=True)  # JSON string of form fields
    workflow_id = db.Column(db.Integer, db.ForeignKey('workflow.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    documents = db.relationship('Document', backref='doc_type', lazy=True)
    
    def get_form_fields(self):
        if self.form_fields:
            return json.loads(self.form_fields)
        return []
    
    def set_form_fields(self, fields):
        self.form_fields = json.dumps(fields)


class Workflow(db.Model):
    """
    Document workflow/routing scheme
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # e.g., "Standard Approval"
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    document_types = db.relationship('DocumentType', backref='workflow', lazy=True)
    stages = db.relationship('WorkflowStage', backref='workflow', lazy=True, order_by='WorkflowStage.order')


class WorkflowStage(db.Model):
    """
    A stage in a document workflow
    """
    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.Integer, db.ForeignKey('workflow.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)  # e.g., "Department Head Review"
    role_required = db.Column(db.String(20), nullable=True)  # Role required for this stage
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Specific user for this stage
    order = db.Column(db.Integer, nullable=False)  # Order in the workflow
    can_approve = db.Column(db.Boolean, default=True)  # Can approve the document
    can_reject = db.Column(db.Boolean, default=True)  # Can reject the document
    can_return = db.Column(db.Boolean, default=True)  # Can return for revision
    
    # Relationships
    actions = db.relationship('DocumentAction', backref='workflow_stage', lazy=True)


class Document(db.Model):
    """
    Document model with cryptographic protection
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content_encrypted = db.Column(db.LargeBinary, nullable=False)  # Encrypted content
    content_hash = db.Column(db.String(64), nullable=False)  # Streebog hash of original content
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type_id = db.Column(db.Integer, db.ForeignKey('document_type.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='draft')  # draft, pending, approved, rejected, archived
    current_stage_id = db.Column(db.Integer, db.ForeignKey('workflow_stage.id'), nullable=True)
    signature = db.Column(db.LargeBinary, nullable=True)  # Digital signature (r, s values)
    signature_valid = db.Column(db.Boolean, default=False)  # Whether signature is valid
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    signed_at = db.Column(db.DateTime, nullable=True)
    
    # Additional document metadata
    doc_metadata = db.Column(db.Text, nullable=True)  # JSON string of additional fields
    
    def get_content(self, user):
        """
        Decrypt document content for a specific user
        This would use the user's private key to decrypt the content
        """
        # This is a simplified implementation - in reality, we'd need to 
        # decrypt the document using a key that the user has access to
        magma = MAGMA(b'\x00' * 32)  # This should be derived from user's key
        try:
            decrypted_content = magma.decrypt(self.content_encrypted)
            return decrypted_content.decode('utf-8')
        except:
            return None
    
    def verify_signature(self):
        """
        Verify the digital signature of the document
        """
        if not self.signature or not self.author.public_key:
            return False
            
        # Deserialize the public key
        try:
            # This is a simplified implementation - in reality, we'd properly deserialize the public key
            # For now, we'll use the GOST3410 implementation
            gost = GOST3410()
            
            # Extract signature values (r, s) - in real implementation these would be properly stored
            # For now, we'll reconstruct them from the stored bytes
            if len(self.signature) == 64:  # 32 bytes each for r and s
                r_bytes = self.signature[:32]
                s_bytes = self.signature[32:]
                r = int.from_bytes(r_bytes, byteorder='big')
                s = int.from_bytes(s_bytes, byteorder='big')
                
                # Deserialize public key (simplified)
                # In real implementation, public key would be properly stored
                public_key_x = int.from_bytes(self.author.public_key[:32], byteorder='big')
                public_key_y = int.from_bytes(self.author.public_key[32:], byteorder='big')
                public_key = (public_key_x, public_key_y)
                
                # Verify the signature against the original content hash
                # For this we need the original content, which we don't have decrypted
                # So we'll just verify against the stored hash
                message = self.content_hash.encode('utf-8')
                return gost.verify(message, (r, s), public_key)
            else:
                return False
        except:
            return False
    
    def get_metadata(self):
        if self.doc_metadata:
            return json.loads(self.doc_metadata)
        return {}
    
    def set_metadata(self, metadata):
        self.doc_metadata = json.dumps(metadata)


class DocumentAction(db.Model):
    """
    Log of actions performed on a document
    """
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stage_id = db.Column(db.Integer, db.ForeignKey('workflow_stage.id'), nullable=True)
    action = db.Column(db.String(20), nullable=False)  # approve, reject, return, sign, view
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    document = db.relationship('Document', backref='actions', lazy=True)


class SystemLog(db.Model):
    """
    System log for audit trail
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # login, logout, create_doc, etc.
    resource_type = db.Column(db.String(50), nullable=True)  # document, user, etc.
    resource_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # Support IPv6
    user_agent = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='logs', lazy=True)