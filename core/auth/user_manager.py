import bcrypt
from datetime import datetime

class UserManager:
    """User authentication and authorization system"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.current_user = None
    
    def register_user(self, username, email, password, role='analyst'):
        """Register a new user with hashed password"""
        # Hash password with bcrypt (cost factor 12)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')
        
        user = self.db.create_user(username, email, password_hash, role)
        return user
    
    def authenticate(self, username, password):
        """Authenticate user with username and password"""
        user = self.db.get_user_by_username(username)
        
        if not user:
            return None
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            # Update last login
            session = self.db.Session()
            user.last_login = datetime.utcnow()
            session.add(user)
            session.commit()
            session.close()
            
            self.current_user = user
            return user
        
        return None
    
    def logout(self):
        """Logout current user"""
        self.current_user = None
    
    def is_authenticated(self):
        """Check if user is authenticated"""
        return self.current_user is not None
    
    def has_permission(self, action, resource=None):
        """Check if current user has permission for action"""
        if not self.current_user:
            return False
        
        role = self.current_user.role
        
        # Admin has all permissions
        if role == 'admin':
            return True
        
        # Analyst can do most things
        if role == 'analyst':
            if action in ['view', 'create', 'edit', 'analyze', 'comment']:
                return True
            if action == 'delete' and resource:
                # Can only delete own resources
                return resource.user_id == self.current_user.id if hasattr(resource, 'user_id') else False
        
        # Viewer can only view
        if role == 'viewer':
            return action == 'view'
        
        return False
    
    def can_access_project(self, project):
        """Check if current user can access a project"""
        if not self.current_user:
            return False
        
        # Admin can access all
        if self.current_user.role == 'admin':
            return True
        
        # Owner can access
        if project.owner_id == self.current_user.id:
            return True
        
        # Check if user is a member
        session = self.db.Session()
        from core.database import ProjectMember
        member = session.query(ProjectMember).filter_by(
            project_id=project.id,
            user_id=self.current_user.id
        ).first()
        session.close()
        
        return member is not None
    
    def get_project_role(self, project):
        """Get user's role in a project"""
        if not self.current_user:
            return None
        
        if self.current_user.role == 'admin':
            return 'owner'
        
        if project.owner_id == self.current_user.id:
            return 'owner'
        
        session = self.db.Session()
        from core.database import ProjectMember
        member = session.query(ProjectMember).filter_by(
            project_id=project.id,
            user_id=self.current_user.id
        ).first()
        session.close()
        
        return member.role if member else None
