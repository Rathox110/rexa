from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Float, Boolean, Index
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import datetime
import json

Base = declarative_base()

# ==================== Core Models ====================

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default='analyst')  # admin, analyst, viewer
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_login = Column(DateTime)
    
class Project(Base):
    __tablename__ = 'projects'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    description = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    visibility = Column(String, default='private')
    samples = relationship("Sample", back_populates="project")
    
class ProjectMember(Base):
    __tablename__ = 'project_members'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    role = Column(String)
    joined_at = Column(DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (Index('idx_project_user', 'project_id', 'user_id'),)

class Sample(Base):
    __tablename__ = 'samples'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    filename = Column(String)
    file_path = Column(String)
    md5 = Column(String)
    sha256 = Column(String)
    analysis_json = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    project = relationship("Project", back_populates="samples")

# ==================== Disassembly Models ====================

class Function(Base):
    __tablename__ = 'functions'
    id = Column(Integer, primary_key=True)
    sample_id = Column(Integer, ForeignKey('samples.id'), index=True)
    address = Column(String)
    name = Column(String)
    size = Column(Integer)
    is_import = Column(Boolean, default=False)
    decompiled_code = Column(Text)
    __table_args__ = (Index('idx_sample_address', 'sample_id', 'address'),)

class Instruction(Base):
    __tablename__ = 'instructions'
    id = Column(Integer, primary_key=True)
    function_id = Column(Integer, ForeignKey('functions.id'), index=True)
    address = Column(String)
    mnemonic = Column(String, index=True)
    operands = Column(String)
    bytes = Column(String)

class CrossReference(Base):
    __tablename__ = 'xrefs'
    id = Column(Integer, primary_key=True)
    sample_id = Column(Integer, ForeignKey('samples.id'), index=True)
    from_address = Column(String)
    to_address = Column(String)
    xref_type = Column(String)

# ==================== Sandbox Models ====================

class SandboxRun(Base):
    __tablename__ = 'sandbox_runs'
    id = Column(Integer, primary_key=True)
    sample_id = Column(Integer, ForeignKey('samples.id'), index=True)
    provider = Column(String)
    task_id = Column(String)
    status = Column(String)
    submitted_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime)
    verdict = Column(String)
    score = Column(Float)

class SandboxResult(Base):
    __tablename__ = 'sandbox_results'
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey('sandbox_runs.id'), index=True)
    result_type = Column(String)
    data_json = Column(Text)

class NetworkIndicator(Base):
    __tablename__ = 'network_indicators'
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey('sandbox_runs.id'), index=True)
    indicator_type = Column(String)
    value = Column(String, index=True)
    protocol = Column(String)
    first_seen = Column(DateTime)

class DroppedFile(Base):
    __tablename__ = 'dropped_files'
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey('sandbox_runs.id'), index=True)
    filename = Column(String)
    file_path = Column(String)
    md5 = Column(String)
    sha256 = Column(String, index=True)
    size = Column(Integer)

# ==================== Threat Intelligence Models ====================

class ThreatIntel(Base):
    __tablename__ = 'threat_intel'
    id = Column(Integer, primary_key=True)
    sample_id = Column(Integer, ForeignKey('samples.id'), index=True)
    source = Column(String)
    data_json = Column(Text)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (Index('idx_sample_source', 'sample_id', 'source'),)

class IOCReputation(Base):
    __tablename__ = 'ioc_reputation'
    id = Column(Integer, primary_key=True)
    ioc_value = Column(String, unique=True, index=True)
    ioc_type = Column(String)
    reputation_score = Column(Float)
    sources = Column(Text)
    last_checked = Column(DateTime)

class MalwareFamily(Base):
    __tablename__ = 'malware_families'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)
    aliases = Column(Text)
    
class SampleFamily(Base):
    __tablename__ = 'sample_families'
    sample_id = Column(Integer, ForeignKey('samples.id'), primary_key=True)
    family_id = Column(Integer, ForeignKey('malware_families.id'), primary_key=True)
    confidence = Column(Float)

# ==================== Collaboration Models ====================

class Annotation(Base):
    __tablename__ = 'annotations'
    id = Column(Integer, primary_key=True)
    sample_id = Column(Integer, ForeignKey('samples.id'), index=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    annotation_type = Column(String)
    target_type = Column(String)
    target_value = Column(String)
    content = Column(Text)
    color = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime)
    __table_args__ = (Index('idx_sample_target', 'sample_id', 'target_type', 'target_value'),)

class ActivityLog(Base):
    __tablename__ = 'activity_log'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    project_id = Column(Integer, ForeignKey('projects.id'), index=True)
    action = Column(String)
    target_type = Column(String)
    target_id = Column(Integer)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

# ==================== Database Manager ====================

class DatabaseManager:
    def __init__(self, db_path='sqlite:///rexa.db'):
        self.engine = create_engine(db_path)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    # ========== Project Methods ==========
    
    def create_project(self, name, description="", owner_id=None):
        session = self.Session()
        try:
            proj = Project(name=name, description=description, owner_id=owner_id)
            session.add(proj)
            session.commit()
            return proj
        except Exception as e:
            session.rollback()
            print(f"Error creating project: {e}")
            return None
        finally:
            session.close()

    def get_projects(self, user_id=None):
        session = self.Session()
        projects = session.query(Project).all()
        session.close()
        return projects

    # ========== Sample Methods ==========
    
    def add_sample(self, project_id, filename, file_path, md5, sha256, analysis_data):
        session = self.Session()
        try:
            sample = Sample(
                project_id=project_id,
                filename=filename,
                file_path=file_path,
                md5=md5,
                sha256=sha256,
                analysis_json=json.dumps(analysis_data)
            )
            session.add(sample)
            session.commit()
            return sample
        except Exception as e:
            session.rollback()
            print(f"Error adding sample: {e}")
            return None
        finally:
            session.close()

    def get_project_samples(self, project_id):
        session = self.Session()
        samples = session.query(Sample).filter_by(project_id=project_id).all()
        session.close()
        return samples

    def get_sample(self, sample_id):
        session = self.Session()
        sample = session.query(Sample).filter_by(id=sample_id).first()
        session.close()
        return sample
    
    # ========== User Methods ==========
    
    def create_user(self, username, email, password_hash, role='analyst'):
        session = self.Session()
        try:
            user = User(username=username, email=email, password_hash=password_hash, role=role)
            session.add(user)
            session.commit()
            return user
        except Exception as e:
            session.rollback()
            print(f"Error creating user: {e}")
            return None
        finally:
            session.close()
    
    def get_user_by_username(self, username):
        session = self.Session()
        user = session.query(User).filter_by(username=username).first()
        session.close()
        return user
    
    # ========== Function/Disassembly Methods ==========
    
    def add_function(self, sample_id, address, name, size=0, is_import=False, decompiled_code=None):
        session = self.Session()
        try:
            func = Function(
                sample_id=sample_id,
                address=address,
                name=name,
                size=size,
                is_import=is_import,
                decompiled_code=decompiled_code
            )
            session.add(func)
            session.commit()
            return func
        except Exception as e:
            session.rollback()
            print(f"Error adding function: {e}")
            return None
        finally:
            session.close()
    
    def get_sample_functions(self, sample_id):
        session = self.Session()
        functions = session.query(Function).filter_by(sample_id=sample_id).all()
        session.close()
        return functions
    
    # ========== Sandbox Methods ==========
    
    def create_sandbox_run(self, sample_id, provider, task_id):
        session = self.Session()
        try:
            run = SandboxRun(
                sample_id=sample_id,
                provider=provider,
                task_id=task_id,
                status='pending'
            )
            session.add(run)
            session.commit()
            return run
        except Exception as e:
            session.rollback()
            print(f"Error creating sandbox run: {e}")
            return None
        finally:
            session.close()
    
    def update_sandbox_run(self, run_id, status=None, verdict=None, score=None, completed_at=None):
        session = self.Session()
        try:
            run = session.query(SandboxRun).filter_by(id=run_id).first()
            if run:
                if status:
                    run.status = status
                if verdict:
                    run.verdict = verdict
                if score is not None:
                    run.score = score
                if completed_at:
                    run.completed_at = completed_at
                session.commit()
            return run
        except Exception as e:
            session.rollback()
            print(f"Error updating sandbox run: {e}")
            return None
        finally:
            session.close()
    
    def get_sample_sandbox_runs(self, sample_id):
        session = self.Session()
        runs = session.query(SandboxRun).filter_by(sample_id=sample_id).all()
        session.close()
        return runs
    
    # ========== Threat Intel Methods ==========
    
    def add_threat_intel(self, sample_id, source, data_json):
        session = self.Session()
        try:
            existing = session.query(ThreatIntel).filter_by(
                sample_id=sample_id, source=source
            ).first()
            
            if existing:
                existing.data_json = data_json
                existing.updated_at = datetime.datetime.utcnow()
                intel = existing
            else:
                intel = ThreatIntel(
                    sample_id=sample_id,
                    source=source,
                    data_json=data_json
                )
                session.add(intel)
            
            session.commit()
            return intel
        except Exception as e:
            session.rollback()
            print(f"Error adding threat intel: {e}")
            return None
        finally:
            session.close()
    
    def get_sample_threat_intel(self, sample_id):
        session = self.Session()
        intel = session.query(ThreatIntel).filter_by(sample_id=sample_id).all()
        session.close()
        return intel
    
    # ========== Annotation Methods ==========
    
    def add_annotation(self, sample_id, user_id, annotation_type, target_type, target_value, content, color=None):
        session = self.Session()
        try:
            annotation = Annotation(
                sample_id=sample_id,
                user_id=user_id,
                annotation_type=annotation_type,
                target_type=target_type,
                target_value=target_value,
                content=content,
                color=color
            )
            session.add(annotation)
            session.commit()
            return annotation
        except Exception as e:
            session.rollback()
            print(f"Error adding annotation: {e}")
            return None
        finally:
            session.close()
    
    def get_sample_annotations(self, sample_id):
        session = self.Session()
        annotations = session.query(Annotation).filter_by(sample_id=sample_id).all()
        session.close()
        return annotations
    
    # ========== Activity Log Methods ==========
    
    def log_activity(self, user_id, project_id, action, target_type, target_id, details=None):
        session = self.Session()
        try:
            log = ActivityLog(
                user_id=user_id,
                project_id=project_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                details=details
            )
            session.add(log)
            session.commit()
            return log
        except Exception as e:
            session.rollback()
            print(f"Error logging activity: {e}")
            return None
        finally:
            session.close()
    
    def get_project_activity(self, project_id, limit=50):
        session = self.Session()
        activities = session.query(ActivityLog).filter_by(
            project_id=project_id
        ).order_by(ActivityLog.timestamp.desc()).limit(limit).all()
        session.close()
        return activities
