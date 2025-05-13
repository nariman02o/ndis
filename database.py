import os
import datetime
import json
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# Create base class for declarative models
Base = declarative_base()

# Define models
class Detection(Base):
    """Detection records for network packets analyzed by the NIDS"""
    __tablename__ = 'detections'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    src_ip = Column(String(50))
    dst_ip = Column(String(50))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    length = Column(Integer)
    is_malicious = Column(Boolean)
    confidence = Column(Float)
    feature_data = Column(Text)  # JSON string of features
    packet_data = Column(Text)  # JSON string of packet

    # Relationship with alerts
    alerts = relationship("Alert", back_populates="detection")

    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'length': self.length,
            'is_malicious': self.is_malicious,
            'confidence': self.confidence,
            'feature_data': json.loads(self.feature_data) if self.feature_data else None,
            'packet_data': json.loads(self.packet_data) if self.packet_data else None
        }

class Alert(Base):
    """Alerts generated for suspicious packets that need admin review"""
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True)
    detection_id = Column(Integer, ForeignKey('detections.id'))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String(20), default='pending')  # pending, confirmed, rejected
    admin_notes = Column(Text, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)

    # Relationship with detection
    detection = relationship("Detection", back_populates="alerts")

    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'detection_id': self.detection_id,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'admin_notes': self.admin_notes,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None
        }

class ModelFeedback(Base):
    """Feedback data for model retraining"""
    __tablename__ = 'model_feedback'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    feature_data = Column(Text)  # JSON string of features
    label = Column(Integer)  # 0 for benign, 1 for malicious
    alert_id = Column(Integer, ForeignKey('alerts.id'), nullable=True)

    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'feature_data': json.loads(self.feature_data) if self.feature_data else None,
            'label': self.label,
            'alert_id': self.alert_id
        }

class TrainingHistory(Base):
    """Record of model training sessions"""
    __tablename__ = 'training_history'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    model_type = Column(String(50))
    training_type = Column(String(20))  # initial, retraining
    dataset_size = Column(Integer)
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    false_positive_rate = Column(Float)
    training_time = Column(Float)  # seconds

    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'model_type': self.model_type,
            'training_type': self.training_type,
            'dataset_size': self.dataset_size,
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'false_positive_rate': self.false_positive_rate,
            'training_time': self.training_time
        }

class DPISignature(Base):
    """Deep Packet Inspection signatures for detecting attack patterns"""
    __tablename__ = 'dpi_signatures'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True)
    pattern = Column(Text)
    description = Column(Text, nullable=True)
    category = Column(String(50))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, 
                        onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'pattern': self.pattern,
            'description': self.description,
            'category': self.category,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class NIDSDatabase:
    """Database manager for the NIDS application"""

    def __init__(self, db_path='sqlite:///nids.db'):
        """Initialize the database connection"""
        self.engine = create_engine(db_path)
        self.Session = sessionmaker(bind=self.engine)
        self.session = None

    def initialize(self):
        """Initialize the database"""
        if not os.path.exists('nids.db'):
            print("Creating new database...")
        Base.metadata.create_all(self.engine)

    def get_session(self):
        """Get a new database session"""
        if self.session is None or not self.session.is_active:
            self.session = self.Session()
        return self.session

    def close_session(self):
        """Close the current database session"""
        if self.session:
            self.session.close()
            self.session = None

    # Detection methods
    def add_detection(self, packet, features, is_malicious, confidence):
        """Add a new detection record"""
        session = self.get_session()

        # Convert feature array to JSON string
        if hasattr(features, 'tolist'):
            feature_json = json.dumps(features.tolist())
        else:
            feature_json = json.dumps(features)

        # Create new detection record
        detection = Detection(
            timestamp=datetime.datetime.utcnow(),
            src_ip=packet.get('src', 'unknown'),
            dst_ip=packet.get('dst', 'unknown'),
            src_port=packet.get('sport', 0),
            dst_port=packet.get('dport', 0),
            protocol=packet.get('proto', 'unknown'),
            length=packet.get('len', 0),
            is_malicious=bool(is_malicious),
            confidence=float(confidence),
            feature_data=feature_json,
            packet_data=json.dumps(packet)
        )

        session.add(detection)
        session.commit()

        return detection.id

    def get_detections(self, limit=100, offset=0, is_malicious=None):
        """Get detection records with optional filtering"""
        session = self.get_session()

        query = session.query(Detection)

        if is_malicious is not None:
            query = query.filter(Detection.is_malicious == is_malicious)

        query = query.order_by(Detection.timestamp.desc())
        query = query.limit(limit).offset(offset)

        detections = query.all()
        return [d.to_dict() for d in detections]

    def get_detection_by_id(self, detection_id):
        """Get a specific detection by ID"""
        session = self.get_session()
        detection = session.query(Detection).filter(Detection.id == detection_id).first()

        if detection:
            return detection.to_dict()
        return None

    # Alert methods
    def add_alert(self, detection_id):
        """Add a new alert for admin review"""
        session = self.get_session()

        alert = Alert(
            detection_id=detection_id,
            timestamp=datetime.datetime.utcnow(),
            status='pending'
        )

        session.add(alert)
        session.commit()

        return alert.id

    def get_alerts(self, status=None, limit=100, offset=0):
        """Get alert records with optional filtering"""
        session = self.get_session()

        query = session.query(Alert)

        if status:
            query = query.filter(Alert.status == status)

        query = query.order_by(Alert.timestamp.desc())
        query = query.limit(limit).offset(offset)

        alerts = query.all()
        return [a.to_dict() for a in alerts]

    def update_alert_status(self, alert_id, status, admin_notes=None):
        """Update the status of an alert after admin review"""
        session = self.get_session()

        alert = session.query(Alert).filter(Alert.id == alert_id).first()

        if alert:
            alert.status = status
            alert.admin_notes = admin_notes
            alert.reviewed_at = datetime.datetime.utcnow()
            session.commit()
            return True

        return False

    # Feedback methods
    def add_feedback(self, features, label, alert_id=None):
        """Add feedback data for model retraining"""
        session = self.get_session()

        # Convert feature array to JSON string
        if hasattr(features, 'tolist'):
            feature_json = json.dumps(features.tolist())
        else:
            feature_json = json.dumps(features)

        feedback = ModelFeedback(
            timestamp=datetime.datetime.utcnow(),
            feature_data=feature_json,
            label=int(label),
            alert_id=alert_id
        )

        session.add(feedback)
        session.commit()

        return feedback.id

    def get_feedback_data(self, limit=1000):
        """Get feedback data for model retraining"""
        session = self.get_session()

        feedback_records = session.query(ModelFeedback).order_by(
            ModelFeedback.timestamp.desc()).limit(limit).all()

        return [
            {
                'features': json.loads(record.feature_data) if record.feature_data else None,
                'label': record.label,
                'timestamp': record.timestamp.isoformat()
            }
            for record in feedback_records
        ]

    # Training history methods
    def add_training_record(self, metrics, model_type='RL', training_type='initial', dataset_size=0, training_time=0):
        """Add a record of model training"""
        session = self.get_session()

        record = TrainingHistory(
            timestamp=datetime.datetime.utcnow(),
            model_type=model_type,
            training_type=training_type,
            dataset_size=dataset_size,
            accuracy=metrics.get('accuracy', 0.0),
            precision=metrics.get('precision', 0.0),
            recall=metrics.get('recall', 0.0),
            f1_score=metrics.get('f1', 0.0),
            false_positive_rate=metrics.get('false_positive_rate', 0.0),
            training_time=training_time
        )

        session.add(record)
        session.commit()

        return record.id

    def get_training_history(self, limit=20):
        """Get history of model training sessions"""
        session = self.get_session()

        records = session.query(TrainingHistory).order_by(
            TrainingHistory.timestamp.desc()).limit(limit).all()

        return [record.to_dict() for record in records]

    # DPI signature methods
    def add_dpi_signature(self, name, pattern, description=None, category='custom'):
        """Add a new DPI signature"""
        session = self.get_session()

        # Check if signature with same name exists
        existing = session.query(DPISignature).filter(DPISignature.name == name).first()

        if existing:
            # Update existing signature
            existing.pattern = pattern
            existing.description = description
            existing.category = category
            existing.updated_at = datetime.datetime.utcnow()
            session.commit()
            return existing.id

        # Create new signature
        signature = DPISignature(
            name=name,
            pattern=pattern,
            description=description,
            category=category,
            is_active=True
        )

        session.add(signature)
        session.commit()

        return signature.id

    def get_dpi_signatures(self, active_only=True):
        """Get all DPI signatures"""
        session = self.get_session()

        query = session.query(DPISignature)

        if active_only:
            query = query.filter(DPISignature.is_active == True)

        signatures = query.all()

        return [sig.to_dict() for sig in signatures]

    def toggle_dpi_signature(self, signature_id, is_active):
        """Enable or disable a DPI signature"""
        session = self.get_session()

        signature = session.query(DPISignature).filter(DPISignature.id == signature_id).first()

        if signature:
            signature.is_active = bool(is_active)
            signature.updated_at = datetime.datetime.utcnow()
            session.commit()
            return True

        return False

    def delete_dpi_signature(self, signature_id):
        """Delete a DPI signature"""
        session = self.get_session()

        signature = session.query(DPISignature).filter(DPISignature.id == signature_id).first()

        if signature:
            session.delete(signature)
            session.commit()
            return True

        return False

# Create global instance
db = NIDSDatabase()