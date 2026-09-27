import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

import pymongo
from bson.objectid import ObjectId

MONGO_URI = os.environ.get('MONGO_URI', '')
DB_NAME = os.environ.get('MONGO_DB_NAME', 'antiscam_db')

def get_db():
    if getattr(get_db, '_db', None) is not None:
        return get_db._db
    
    client = None
    if MONGO_URI:
        try:
            client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
            client.server_info()
            print(f"[MongoDB] Connected via MONGO_URI to database '{DB_NAME}'")
        except Exception as e:
            print(f"[MongoDB] Could not connect via MONGO_URI: {e}")
            client = None
            
    if client is None:
        try:
            client = pymongo.MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=1500)
            client.server_info()
            print(f"[MongoDB] Connected to local MongoDB (localhost:27017) database '{DB_NAME}'")
        except Exception:
            import mongomock
            print("[MongoDB] Local MongoDB daemon not detected. Using in-memory MongoMock database.")
            client = mongomock.MongoClient()

    get_db._db = client[DB_NAME]
    return get_db._db

def get_next_sequence(name):
    db = get_db()
    ret = db.counters.find_one_and_update(
        {'_id': name},
        {'$inc': {'seq': 1}},
        upsert=True,
        return_document=pymongo.ReturnDocument.AFTER
    )
    return ret['seq']

class QueryField:
    def __init__(self, name):
        self.name = name

    def desc(self):
        return (self.name, -1)

    def asc(self):
        return (self.name, 1)

    def __eq__(self, other):
        return {self.name: other}

    def __ne__(self, other):
        return {self.name: {'$ne': other}}

    def like(self, pattern):
        p = str(pattern).strip('%')
        return {self.name: {'$regex': p, '$options': 'i'}}

class MongoQuery:
    def __init__(self, model_cls, collection_name):
        self.model_cls = model_cls
        self.collection_name = collection_name
        self._filter = {}
        self._sort = None
        self._limit = None

    @property
    def collection(self):
        return get_db()[self.collection_name]

    def filter_by(self, **kwargs):
        nq = self._clone()
        for k, v in kwargs.items():
            if v is not None and v != '':
                nq._filter[k] = v
        return nq

    def filter(self, *criterions):
        nq = self._clone()
        for c in criterions:
            if isinstance(c, dict):
                # Handle Mongo expressions or dictionary filters
                if '$or' in c and '$or' in nq._filter:
                    nq._filter['$or'].extend(c['$or'])
                else:
                    nq._filter.update(c)
        return nq

    def order_by(self, *args):
        nq = self._clone()
        sort_list = []
        for a in args:
            if isinstance(a, tuple):
                sort_list.append(a)
            elif isinstance(a, str):
                if a.startswith('-'):
                    sort_list.append((a[1:], -1))
                else:
                    sort_list.append((a, 1))
            elif hasattr(a, 'desc'):
                sort_list.append((a.name, -1))
            elif hasattr(a, 'name'):
                sort_list.append((a.name, 1))
            else:
                sort_list.append(('created_at', -1))
        nq._sort = sort_list
        return nq

    def limit(self, n):
        nq = self._clone()
        nq._limit = n
        return nq

    def get(self, id_val):
        if id_val is None:
            return None
        doc = self.collection.find_one({'id': id_val})
        if not doc and isinstance(id_val, str):
            try:
                doc = self.collection.find_one({'id': int(id_val)})
            except ValueError:
                pass
        if not doc and ObjectId.is_valid(str(id_val)):
            doc = self.collection.find_one({'_id': ObjectId(str(id_val))})
        if doc:
            return self.model_cls._from_dict(doc)
        return None

    def first(self):
        cursor = self._build_cursor()
        for doc in cursor.limit(1):
            return self.model_cls._from_dict(doc)
        return None

    def first_or_404(self):
        res = self.first()
        if not res:
            from flask import abort
            abort(404)
        return res

    def all(self):
        cursor = self._build_cursor()
        return [self.model_cls._from_dict(doc) for doc in cursor]

    def count(self):
        return self.collection.count_documents(self._filter)

    def _build_cursor(self):
        cursor = self.collection.find(self._filter)
        if self._sort:
            cursor = cursor.sort(self._sort)
        if self._limit:
            cursor = cursor.limit(self._limit)
        return cursor

    def _clone(self):
        nq = MongoQuery(self.model_cls, self.collection_name)
        nq._filter = dict(self._filter)
        nq._sort = list(self._sort) if self._sort else None
        nq._limit = self._limit
        return nq

class ModelMeta(type):
    @property
    def query(cls):
        return MongoQuery(cls, cls.collection_name)

class BaseModel(metaclass=ModelMeta):
    collection_name = ''
    sequence_name = ''

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self._id = kwargs.get('_id')
        for k, v in kwargs.items():
            setattr(self, k, v)

    @classmethod
    def _from_dict(cls, data):
        if not data:
            return None
        return cls(**data)

    def to_dict(self):
        d = {}
        for k, v in self.__dict__.items():
            if k.startswith('_') and k != '_id':
                continue
            d[k] = v
        return d

    def save(self):
        db = get_db()
        col = db[self.collection_name]
        if not self.id:
            self.id = get_next_sequence(self.sequence_name)
        d = self.to_dict()
        col.replace_one({'id': self.id}, d, upsert=True)
        return self

class MongoDBSession:
    def add(self, item):
        item.save()

    def add_all(self, items):
        for item in items:
            item.save()

    def commit(self):
        pass

    def flush(self):
        pass

    def remove(self):
        pass

class MongoDB:
    def __init__(self, app=None):
        self.session = MongoDBSession()
        if app:
            self.init_app(app)

    def init_app(self, app):
        pass

    def create_all(self):
        db = get_db()
        try:
            db.users.create_index('email', unique=True)
            db.complaints.create_index('complaint_id', unique=True)
            db.complaints.create_index('user_id')
            db.complaints.create_index('category')
            db.complaints.create_index('status')
            db.complaints.create_index('phone_number')
            db.complaints.create_index('upi_id')
            db.complaints.create_index('website_url')
        except Exception as e:
            print(f"[MongoDB Index Warning] {e}")

    def drop_all(self):
        db = get_db()
        db.users.drop()
        db.complaints.drop()
        db.complaint_history.drop()
        db.counters.drop()

db = MongoDB()

class User(BaseModel):
    collection_name = 'users'
    sequence_name = 'users'

    id = QueryField('id')
    name = QueryField('name')
    email = QueryField('email')
    phone = QueryField('phone')
    role = QueryField('role')
    status = QueryField('status')
    created_at = QueryField('created_at')

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.name = kwargs.get('name', '')
        self.email = kwargs.get('email', '')
        self.phone = kwargs.get('phone', '')
        self.password_hash = kwargs.get('password_hash', '')
        self.role = kwargs.get('role', 'user')
        self.status = kwargs.get('status', 'active')
        created = kwargs.get('created_at')
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created)
            except Exception:
                created = datetime.utcnow()
        self.created_at = created or datetime.utcnow()

    @property
    def complaints(self):
        return Complaint.query.filter_by(user_id=self.id).order_by(('created_at', -1)).all()

    def __repr__(self):
        return f'<User {self.email} ({self.role})>'

class Complaint(BaseModel):
    collection_name = 'complaints'
    sequence_name = 'complaints'

    id = QueryField('id')
    complaint_id = QueryField('complaint_id')
    user_id = QueryField('user_id')
    title = QueryField('title')
    category = QueryField('category')
    description = QueryField('description')
    incident_date = QueryField('incident_date')
    incident_time = QueryField('incident_time')
    amount_lost = QueryField('amount_lost')
    payment_method = QueryField('payment_method')
    phone_number = QueryField('phone_number')
    email = QueryField('email')
    upi_id = QueryField('upi_id')
    website_url = QueryField('website_url')
    social_media_account = QueryField('social_media_account')
    evidence_filename = QueryField('evidence_filename')
    evidence_original_name = QueryField('evidence_original_name')
    additional_info = QueryField('additional_info')
    risk_score = QueryField('risk_score')
    risk_level = QueryField('risk_level')
    status = QueryField('status')
    admin_remarks = QueryField('admin_remarks')
    created_at = QueryField('created_at')
    updated_at = QueryField('updated_at')

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.complaint_id = kwargs.get('complaint_id', '')
        self.user_id = kwargs.get('user_id')
        self.title = kwargs.get('title', '')
        self.category = kwargs.get('category', '')
        self.description = kwargs.get('description', '')
        self.incident_date = kwargs.get('incident_date', '')
        self.incident_time = kwargs.get('incident_time', '')
        
        try:
            self.amount_lost = float(kwargs.get('amount_lost', 0.0))
        except (ValueError, TypeError):
            self.amount_lost = 0.0
            
        self.payment_method = kwargs.get('payment_method', '')
        self.phone_number = kwargs.get('phone_number', '')
        self.email = kwargs.get('email', '')
        self.upi_id = kwargs.get('upi_id', '')
        self.website_url = kwargs.get('website_url', '')
        self.social_media_account = kwargs.get('social_media_account', '')
        self.evidence_filename = kwargs.get('evidence_filename')
        self.evidence_original_name = kwargs.get('evidence_original_name')
        self.additional_info = kwargs.get('additional_info', '')
        
        try:
            self.risk_score = int(kwargs.get('risk_score', 0))
        except (ValueError, TypeError):
            self.risk_score = 0
            
        self.risk_level = kwargs.get('risk_level', 'LOW')
        
        r_reasons = kwargs.get('risk_reasons', kwargs.get('risk_reasons_json'))
        if isinstance(r_reasons, str):
            try:
                self._risk_reasons = json.loads(r_reasons)
            except Exception:
                self._risk_reasons = []
        else:
            self._risk_reasons = r_reasons or []

        self.status = kwargs.get('status', 'PENDING')
        self.admin_remarks = kwargs.get('admin_remarks', '')

        created = kwargs.get('created_at')
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created)
            except Exception:
                created = datetime.utcnow()
        self.created_at = created or datetime.utcnow()

        updated = kwargs.get('updated_at')
        if isinstance(updated, str):
            try:
                updated = datetime.fromisoformat(updated)
            except Exception:
                updated = datetime.utcnow()
        self.updated_at = updated or datetime.utcnow()

    @property
    def risk_reasons(self):
        return getattr(self, '_risk_reasons', [])

    @risk_reasons.setter
    def risk_reasons(self, value):
        if isinstance(value, str):
            try:
                self._risk_reasons = json.loads(value)
            except Exception:
                self._risk_reasons = []
        else:
            self._risk_reasons = value if value else []

    @property
    def risk_reasons_json(self):
        return json.dumps(self.risk_reasons)

    @property
    def user(self):
        return User.query.get(self.user_id)

    @property
    def history(self):
        return ComplaintHistory.query.filter_by(complaint_id=self.id).order_by(('updated_at', -1)).all()

    def to_dict(self):
        d = super().to_dict()
        d['risk_reasons'] = self.risk_reasons
        return d

    def __repr__(self):
        return f'<Complaint {self.complaint_id} - {self.status}>'

class ComplaintHistory(BaseModel):
    collection_name = 'complaint_history'
    sequence_name = 'complaint_history'

    id = QueryField('id')
    complaint_id = QueryField('complaint_id')
    status = QueryField('status')
    remarks = QueryField('remarks')
    updated_by_name = QueryField('updated_by_name')
    updated_at = QueryField('updated_at')

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.complaint_id = kwargs.get('complaint_id')
        self.status = kwargs.get('status', 'PENDING')
        self.remarks = kwargs.get('remarks', '')
        self.updated_by_name = kwargs.get('updated_by_name', 'System Admin')

        updated = kwargs.get('updated_at')
        if isinstance(updated, str):
            try:
                updated = datetime.fromisoformat(updated)
            except Exception:
                updated = datetime.utcnow()
        self.updated_at = updated or datetime.utcnow()

    def __repr__(self):
        return f'<ComplaintHistory {self.complaint_id} -> {self.status}>'
