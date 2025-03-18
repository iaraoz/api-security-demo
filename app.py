from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os
import jwt
import datetime
import random
import hashlib
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_super_secreta_123'  # VULNERABILIDAD: Clave secreta hardcodeada
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo de usuario
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # 🔹 Columnas para MFA
    mfa_code = db.Column(db.String(6), nullable=True)
    mfa_expiration = db.Column(db.DateTime, nullable=True)
    mfa_attempts = db.Column(db.Integer, default=0)  # 🚨 Protección contra fuerza bruta
    mfa_locked_until = db.Column(db.DateTime, nullable=True)  # 

    
    
    def __repr__(self):
        return f'<Usuario {self.username}>'

# Inicializar la base de datos y agregar usuarios de prueba
def init_db():
    with app.app_context():
        db.create_all()
        
        # Verificar si ya existen usuarios
        if Usuario.query.count() == 0:
            # Agregar usuarios de prueba
            usuarios = [
                Usuario(id=1, username='admin', 
                       password=hashlib.sha256('admin123'.encode()).hexdigest(), 
                       email='admin@example.com', is_admin=True),
                Usuario(id=2, username='usuario1', 
                       password=hashlib.sha256('password123'.encode()).hexdigest(), 
                       email='usuario1@example.com', is_admin=False),
                Usuario(id=3, username='usuario2', 
                       password=hashlib.sha256('securepass'.encode()).hexdigest(), 
                       email='usuario2@example.com', is_admin=False)
            ]
            
            for usuario in usuarios:
                db.session.add(usuario)
            
            db.session.commit()

# Función para verificar token (decorator)
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if ' ' in auth_header:
                token = auth_header.split(" ")[1]
            
        if not token:
            return jsonify({'message': 'Token not found!'}), 401
            
        try:
            # VULNERABILIDAD: No se verifica el algoritmo (alg: none attack posible)
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = Usuario.query.filter_by(id=data['id']).first()
            
            if not current_user:
                raise Exception("Usuario no encontrado")
                
        except Exception as e:
            return jsonify({'message': f'Token inválido: {str(e)}'}), 401
            
        return f(current_user, *args, **kwargs)
        
    return decorated

# Ruta para login
@app.route('/api/login', methods=['POST'])
def login():
    auth = request.get_json()
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response('It could not be verified', 401, {'WWW-Authenticate': 'Basic realm="Login requiered"'})
    
    # VULNERABILIDAD 1: User enumeration via login responses
    # La consulta revela si el usuario existe o no
    user = Usuario.query.filter_by(username=auth.get('username')).first()
    
    if not user:
        # VULNERABILIDAD: Mensaje específico que revela que el usuario no existe
        return jsonify({'message': 'The user does no exist', 'error': 'user_not_found'}), 401
    
    # Verificar contraseña
    if hashlib.sha256(auth.get('password').encode()).hexdigest() == user.password:
        # Crear token JWT
        token = jwt.encode({
            'id': user.id,
            'username': user.username,
            'is_admin': user.is_admin,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({'token': token})
    
    # VULNERABILIDAD: Mensaje específico que revela que la contraseña es incorrecta
    return jsonify({'message': 'Invalid Password', 'error': 'invalid_password'}), 401

# Ruta para recuperar contraseña
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    
    if not data or not data.get('username'):
        return jsonify({'message': 'Se requiere nombre de usuario'}), 400
    
    # VULNERABILIDAD 2: User Enumeration via Forgot Password
    # La consulta revela si el usuario existe o no
    user = Usuario.query.filter_by(username=data.get('username')).first()
    
    if not user:
        # VULNERABILIDAD: Mensaje específico que revela que el usuario no existe
        return jsonify({'message': 'No account was found', 'error': 'user_not_found'}), 404
    
    # En una aplicación real, aquí se enviaría un correo electrónico para restablecer la contraseña
    return jsonify({'message': f'Se ha enviado un correo electrónico a {user.email} con instrucciones para restablecer la contraseña'})

# VULNERABILIDAD 3: Accesing unauthenticated endpoints
# Este endpoint debería estar protegido pero no lo está
@app.route('/api/users', methods=['GET'])
def get_users():
    users = Usuario.query.all()
    result = []
    
    for user in users:
        result.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        })
    
    return jsonify({'users': result})


# VULNERABILIDAD 4: JWT sin verificación de permisos
# Este endpoint debería verificar si el usuario es admin, pero solo verifica autenticación
@app.route('/api/admin/settings', methods=['GET'])
@token_required
def get_admin_settings(current_user):
    # VULNERABILIDAD: No se verifica si el usuario actual es administrador
    # Debería tener: if not current_user.is_admin: return jsonify({'message': 'No autorizado'}), 403
    
    return jsonify({
        'settings': {
            'maintenance_mode': False,
            'debug_mode': True,
            'api_keys': ['ak_test_12345', 'ak_prod_67890'],  # Información sensible
            'database_connection': app.config['SQLALCHEMY_DATABASE_URI']
        }
    })

# Endpoint para verificar vulnerabilidad de JWT
@app.route('/api/verify_token', methods=['GET'])
def verify_token():
    token = None
    
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if ' ' in auth_header:
            token = auth_header.split(" ")[1]
    
    if not token:
        return jsonify({'message': 'No token found'}), 401
    
    try:
        # VULNERABILIDAD: No se valida el algoritmo 'none'
        # Esto permite un ataque 'alg:none' donde se puede falsificar un token
        data = jwt.decode(token, options={"verify_signature": True}, algorithms=['HS256'])
        return jsonify({'valid': True, 'payload': data})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 401

def generar_codigo_mfa():
    return str(random.randint(100000, 999999))

# 1️⃣ Endpoint vulnerable: Generar MFA sin rate limiting

@app.route('/api/generate-mfa', methods=['POST'])
@token_required
def generate_mfa():
    data = request.get_json()
    user = Usuario.query.filter_by(username=data.get('username')).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user.mfa_code = generar_codigo_mfa()
    user.mfa_expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    db.session.commit()
    
    return jsonify({'message': 'MFA Code generated', 'mfa_code': user.mfa_code})  # ⚠️ Devuelve el código directamente

# 2️⃣ Endpoint vulnerable: Verificar MFA sin rate limiting

@app.route('/api/verify-mfa', methods=['POST'])
@token_required
def verify_mfa():
    data = request.get_json()
    user = Usuario.query.filter_by(username=data.get('username')).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    if user.mfa_code != data.get('mfa_code'):
        return jsonify({'message': 'Incorrect Code'}), 401  # ⚠️ Sin límite de intentos
    
    return jsonify({'message': 'MFA successfully verified'})

# 3️⃣ Endpoint vulnerable: Reset password sin rate limiting
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    user = Usuario.query.filter_by(username=data.get('username')).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user.password = hashlib.sha256(data.get('new_password').encode()).hexdigest()
    db.session.commit()
    
    return jsonify({'message': 'Password has benn reset'})  # ⚠️ Permite intentos ilimitados sin validación


# Inicializar la base de datos antes de ejecutar la aplicación
init_db()

if __name__ == '__main__':
    app.run(debug=True)