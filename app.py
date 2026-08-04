from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flasgger import Swagger, swag_from
import mysql.connector
import jwt
from datetime import datetime, timedelta
from functools import wraps
from db import get_db
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_EXPIRATION_HOURS'] = 8

# ========== KONFIGURASI SWAGGER ==========
app.config['SWAGGER'] = {
    'title': 'API Sistem Pendaftaran Pasien',
    'uiversion': 3,
    'version': '1.0.0',
    'description': '''
## API Sistem Informasi Pendaftaran Pasien
**Tempat Praktik Mandiri Dokter (TPMD) dr. Nofi Liza Meliana**

---
### Autentikasi
API ini menggunakan **JWT (JSON Web Token)**. Untuk mengakses endpoint yang dilindungi:
1. Login melalui `POST /api/login` untuk mendapatkan token
2. Sertakan token di header setiap request:
   ```
   Authorization: Bearer <token>
   ```

### Role Pengguna
| Role | Akses |
|------|-------|
| `admin` | Akses penuh ke semua endpoint |
| `petugas` | Lihat & tambah pasien, buat kunjungan |
| `dokter` | Lihat pasien, lihat & update kunjungan |
    ''',
    'termsOfService': '',
    'contact': {
        'name': 'TPMD dr. Nofi Liza Meliana'
    },
    'securityDefinitions': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'Masukkan token dengan format: **Bearer &lt;token&gt;**'
        }
    },
    'security': [{'Bearer': []}],
    'tags': [
        {'name': 'Auth', 'description': 'Autentikasi pengguna'},
        {'name': 'Pasien', 'description': 'Manajemen data pasien'},
        {'name': 'Kunjungan', 'description': 'Manajemen kunjungan pasien'},
    ]
}
swagger = Swagger(app)

# ========== FUNGSI BANTUAN ==========
def generate_token(user_id, username, role):
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        return None

# ========== MIDDLEWARE ==========
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token missing'}), 401
        if token.startswith('Bearer '):
            token = token[7:]
        payload = decode_token(token)
        if not payload:
            return jsonify({'message': 'Token invalid or expired'}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.user.get('role') not in allowed_roles:
                return jsonify({'message': 'Forbidden: tidak punya akses'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ========== ENDPOINT LOGIN ==========
@app.route('/api/login', methods=['POST'])
def login():
    """
    Login pengguna dan dapatkan JWT token
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
              example: admin
            password:
              type: string
              example: admin123
    responses:
      200:
        description: Login berhasil, token dikembalikan
        schema:
          type: object
          properties:
            token:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
            user:
              type: object
              properties:
                id:
                  type: integer
                  example: 1
                username:
                  type: string
                  example: admin
                role:
                  type: string
                  example: admin
                nama_lengkap:
                  type: string
                  example: Administrator
      400:
        description: Username atau password tidak diisi
      401:
        description: Username atau password salah
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username dan password wajib diisi'}), 400
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    
    if not user:
        return jsonify({'message': 'Username atau password salah'}), 401
    
    # Karena password masih plain text di database, bandingkan langsung
    if password != user['passwordnya']:
        return jsonify({'message': 'Username atau password salah'}), 401
    
    token = generate_token(user['id_user'], user['username'], user['rolenya'])
    return jsonify({
        'token': token,
        'user': {
            'id': user['id_user'],
            'username': user['username'],
            'role': user['rolenya'],
            'nama_lengkap': user['nama_lengkap']
        }
    })

# ========== ENDPOINT PASIEN ==========
@app.route('/api/pasien', methods=['GET'])
@token_required
@role_required(['admin', 'petugas', 'dokter'])
def get_pasien():
    """
    Ambil semua data pasien
    ---
    tags:
      - Pasien
    security:
      - Bearer: []
    responses:
      200:
        description: Daftar semua pasien diurutkan dari ID terbaru
        schema:
          type: array
          items:
            $ref: '#/definitions/Pasien'
      401:
        description: Token tidak valid atau tidak ada
      403:
        description: Tidak punya akses
    definitions:
      Pasien:
        type: object
        properties:
          id_pasien:
            type: integer
            example: 1
          nama_pasien:
            type: string
            example: Fitriani Lestari
          jenis_pasien:
            type: string
            enum: [bpjs, umum]
            example: bpjs
          no_bpjs:
            type: string
            example: "0001234567890"
          no_nik:
            type: string
            example: "3201011501990001"
          alamat:
            type: string
            example: Jl. Merdeka No. 12, Jakarta
          tgl_lahir:
            type: string
            format: date
            example: "1990-01-15"
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM pasien ORDER BY id_pasien DESC")
    pasien = cursor.fetchall()
    cursor.close()
    db.close()
    return jsonify(pasien)

# tambah data pasien kedalam tabel pasien
@app.route('/api/pasien', methods=['POST'])
@token_required
@role_required(['admin', 'petugas'])
def create_pasien():
    """
    Tambah data pasien baru
    ---
    tags:
      - Pasien
    security:
      - Bearer: []
    parameters:
      - in: body 
        name: body
        required: true
        schema:
          type: object
          required:
            - nama_pasien
            - jenis_pasien
            - alamat
          properties:
            nama_pasien:
              type: string
              example: Budi Santoso
            jenis_pasien:
              type: string
              enum: [bpjs, umum]
              example: umum
            no_bpjs:
              type: string
              example: "0001234567891"
            no_nik:
              type: string
              example: "3201011501990002"
            alamat:
              type: string
              example: Jl. Melati No. 5, Bandung
            tgl_lahir:
              type: string
              format: date
              example: "1995-06-20"
    responses:
      201:
        description: Pasien berhasil ditambahkan
        schema:
          type: object
          properties:
            message:
              type: string
              example: Pasien berhasil ditambahkan
            id:
              type: integer
              example: 10
      401:
        description: Token tidak valid
      403:
        description: Role tidak diizinkan (hanya admin/petugas)
    """
    data = request.json
    db = get_db()
    cursor = db.cursor()
    sql = """
        INSERT INTO pasien (nama_pasien, jenis_pasien, no_bpjs, no_nik, alamat, tgl_lahir)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    cursor.execute(sql, (
        data['nama_pasien'],
        data['jenis_pasien'],
        data.get('no_bpjs'),
        data.get('no_nik'),
        data['alamat'],
        data.get('tgl_lahir')
    ))
    db.commit()
    last_id = cursor.lastrowid
    cursor.close()
    db.close()
    return jsonify({'message': 'Pasien berhasil ditambahkan', 'id': last_id}), 201

# edit data pasien kedalam tabel pasien
@app.route('/api/pasien/<int:id_pasien>', methods=['GET'])
@token_required
@role_required(['admin', 'petugas', 'dokter'])
def get_detail_pasien(id_pasien):
    """
    Ambil detail satu pasien berdasarkan ID
    ---
    tags:
      - Pasien
    security:
      - Bearer: []
    parameters:
      - in: path
        name: id_pasien
        type: integer
        required: true
        description: ID pasien
        example: 1
    responses:
      200:
        description: Detail data pasien
        schema:
          $ref: '#/definitions/Pasien'
      404:
        description: Pasien tidak ditemukan
      401:
        description: Token tidak valid
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM pasien WHERE id_pasien = %s", (id_pasien,))
    pasien = cursor.fetchone()
    cursor.close()
    db.close()
    
    if not pasien:
        return jsonify({'message': 'Pasien tidak ditemukan'}), 404
    
    return jsonify(pasien)

# edit data pasien (update)
@app.route("/api/pasien/<int:id_pasien>", methods=["PUT"])
@token_required
@role_required(["admin", "petugas"])
def update_pasien(id_pasien):
    """
    Update data pasien berdasarkan ID
    ---
    tags:
      - Pasien
    security:
      - Bearer: []
    parameters:
      - in: path
        name: id_pasien
        type: integer
        required: true
        example: 1
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - nama_pasien
            - jenis_pasien
            - alamat
          properties:
            nama_pasien:
              type: string
              example: Budi Santoso
            jenis_pasien:
              type: string
              enum: [bpjs, umum]
              example: bpjs
            no_bpjs:
              type: string
              example: "0001234567891"
            no_nik:
              type: string
              example: "3201011501990002"
            alamat:
              type: string
              example: Jl. Melati No. 5, Bandung
            tgl_lahir:
              type: string
              format: date
              example: "1995-06-20"
    responses:
      200:
        description: Data pasien berhasil diperbarui
      401:
        description: Token tidak valid
      403:
        description: Role tidak diizinkan
    """
    data = request.json
    db = get_db()
    cursor = db.cursor()
    sql = """
        UPDATE pasien 
        SET nama_pasien = %s, jenis_pasien = %s, no_bpjs = %s, no_nik = %s, alamat = %s, tgl_lahir = %s
        WHERE id_pasien = %s
    """
    cursor.execute(sql, (
        data["nama_pasien"],
        data["jenis_pasien"],
        data.get("no_bpjs"),
        data.get("no_nik"),
        data["alamat"],
        data.get("tgl_lahir"),
        id_pasien
    ))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"message": "Data pasien berhasil diperbarui"})

# hapus data pasien (delete)
@app.route("/api/pasien/<int:id_pasien>", methods=["DELETE"])
@token_required
@role_required(["admin"])
def delete_pasien(id_pasien):
    """
    Hapus data pasien berdasarkan ID
    ---
    tags:
      - Pasien
    security:
      - Bearer: []
    parameters:
      - in: path
        name: id_pasien
        type: integer
        required: true
        example: 1
    responses:
      200:
        description: Data pasien berhasil dihapus
      401:
        description: Token tidak valid
      403:
        description: Hanya admin yang dapat menghapus pasien
    """
    db = get_db()
    cursor = db.cursor()
    # Sebelum hapus pasien, biasanya data kunjungan pasien itu juga harus dipikirkan.
    # Tapi untuk simpelnya skripsi, kita hapus langsung saja.
    cursor.execute("DELETE FROM pasien WHERE id_pasien = %s", (id_pasien,))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"message": "Data pasien berhasil dihapus"})


# ========== CLOSE ENDPOINT PASIEN ==========

# ========== ENDPOINT KUNJUNGAN ==========
# PENTING: route dengan path statis (hari-ini, menunggu) harus di atas route dengan parameter (<int:>)

@app.route('/api/kunjungan/hari-ini', methods=['GET'])
@token_required
@role_required(['admin', 'petugas', 'dokter'])
def get_kunjungan_hari_ini():
    """
    Ambil semua kunjungan hari ini
    ---
    tags:
      - Kunjungan
    security:
      - Bearer: []
    responses:
      200:
        description: Daftar kunjungan hari ini (JOIN dengan nama pasien)
        schema:
          type: array
          items:
            $ref: '#/definitions/Kunjungan'
      401:
        description: Token tidak valid
    definitions:
      Kunjungan:
        type: object
        properties:
          id_kunjungan:
            type: integer
            example: 1
          pasien_id:
            type: integer
            example: 3
          nama_pasien:
            type: string
            example: Fitriani Lestari
          keluhan:
            type: string
            example: Demam dan batuk
          umur_saat_kunjungan:
            type: integer
            example: 32
          berat_badan:
            type: number
            example: 55.5
          tinggi_badan:
            type: number
            example: 160.0
          tensi_darah:
            type: string
            example: "120/80"
          suhu:
            type: number
            example: 37.2
          diagnosa:
            type: string
            example: Infeksi saluran pernapasan atas
          resep_obat:
            type: string
            example: Paracetamol 500mg 3x1
          status:
            type: string
            enum: [menunggu, hadir, tidak_hadir]
            example: menunggu
          tgl_kunjungan:
            type: string
            example: "2026-07-01 10:30:00"
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT k.*, p.nama_pasien 
        FROM kunjungan k
        JOIN pasien p ON k.pasien_id = p.id_pasien
        WHERE DATE(k.tgl_kunjungan) = CURDATE()
        ORDER BY k.tgl_kunjungan ASC
    """)
    hasil = cursor.fetchall()
    cursor.close()
    db.close()
    return jsonify(hasil)

# endpoint kunjungan dengan filter tanggal opsional
@app.route('/api/kunjungan/filter', methods=['GET'])
@token_required
@role_required(['admin', 'petugas', 'dokter'])
def get_kunjungan_filter():
    """
    Ambil kunjungan berdasarkan filter tanggal
    ---
    tags:
      - Kunjungan
    security:
      - Bearer: []
    parameters:
      - in: query
        name: tanggal
        type: string
        format: date
        required: false
        description: Filter tanggal format YYYY-MM-DD. Jika kosong, default hari ini.
        example: "2026-07-01"
    responses:
      200:
        description: Daftar kunjungan pada tanggal yang dipilih
        schema:
          type: array
          items:
            $ref: '#/definitions/Kunjungan'
      401:
        description: Token tidak valid
    """
    tanggal = request.args.get('tanggal')  # format: YYYY-MM-DD
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if tanggal:
        cursor.execute("""
            SELECT k.*, p.nama_pasien 
            FROM kunjungan k
            JOIN pasien p ON k.pasien_id = p.id_pasien
            WHERE DATE(k.tgl_kunjungan) = %s
            ORDER BY k.tgl_kunjungan ASC
        """, (tanggal,))
    else:
        cursor.execute("""
            SELECT k.*, p.nama_pasien 
            FROM kunjungan k
            JOIN pasien p ON k.pasien_id = p.id_pasien
            WHERE DATE(k.tgl_kunjungan) = CURDATE()
            ORDER BY k.tgl_kunjungan ASC
        """)
    hasil = cursor.fetchall()
    cursor.close()
    db.close()
    return jsonify(hasil)

@app.route('/api/kunjungan/menunggu', methods=['GET'])
@token_required
@role_required(['dokter', 'admin'])
def get_kunjungan_menunggu():
    """
    Ambil daftar antrian pasien yang sedang menunggu
    ---
    tags:
      - Kunjungan
    security:
      - Bearer: []
    responses:
      200:
        description: Daftar kunjungan dengan status menunggu, urut dari yang paling awal
        schema:
          type: array
          items:
            $ref: '#/definitions/Kunjungan'
      401:
        description: Token tidak valid
      403:
        description: Hanya dokter dan admin
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT k.*, p.nama_pasien 
        FROM kunjungan k
        JOIN pasien p ON k.pasien_id = p.id_pasien
        WHERE k.status = 'menunggu'
        ORDER BY k.tgl_kunjungan ASC
    """)
    hasil = cursor.fetchall()
    cursor.close()
    db.close()
    return jsonify(hasil)

@app.route('/api/kunjungan', methods=['POST'])
@token_required
@role_required(['admin', 'petugas'])
def create_kunjungan():
    """
    Buat kunjungan baru (daftarkan pasien)
    ---
    tags:
      - Kunjungan
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - pasien_id
            - keluhan
          properties:
            pasien_id:
              type: integer
              example: 3
            keluhan:
              type: string
              example: Demam tinggi dan pusing
            umur_saat_kunjungan:
              type: integer
              example: 32
            berat_badan:
              type: number
              example: 55.5
            tinggi_badan:
              type: number
              example: 160.0
            tensi_darah:
              type: string
              example: "120/80"
            suhu:
              type: number
              example: 37.2
    responses:
      201:
        description: Kunjungan berhasil dibuat, status otomatis menunggu
        schema:
          type: object
          properties:
            message:
              type: string
              example: Kunjungan berhasil dibuat
            id:
              type: integer
              example: 5
      401:
        description: Token tidak valid
      403:
        description: Hanya admin dan petugas
    """
    data = request.json
    db = get_db()
    cursor = db.cursor()
    
    # Cari dokter_id dengan role 'dokter'
    cursor.execute("SELECT id_user FROM users WHERE rolenya = 'dokter' LIMIT 1")
    dokter = cursor.fetchone()
    dokter_id = dokter[0] if dokter else 3
    
    sql = """
        INSERT INTO kunjungan (pasien_id, petugas_id, dokter_id, keluhan, umur_saat_kunjungan, 
                               berat_badan, tinggi_badan, tensi_darah, suhu, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'menunggu')
    """
    cursor.execute(sql, (
        data['pasien_id'],
        request.user['user_id'],
        dokter_id,
        data['keluhan'],
        data.get('umur_saat_kunjungan'),
        data.get('berat_badan'),
        data.get('tinggi_badan'),
        data.get('tensi_darah'),
        data.get('suhu')
    ))
    db.commit()
    last_id = cursor.lastrowid
    cursor.close()
    db.close()
    return jsonify({'message': 'Kunjungan berhasil dibuat', 'id': last_id}), 201

# ambil detail satu kunjungan (spesifik berdasarkan id)
@app.route("/api/kunjungan/<int:kunjungan_id>", methods=["GET"])
@token_required
@role_required(["admin", "petugas", "dokter"])
def get_detail_kunjungan(kunjungan_id):
    """
    Ambil detail satu kunjungan berdasarkan ID
    ---
    tags:
      - Kunjungan
    security:
      - Bearer: []
    parameters:
      - in: path
        name: kunjungan_id
        type: integer
        required: true
        example: 1
    responses:
      200:
        description: Detail kunjungan beserta nama pasien
        schema:
          $ref: '#/definitions/Kunjungan'
      404:
        description: Kunjungan tidak ditemukan
      401:
        description: Token tidak valid
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT k.*, p.nama_pasien 
        FROM kunjungan k
        JOIN pasien p ON k.pasien_id = p.id_pasien
        WHERE k.id_kunjungan = %s
    """, (kunjungan_id,))
    kunjungan = cursor.fetchone()
    cursor.close()
    db.close()
    
    if not kunjungan:
        return jsonify({"message": "Data kunjungan tidak ditemukan"}), 404
    
    return jsonify(kunjungan)

@app.route('/api/kunjungan/<int:kunjungan_id>', methods=['PUT'])
@token_required
@role_required(['dokter', 'admin', 'petugas'])
def update_kunjungan(kunjungan_id):
    """
    Update diagnosa, resep, dan status kunjungan (oleh dokter)
    ---
    tags:
      - Kunjungan
    security:
      - Bearer: []
    parameters:
      - in: path
        name: kunjungan_id
        type: integer
        required: true
        example: 1
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            diagnosa:
              type: string
              example: Infeksi saluran pernapasan atas (ISPA)
            resep_obat:
              type: string
              example: "Paracetamol 500mg 3x1, Amoxicillin 500mg 3x1"
            status:
              type: string
              enum: [menunggu, hadir, tidak_hadir]
              example: hadir
    responses:
      200:
        description: Kunjungan berhasil diperbarui
      400:
        description: Data tidak boleh kosong atau status tidak valid
      404:
        description: Kunjungan tidak ditemukan
      500:
        description: Error database
    """
    data = request.json
    if not data:
        return jsonify({'message': 'Data tidak boleh kosong'}), 400

    # Validasi nilai status sesuai ENUM di database
    allowed_status = ['menunggu', 'hadir', 'tidak_hadir']
    status = data.get('status', 'hadir')
    if status not in allowed_status:
        return jsonify({'message': f'Status tidak valid. Pilihan: {allowed_status}'}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            UPDATE kunjungan 
            SET diagnosa = %s, resep_obat = %s, status = %s
            WHERE id_kunjungan = %s
        """, (
            data.get('diagnosa'),
            data.get('resep_obat'),
            status,
            kunjungan_id
        ))
        db.commit()
        affected = cursor.rowcount
        cursor.close()
        db.close()
        if affected == 0:
            return jsonify({'message': f'Kunjungan ID {kunjungan_id} tidak ditemukan'}), 404
        return jsonify({'message': 'Kunjungan berhasil diperbarui'})
    except Exception as e:
        return jsonify({'message': f'Error database: {str(e)}'}), 500

# hapus data kunjungan (delete)
@app.route("/api/kunjungan/<int:kunjungan_id>", methods=["DELETE"])
@token_required
@role_required(["admin"])
def delete_kunjungan(kunjungan_id):
    """
    Hapus data kunjungan berdasarkan ID
    ---
    tags:
      - Kunjungan
    security:
      - Bearer: []
    parameters:
      - in: path
        name: kunjungan_id
        type: integer
        required: true
        example: 1
    responses:
      200:
        description: Data kunjungan berhasil dihapus
      401:
        description: Token tidak valid
      403:
        description: Hanya admin yang dapat menghapus kunjungan
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM kunjungan WHERE id_kunjungan = %s", (kunjungan_id,))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"message": "Data kunjungan berhasil dihapus"})


# ========== ENDPOINT KELOLA USER (ADMIN ONLY) ==========

@app.route('/api/users', methods=['GET'])
@token_required
@role_required(['admin'])
def get_users():
    """Ambil semua data user --- tags: [User] security: [{Bearer: []}] responses: {200: {description: Daftar user}}"""
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id_user, username, nama_lengkap, rolenya FROM users ORDER BY id_user ASC")
    users = cursor.fetchall()
    cursor.close()
    db.close()
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
@token_required
@role_required(['admin'])
def create_user():
    """Tambah user baru --- tags: [User] security: [{Bearer: []}] responses: {201: {description: User berhasil ditambahkan}}"""
    data = request.json
    if not data.get('username') or not data.get('password') or not data.get('rolenya'):
        return jsonify({'message': 'Username, password, dan role wajib diisi'}), 400
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id_user FROM users WHERE username = %s", (data['username'],))
        if cursor.fetchone():
            cursor.close()
            db.close()
            return jsonify({'message': 'Username sudah digunakan'}), 409
        cursor.close()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (username, passwordnya, nama_lengkap, rolenya) VALUES (%s, %s, %s, %s)",
            (data['username'], data['password'], data.get('nama_lengkap', ''), data['rolenya'])
        )
        db.commit()
        last_id = cursor.lastrowid
        cursor.close()
        db.close()
        return jsonify({'message': 'User berhasil ditambahkan', 'id': last_id}), 201
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['GET'])
@token_required
@role_required(['admin'])
def get_detail_user(user_id):
    """Ambil detail user --- tags: [User] security: [{Bearer: []}] responses: {200: {description: Detail user}}"""
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id_user, username, nama_lengkap, rolenya FROM users WHERE id_user = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()
    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404
    return jsonify(user)

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
@role_required(['admin'])
def update_user(user_id):
    """Update data user --- tags: [User] security: [{Bearer: []}] responses: {200: {description: User diperbarui}}"""
    data = request.json
    try:
        db = get_db()
        cursor = db.cursor()
        if data.get('password'):
            cursor.execute(
                "UPDATE users SET username=%s, passwordnya=%s, nama_lengkap=%s, rolenya=%s WHERE id_user=%s",
                (data['username'], data['password'], data.get('nama_lengkap', ''), data['rolenya'], user_id)
            )
        else:
            cursor.execute(
                "UPDATE users SET username=%s, nama_lengkap=%s, rolenya=%s WHERE id_user=%s",
                (data['username'], data.get('nama_lengkap', ''), data['rolenya'], user_id)
            )
        db.commit()
        cursor.close()
        db.close()
        return jsonify({'message': 'User berhasil diperbarui'})
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
@role_required(['admin'])
def delete_user(user_id):
    """Hapus user --- tags: [User] security: [{Bearer: []}] responses: {200: {description: User dihapus}}"""
    if user_id == request.user['user_id']:
        return jsonify({'message': 'Tidak dapat menghapus akun sendiri'}), 400
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM users WHERE id_user = %s", (user_id,))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({'message': 'User berhasil dihapus'})

# ========== ENDPOINT LAPORAN ==========

@app.route('/api/laporan/kunjungan', methods=['GET'])
@token_required
@role_required(['admin', 'dokter'])
def get_laporan_kunjungan():
    """Ambil laporan kunjungan dengan filter --- tags: [Laporan] security: [{Bearer: []}] responses: {200: {description: Data laporan}}"""
    tgl_dari  = request.args.get('tgl_dari')
    tgl_sampai = request.args.get('tgl_sampai')
    jenis_pasien = request.args.get('jenis_pasien')  # bpjs / umum / kosong = semua
    status_filter = request.args.get('status')       # menunggu / hadir / tidak_hadir / kosong = semua

    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        sql = """
            SELECT k.id_kunjungan, k.tgl_kunjungan, p.nama_pasien, p.jenis_pasien,
                   p.no_bpjs, p.no_nik, k.keluhan, k.diagnosa, k.resep_obat,
                   k.tensi_darah, k.suhu, k.berat_badan, k.tinggi_badan,
                   k.umur_saat_kunjungan, k.status
            FROM kunjungan k
            JOIN pasien p ON k.pasien_id = p.id_pasien
            WHERE 1=1
        """
        params = []

        if tgl_dari:
            sql += " AND DATE(k.tgl_kunjungan) >= %s"
            params.append(tgl_dari)
        if tgl_sampai:
            sql += " AND DATE(k.tgl_kunjungan) <= %s"
            params.append(tgl_sampai)
        if jenis_pasien and jenis_pasien in ['bpjs', 'umum']:
            sql += " AND p.jenis_pasien = %s"
            params.append(jenis_pasien)
        if status_filter and status_filter in ['menunggu', 'hadir', 'tidak_hadir']:
            sql += " AND k.status = %s"
            params.append(status_filter)

        sql += " ORDER BY k.tgl_kunjungan DESC"
        cursor.execute(sql, params)
        hasil = cursor.fetchall()
        cursor.close()
        db.close()

        # Konversi datetime ke string
        for row in hasil:
            if row.get('tgl_kunjungan'):
                row['tgl_kunjungan'] = str(row['tgl_kunjungan'])

        return jsonify({
            'total': len(hasil),
            'data': hasil
        })
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# ========== ROUTE TAMPILAN (FRONTEND) ==========
@app.route('/', methods=['GET'])
def home():
    return render_template('login.html')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/pasien', methods=['GET'])
def halaman_pasien():
    return render_template('pasien.html')

@app.route('/kunjungan', methods=['GET'])
def halaman_kunjungan():
    return render_template('kunjungan.html')

@app.route('/antrian', methods=['GET'])
def halaman_antrian():
    return render_template('antrian.html')

@app.route('/laporan', methods=['GET'])
def halaman_laporan():
    return render_template('laporan.html')

@app.route('/users', methods=['GET'])
def halaman_users():
    return render_template('users.html')

# ========== JALANKAN SERVER ==========
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)