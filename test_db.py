from db import get_db

try:
    conn = get_db()
    if conn.is_connected():
        print("Mantap! Koneksi ke database die_praxis berhasil.")
    conn.close()
except Exception as e:
    print(f"Waduh, error cuy: {e}")