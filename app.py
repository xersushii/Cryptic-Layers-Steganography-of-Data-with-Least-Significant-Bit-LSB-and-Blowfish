from flask import (
    Flask,
    render_template,
    request,
    send_file,
    flash,
    redirect,
    url_for,
    session
)

from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from PIL import Image
import base64
import re
import os
import uuid
import sys

# =====================================================
# FIXED PATH HANDLING (WORKS FOR .py AND .exe)
# =====================================================

def get_base_path():
    if getattr(sys, 'frozen', False):
        # Running as executable
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

BASE_PATH = get_base_path()

TEMPLATE_FOLDER = os.path.join(BASE_PATH, "templates")
UPLOAD_FOLDER = os.path.join(BASE_PATH, "uploads")

# Create uploads folder if missing
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, template_folder=TEMPLATE_FOLDER)
app.secret_key = "cryptic_layer_secret"

# ================= FILE VALIDATION =================

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

def allowed_file(filename):
    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )

# ================= KEY VALIDATION =================

def validate_key(key):

    if len(key) < 8:
        return "Key must be at least 8 characters"

    if not re.search(r"[A-Z]", key):
        return "Need uppercase letter"

    if not re.search(r"[a-z]", key):
        return "Need lowercase letter"

    if not re.search(r"\\d", key):
        return "Need number"

    if not re.search(r"[!@#$%^&*]", key):
        return "Need special character"

    return None

# ================= REAL IMAGE VALIDATION =================

def validate_image_file(file):

    if not allowed_file(file.filename):
        return False

    try:
        img = Image.open(file)
        img.verify()
        file.seek(0)

    except Exception:
        return False

    return True

# ================= SECURE KEY =================

def derive_secure_key(password, salt):
    return PBKDF2(
        password,
        salt,
        dkLen=16,
        count=200000,
        hmac_hash_module=SHA256
    )

# ================= BLOWFISH ENCRYPT =================

def blowfish_encrypt(text, password):

    salt = get_random_bytes(16)

    key = derive_secure_key(password, salt)

    cipher = Blowfish.new(
        key,
        Blowfish.MODE_ECB
    )

    padded = pad(
        text.encode(),
        Blowfish.block_size
    )

    encrypted = cipher.encrypt(padded)

    final_data = salt + encrypted

    return base64.b64encode(final_data).decode()

# ================= BLOWFISH DECRYPT =================

def blowfish_decrypt(ciphertext, password):

    raw = base64.b64decode(ciphertext)

    salt = raw[:16]
    encrypted = raw[16:]

    key = derive_secure_key(password, salt)

    cipher = Blowfish.new(
        key,
        Blowfish.MODE_ECB
    )

    decrypted = unpad(
        cipher.decrypt(encrypted),
        Blowfish.block_size
    )

    return decrypted.decode()

# ================= LSB EMBED =================

def embed_data(image_path, ciphertext, output_path):

    img = Image.open(image_path).convert("RGB")

    ciphertext += "###END###"

    binary = ''.join(
        format(ord(i), '08b')
        for i in ciphertext
    )

    pixels = img.load()

    max_capacity = img.width * img.height * 3

    if len(binary) > max_capacity:

        raise ValueError(
            "Image too small to hold the encrypted data. "
            "Please use a larger image."
        )

    index = 0

    for y in range(img.height):
        for x in range(img.width):

            pixel = list(pixels[x, y])

            for i in range(3):
                if index < len(binary):

                    pixel[i] = (
                        pixel[i] & ~1 |
                        int(binary[index])
                    )

                    index += 1

            pixels[x, y] = tuple(pixel)

            if index >= len(binary):
                break

        if index >= len(binary):
            break

    img.save(output_path)

# ================= LSB EXTRACT =================

def extract_data(image_path):

    img = Image.open(image_path).convert("RGB")

    pixels = img.load()

    binary_data = ""
    text = ""

    for y in range(img.height):
        for x in range(img.width):

            pixel = pixels[x, y]

            for i in range(3):

                binary_data += str(pixel[i] & 1)

                if len(binary_data) % 8 == 0:

                    byte = binary_data[-8:]

                    char = chr(int(byte, 2))

                    text += char

                    if text.endswith("###END###"):

                        return text.replace(
                            "###END###",
                            ""
                        )

    raise ValueError(
        "No hidden data found or image corrupted."
    )

# ================= HOME =================

@app.route("/")
def home():
    return render_template("index.html")

# ================= ENCRYPT =================

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():

    if request.method == "POST":

        plaintext = request.form.get("plaintext")
        key = request.form.get("key")
        image = request.files.get("image")

        if not plaintext or not key or not image:

            flash("All fields are required.")
            return redirect(url_for("encrypt"))

        if not validate_image_file(image):

            flash(
                "Only valid PNG, JPG, JPEG images allowed."
            )

            return redirect(url_for("encrypt"))

        error = validate_key(key)

        if error:

            flash(error)
            return redirect(url_for("encrypt"))

        input_path = os.path.join(
            UPLOAD_FOLDER,
            f"{uuid.uuid4()}.png"
        )

        output_path = os.path.join(
            UPLOAD_FOLDER,
            f"encrypted_{uuid.uuid4()}.png"
        )

        image.save(input_path)

        try:

            ciphertext = blowfish_encrypt(
                plaintext,
                key
            )

            embed_data(
                input_path,
                ciphertext,
                output_path
            )

            os.remove(input_path)

            session.pop("_flashes", None)

            return send_file(
                output_path,
                as_attachment=True,
                download_name="encrypted_image.png"
            )

        except Exception as e:

            flash(str(e))

            if os.path.exists(input_path):
                os.remove(input_path)

            return redirect(url_for("encrypt"))

    return render_template("encrypt.html")

# ================= DECRYPT =================

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():

    extracted_text = ""

    if request.method == "POST":

        key = request.form.get("key")
        image = request.files.get("image")

        if not key or not image:

            flash("Missing key or image.")
            return redirect(url_for("decrypt"))

        if not validate_image_file(image):

            flash(
                "Only valid PNG, JPG, JPEG allowed."
            )

            return redirect(url_for("decrypt"))

        image_path = os.path.join(
            UPLOAD_FOLDER,
            f"{uuid.uuid4()}.png"
        )

        image.save(image_path)

        try:

            ciphertext = extract_data(
                image_path
            )

            plaintext = blowfish_decrypt(
                ciphertext,
                key
            )

            extracted_text = plaintext

            session.pop("_flashes", None)

        except Exception:

            flash("Decryption failed.")

        if os.path.exists(image_path):
            os.remove(image_path)

        return render_template(
            "decrypt.html",
            extracted_text=extracted_text
        )

    return render_template("decrypt.html")

# ================= RUN =================

import webbrowser
import threading

def open_browser():
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == "__main__":
    threading.Timer(1, open_browser).start()
    app.run()