from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
import time
import threading
import random
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

app = FastAPI()

AES_KEY = get_random_bytes(32)

# Variables para el hilo infinito
cancel_attack_event = threading.Event()
infinite_thread = None

# Modelo para recibir la clave personalizada
class KeyInput(BaseModel):
    key: str  # Clave a encriptar

class CiphertextInput(BaseModel):
    ciphertext: str  # Clave cifrada en Base64
    iv: str  # Vector de Inicialización en Base64

def encrypt_aes(key: str) -> tuple[str, str]:
    """Cifra una clave con AES-256 en modo CBC."""
    key_bytes = key.encode()
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pad_length = 16 - (len(key_bytes) % 16)
    padded_key = key_bytes + bytes([pad_length] * pad_length)
    encrypted_key = cipher.encrypt(padded_key)
    return (base64.b64encode(encrypted_key).decode(), 
            base64.b64encode(iv).decode())

def decrypt_aes(ciphertext: str, iv: str) -> str:
    """Descifra una clave cifrada con AES-256 en modo CBC."""
    try:
        encrypted_key_bytes = base64.b64decode(ciphertext)
        iv_bytes = base64.b64decode(iv)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv_bytes)
        decrypted_padded_key = cipher.decrypt(encrypted_key_bytes)
        pad_length = decrypted_padded_key[-1]
        decrypted_key = decrypted_padded_key[:-pad_length]
        return decrypted_key.decode()
    except (ValueError, KeyError):
        # Lanza un error para indicar que el descifrado falló
        raise ValueError("Error al descifrar la clave.")

def infinite_decrypt_simulation():
    """Simula intentos infinitos de descifrado en un hilo separado."""
    attempt = 1
    start_time = datetime.now()
    print(f"Ataque iniciado a las: {start_time.strftime('%H:%M:%S')}")
    while not cancel_attack_event.is_set():
        print(f"Intentando descifrar... (Intento {attempt})")
        time.sleep(1)  
        attempt += 1
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"Proceso de descifrado cancelado a las: {end_time.strftime('%H:%M:%S')}")
    print(f"Duración total del ataque: {duration.total_seconds():.2f} segundos")

@app.post("/cifrado")
def encrypt_custom_key(data: KeyInput):
    """Cifra una clave proporcionada por el usuario con AES-256."""
    if len(data.key) == 0:
        raise HTTPException(status_code=400, detail="La clave no puede estar vacía.")
    ciphertext, iv = encrypt_aes(data.key)
    print(f"Clave original a cifrar: {data.key}")
    print(f"Texto cifrado (Base64): {ciphertext}")
    print(f"IV (Base64): {iv}")
    return {"ciphertext": ciphertext, "iv": iv}

@app.post("/ataque")
def quantum_attack(data: CiphertextInput):
    """Simula un ataque cuántico para encontrar la clave cifrada."""
    global cancel_attack_event, infinite_thread

    # Reiniciar el evento de cancelación
    cancel_attack_event.clear()
    
    start_time = datetime.now()
    print(f"Intento de descifrado iniciado a las: {start_time.strftime('%H:%M:%S')}")

    # Intentar descifrar la clave
    try:
        decrypted_key = decrypt_aes(data.ciphertext, data.iv)
        end_time = datetime.now()
        duration = end_time - start_time
        print(f"Clave desencriptada: {decrypted_key}")
        print(f"Descifrado completado a las: {end_time.strftime('%H:%M:%S')}")
        print(f"Tiempo total de descifrado: {duration.total_seconds():.2f} segundos")
        return {
            "ciphertext": data.ciphertext,
            "decrypted_key": decrypted_key,
            "message": "Clave descifrada exitosamente.",
            "start_time": start_time.strftime('%H:%M:%S'),
            "end_time": end_time.strftime('%H:%M:%S'),
            "duration_seconds": f"{duration.total_seconds():.2f}"
        }
    except ValueError:
        # Si falla el descifrado, iniciar un hilo infinito
        if infinite_thread is None or not infinite_thread.is_alive():
            infinite_thread = threading.Thread(target=infinite_decrypt_simulation)
            infinite_thread.daemon = True  # Permite matar el hilo al cerrar el programa
            infinite_thread.start()
        
        # Respuesta inmediata indicando que el descifrado está en progreso
        return {
            "message": "Intentando descifrar... Puede tomar tiempo.",
            "start_time": start_time.strftime('%H:%M:%S')
        }

@app.get("/cancel")
def cancel_attack():
    """Cancela el ataque cuántico en curso."""
    global cancel_attack_event
    cancel_attack_event.set()
    end_time = datetime.now()
    print(f"El ataque cuántico ha sido cancelado a las: {end_time.strftime('%H:%M:%S')}")
    return {
        "message": "El ataque cuántico ha sido cancelado.",
        "end_time": end_time.strftime('%H:%M:%S')
    }

# Ejecutar con: uvicorn CopiaRetoSimple:app --reload