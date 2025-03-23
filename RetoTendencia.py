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

# Crear la aplicación FastAPI
app = FastAPI()

# Variable global para cancelar la ejecución
cancel_attack_event = threading.Event()

# Clave AES-256 de 32 bytes (256 bits)
AES_KEY = get_random_bytes(32)

# Modelo de datos para recibir la clave cifrada
class CiphertextInput(BaseModel):
    ciphertext: str  # Clave cifrada en Base64
    iv: str  # Vector de Inicialización en Base64

# ------------------- Funciones de Criptografía -------------------

def generate_binary_key(bits: int = 128) -> str:
    """Genera una clave binaria aleatoria de longitud especificada.
    
    Args:
        bits: Número de bits de la clave (por defecto 128).
    
    Returns:
        Clave binaria como string.
    """
    return ''.join(random.choice('01') for _ in range(bits))

def encrypt_aes(key: str) -> tuple[str, str]:
    """Cifra una clave con AES-256 en modo CBC.
    
    Args:
        key: Clave a cifrar en formato string.
    
    Returns:
        Tuple con el texto cifrado y el IV, ambos en base64.
    """
    key_bytes = key.encode()
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pad_length = 16 - (len(key_bytes) % 16)
    padded_key = key_bytes + bytes([pad_length] * pad_length)
    encrypted_key = cipher.encrypt(padded_key)
    return (base64.b64encode(encrypted_key).decode(), 
            base64.b64encode(iv).decode())

def decrypt_aes(ciphertext: str, iv: str) -> str:
    """Descifra una clave cifrada con AES-256 en modo CBC.
    
    Args:
        ciphertext: Texto cifrado en base64.
        iv: Vector de inicialización en base64.
    
    Returns:
        Clave descifrada en formato string.
    
    Raises:
        ValueError: Si hay un error en el descifrado.
    """
    try:
        encrypted_key_bytes = base64.b64decode(ciphertext)
        iv_bytes = base64.b64decode(iv)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv_bytes)
        decrypted_padded_key = cipher.decrypt(encrypted_key_bytes)
        pad_length = decrypted_padded_key[-1]
        decrypted_key = decrypted_padded_key[:-pad_length]
        return decrypted_key.decode()
    except (ValueError, KeyError) as e:
        raise ValueError("Error al descifrar la clave. Verifique el ciphertext y el IV.") from e

# ------------------- Funciones Cuánticas -------------------

def oracle(qc: QuantumCircuit, key: str, n_bits: int) -> None:
    """Implementa el oráculo para el algoritmo de Grover.
    
    Args:
        qc: Circuito cuántico.
        key: Clave secreta en formato binario.
        n_bits: Número de bits de la clave.
    """
    for i, bit in enumerate(key):
        if bit == '0':
            qc.x(i)
    qc.mcx(list(range(n_bits)), n_bits)
    for i, bit in enumerate(key):
        if bit == '0':
            qc.x(i)

def diffuser(qc: QuantumCircuit, n_bits: int) -> None:
    """Implementa el difusor para el algoritmo de Grover.
    
    Args:
        qc: Circuito cuántico.
        n_bits: Número de bits de la clave.
    """
    qc.h(range(n_bits))
    qc.x(range(n_bits))
    qc.h(n_bits - 1)
    qc.mcx(list(range(n_bits - 1)), n_bits - 1)
    qc.h(n_bits - 1)
    qc.x(range(n_bits))
    qc.h(range(n_bits))

def grovers_algorithm(secret_key: str, n_bits: int = 128) -> QuantumCircuit:
    """Simula el algoritmo de Grover para encontrar la clave secreta durante el tiempo teórico completo.
    
    Advertencia: Ejecutar el número completo de iteraciones para n_bits=128 llevará un tiempo 
    extremadamente largo (miles de millones de años) y es impracticable en cualquier sistema real. 
    Use el endpoint /cancel para interrumpir el ataque manualmente.
    
    Args:
        secret_key: Clave secreta en formato binario.
        n_bits: Número de bits de la clave (por defecto 128).
    
    Returns:
        Circuito cuántico configurado o None si se cancela.
    """
    # Inicializar el circuito cuántico
    qc = QuantumCircuit(n_bits + 1, n_bits)
    qc.h(range(n_bits))  # Superposición inicial
    qc.x(n_bits)
    qc.h(n_bits)  # Preparar el qubit auxiliar

    # Registrar el inicio del ataque
    start_time = datetime.now().strftime("%H:%M:%S")
    print(f"Inicio del ataque a las {start_time}")

    # Calcular el número óptimo de iteraciones según la teoría de Grover
    iterations = int((3.14 / 4) * (2 ** (n_bits / 2)))
    print(f"Número total de iteraciones: {iterations}")

    # Ejecutar todas las iteraciones teóricas
    for i in range(iterations):
        if cancel_attack_event.is_set():
            print(f"Proceso interrumpido. Se realizaron {i} intentos.")
            return None
        print(f"Ejecutando iteración {i + 1} de {iterations}")
        oracle(qc, secret_key, n_bits)  # Aplicar el oráculo
        diffuser(qc, n_bits)  # Aplicar el difusor
        time.sleep(0.22)  # Retraso para simular tiempo de procesamiento

    # Medir los qubits
    qc.measure(range(n_bits), range(n_bits))
    return qc

# ------------------- Endpoints de la API -------------------

@app.get("/cifrado")
def generate_encrypted_key():
    """Genera una clave binaria aleatoria y la cifra con AES-256.
    
    Returns:
        Diccionario con el texto cifrado y el IV.
    """
    binary_key = generate_binary_key()
    ciphertext, iv = encrypt_aes(binary_key)
    return {"ciphertext": ciphertext, "iv": iv}

@app.post("/ataque")
def quantum_attack(data: CiphertextInput):
    """Simula un ataque cuántico para encontrar la clave cifrada durante el tiempo teórico completo.
    
    Args:
        data: Objeto con el texto cifrado y el IV.
    
    Returns:
        Resultados del ataque cuántico.
    
    Raises:
        HTTPException: Si hay un error en el descifrado.
    """
    global cancel_attack_event
    cancel_attack_event.clear()

    # Descifrar la clave recibida
    try:
        decrypted_key = decrypt_aes(data.ciphertext, data.iv)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Convertir la clave descifrada a binario (128 bits)
    binary_key = ''.join(format(byte, '08b') for byte in decrypted_key.encode())[:128]

    # Ejecutar el algoritmo de Grover
    qc = grovers_algorithm(binary_key)
    if qc is None:
        return {"message": "Ataque cancelado por el usuario."}

    # Simular el circuito cuántico
    backend = Aer.get_backend('qasm_simulator')
    tq = transpile(qc, backend)
    job = backend.run(tq, shots=1024)
    result = job.result()
    counts = result.get_counts()

    return {
        "ciphertext": data.ciphertext,
        "binary_key": binary_key,
        "attack_results": counts,
    }

@app.get("/cancel")
def cancel_attack():
    """Cancela el ataque cuántico en curso.
    
    Returns:
        Mensaje de confirmación.
    """
    cancel_attack_event.set()
    return {"message": "El ataque cuántico ha sido cancelado."}

# Ejecutar con: uvicorn RetoTendencia:app --reload