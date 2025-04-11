#!/usr/bin/env python3
import sys
import os

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import json
import re
import shutil
import struct
import codecs
import time
import hashlib
import subprocess
import webbrowser
from datetime import datetime
from base64 import urlsafe_b64encode, urlsafe_b64decode
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import*
from PyQt5.QtWebEngineWidgets import QWebEngineView
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20, Salsa20, CAST, DES, ARC4
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, SHA512, MD5, RIPEMD160, SHA1, SHA3_256, SHA3_512
from Crypto.Protocol.KDF import PBKDF2, bcrypt, scrypt
import pyAesCrypt
import base64
import hashlib
import hmac
import zlib
import random
import string
import subprocess
import platform
# Добавляем импорт QTermWidget
from PyQt5.QtWidgets import QApplication
 
# Создаем собственный класс терминала
class CustomTerminalWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.process = None
        self.startTerminal()
        
    def initUI(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем текстовый виджет для вывода терминала
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #DCDCDC;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
                border: none;
            }
        """)
        
        # Создаем поле ввода для команд
        self.command_input = QLineEdit()
        self.command_input.setStyleSheet("""
            QLineEdit {
                background-color: #1E1E1E;
                color: #DCDCDC;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
                border: 1px solid #333333;
                padding: 5px;
            }
        """)
        self.command_input.returnPressed.connect(self.executeCommand)
        
        # Добавляем виджеты в layout
        self.layout.addWidget(self.terminal_output)
        self.layout.addWidget(self.command_input)
        
    def startTerminal(self):
        """Запускает процесс терминала"""
        if platform.system() == 'Windows':
            # Используем кодировку cp866 для Windows
            self.process = subprocess.Popen(
                ['cmd.exe'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                encoding='cp866',
                errors='replace',
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:
            # Используем UTF-8 для Unix-подобных систем
            self.process = subprocess.Popen(
                ['/bin/bash'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                encoding='utf-8',
                errors='replace'
            )
        
        # Запускаем поток для чтения вывода
        self.reader_thread = QThread()
        self.reader = TerminalReader(self.process)
        self.reader.moveToThread(self.reader_thread)
        self.reader.output_ready.connect(self.appendOutput)
        self.reader_thread.started.connect(self.reader.run)
        self.reader_thread.start()
        
    def executeCommand(self):
        """Выполняет команду из поля ввода"""
        command = self.command_input.text()
        if command:
            # Добавляем команду в вывод
            self.appendOutput(f"\n$ {command}\n")
            
            # Отправляем команду в процесс
            if self.process and self.process.poll() is None:
                try:
                    self.process.stdin.write(command + "\n")
                    self.process.stdin.flush()
                except Exception as e:
                    self.appendOutput(f"Ошибка: {str(e)}\n")
            
            # Очищаем поле ввода
            self.command_input.clear()
    
    def appendOutput(self, text):
        """Добавляет текст в вывод терминала"""
        self.terminal_output.append(text)
        # Прокручиваем вниз
        self.terminal_output.verticalScrollBar().setValue(
            self.terminal_output.verticalScrollBar().maximum()
        )
    
    def clearTerminal(self):
        """Очищает вывод терминала"""
        self.terminal_output.clear()
        self.appendOutput("Терминал очищен\n")
    
    def closeEvent(self, event):
        """Обрабатывает закрытие виджета"""
        if self.process:
            self.process.terminate()
        if hasattr(self, 'reader_thread'):
            self.reader_thread.quit()
            self.reader_thread.wait()
        super().closeEvent(event)

class TerminalReader(QObject):
    output_ready = pyqtSignal(str)
    
    def __init__(self, process):
        super().__init__()
        self.process = process
        self.running = True
    
    def run(self):
        """Читает вывод из процесса и отправляет его через сигнал"""
        while self.running and self.process.poll() is None:
            try:
                output = self.process.stdout.readline()
                if output:
                    self.output_ready.emit(output)
            except Exception as e:
                self.output_ready.emit(f"Ошибка чтения: {str(e)}\n")
                break
        
        # Читаем оставшийся вывод
        try:
            remaining_output = self.process.stdout.read()
            if remaining_output:
                self.output_ready.emit(remaining_output)
        except:
            pass

class EncryptionWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, input_file, output_file, key, method, mode='encrypt'):
        super().__init__()
        self.input_file = input_file
        self.output_file = output_file
        self.key = key
        self.method = method
        self.mode = mode
        # Get reference to the main window's plugins
        self.plugins = QApplication.instance().activeWindow().plugins

    def run(self):
        try:
            # Check if this is a plugin method
            if self.method in self.plugins:
                self._handle_plugin()
            elif self.method == 'Fernet':
                self._handle_fernet()
            elif self.method == 'AES':
                self._handle_aes()
            elif self.method == 'AES-CBC':
                self._handle_aes_cbc()
            elif self.method == 'RSA':
                self._handle_rsa()
            elif self.method == 'ChaCha20':
                self._handle_chacha20()
            elif self.method == 'Salsa20':
                self._handle_salsa20()
            elif self.method == 'CAST':
                self._handle_cast()
            elif self.method == 'DES':
                self._handle_des()
            elif self.method == 'ARC4':
                self._handle_arc4()
            elif self.method == 'SHA256':
                self._handle_sha256()
            elif self.method == 'SHA512':
                self._handle_sha512()
            elif self.method == 'MD5':
                self._handle_md5()
            elif self.method == 'RIPEMD160':
                self._handle_ripemd160()
            elif self.method == 'SHA1':
                self._handle_sha1()
            elif self.method == 'SHA3_256':
                self._handle_sha3_256()
            elif self.method == 'SHA3_512':
                self._handle_sha3_512()
            elif self.method == 'PBKDF2':
                self._handle_pbkdf2()
            elif self.method == 'bcrypt':
                self._handle_bcrypt()
            elif self.method == 'scrypt':
                self._handle_scrypt()
            elif self.method == 'HMAC':
                self._handle_hmac()
            elif self.method == 'zlib':
                self._handle_zlib()
            
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

    def _handle_plugin(self):
        """Handles encryption/decryption using a plugin"""
        try:
            plugin = self.plugins[self.method]
            
            # Read input file
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            # Process data using plugin
            if self.mode == 'encrypt':
                processed_data = plugin.encrypt(data, self.key)
            else:
                processed_data = plugin.decrypt(data, self.key)
            
            # Write output file
            with open(self.output_file, 'wb') as file:
                file.write(processed_data)
                
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка плагина {self.method}: {str(e)}")

    def _handle_fernet(self):
        try:
            # Генерируем ключ Fernet, если он не предоставлен
            if not self.key:
                self.key = Fernet.generate_key()
            else:
                # Преобразуем ключ в правильный формат Fernet (32 байта, закодированные в base64)
                if isinstance(self.key, str):
                    # Если ключ - строка, преобразуем его в байты и хешируем
                    key_bytes = self.key.encode()
                    key_hash = hashlib.sha256(key_bytes).digest()
                    self.key = base64.urlsafe_b64encode(key_hash)
                else:
                    # Если ключ - байты, хешируем и кодируем
                    key_hash = hashlib.sha256(self.key).digest()
                    self.key = base64.urlsafe_b64encode(key_hash)
            
            # Создаем экземпляр Fernet с ключом
            f = Fernet(self.key)
            
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            # Шифруем или дешифруем данные
            if self.mode == 'encrypt':
                encrypted_data = f.encrypt(data)
            else:
                encrypted_data = f.decrypt(data)
            
            # Записываем результат в выходной файл
            with open(self.output_file, 'wb') as file:
                file.write(encrypted_data)
                
            # Обновляем прогресс
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка Fernet: {str(e)}")

    def _handle_aes(self):
        try:
            key = self.key.encode('utf-8')
            key = pad(key, AES.block_size)[:32]
            cipher = AES.new(key, AES.MODE_ECB)
            
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                encrypted_data = cipher.encrypt(pad(data, AES.block_size))
            else:
                try:
                    encrypted_data = unpad(cipher.decrypt(data), AES.block_size)
                except ValueError as e:
                    # Обработка ошибки при неправильном паддинге
                    self.error.emit(f"Ошибка при расшифровке AES (неверный ключ или формат): {str(e)}")
                    return
            
            with open(self.output_file, 'wb') as file:
                file.write(encrypted_data)
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка AES: {str(e)}")

    def _handle_aes_cbc(self):
        try:
            buffer_size = 64 * 1024
            if self.mode == 'encrypt':
                pyAesCrypt.encryptFile(self.input_file, self.output_file, self.key, buffer_size)
            else:
                try:
                    pyAesCrypt.decryptFile(self.input_file, self.output_file, self.key, buffer_size)
                except ValueError as e:
                    # Обработка ошибки при неправильном паддинге
                    self.error.emit(f"Ошибка при расшифровке AES-CBC (неверный ключ или формат): {str(e)}")
                    return
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка AES-CBC: {str(e)}")
            
    def _handle_rsa(self):
        # For RSA, we need to handle key generation differently
        if self.mode == 'encrypt':
            # Generate RSA key pair
            key = RSA.generate(2048)
            private_key = key
            public_key = key.publickey()
            
            # Save keys to files
            with open("private_key.pem", "wb") as f:
                f.write(private_key.export_key())
            with open("public_key.pem", "wb") as f:
                f.write(public_key.export_key())
                
            # Encrypt with public key
            cipher = PKCS1_OAEP.new(public_key)
            with open(self.input_file, 'rb') as file:
                data = file.read()
                
            # RSA can only encrypt data up to key size - 42 bytes
            # For larger files, we need to chunk the data
            chunk_size = 190  # 2048 bits = 256 bytes, -42 for padding
            encrypted_chunks = []
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                encrypted_chunk = cipher.encrypt(chunk)
                encrypted_chunks.append(encrypted_chunk)
                
            # Write encrypted data with chunk size as header
            with open(self.output_file, 'wb') as file:
                # Write number of chunks
                file.write(len(encrypted_chunks).to_bytes(4, byteorder='big'))
                # Write each chunk
                for chunk in encrypted_chunks:
                    file.write(len(chunk).to_bytes(4, byteorder='big'))
                    file.write(chunk)
        else:
            # Decrypt with private key
            with open("private_key.pem", "rb") as f:
                private_key = RSA.import_key(f.read())
                
            cipher = PKCS1_OAEP.new(private_key)
            
            with open(self.input_file, 'rb') as file:
                # Read number of chunks
                num_chunks = int.from_bytes(file.read(4), byteorder='big')
                decrypted_data = bytearray()
                
                # Read and decrypt each chunk
                for _ in range(num_chunks):
                    chunk_size = int.from_bytes(file.read(4), byteorder='big')
                    chunk = file.read(chunk_size)
                    decrypted_chunk = cipher.decrypt(chunk)
                    decrypted_data.extend(decrypted_chunk)
                    
            with open(self.output_file, 'wb') as file:
                file.write(decrypted_data)
                
    def _handle_chacha20(self):
        try:
            # Преобразуем ключ в байты
            if isinstance(self.key, str):
                key = self.key.encode()
            else:
                key = self.key
                
            # Salsa20 требует 32 байта
            # Если ключ короче, повторяем его
            if len(key) < 32:
                key = key * (32 // len(key) + 1)
            key = key[:32]
            
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            # Шифруем или дешифруем данные
            if self.mode == 'encrypt':
                # Генерируем случайный nonce
                nonce = os.urandom(8)
                cipher = ChaCha20.new(key=key, nonce=nonce)
                encrypted_data = cipher.encrypt(data)
                
                # Сохраняем nonce и зашифрованные данные
                with open(self.output_file, 'wb') as file:
                    file.write(nonce)
                    file.write(encrypted_data)
            else:
                # Читаем nonce из начала файла
                with open(self.input_file, 'rb') as file:
                    nonce = file.read(8)
                    encrypted_data = file.read()
                
                # Создаем шифр с сохраненным nonce
                cipher = ChaCha20.new(key=key, nonce=nonce)
                decrypted_data = cipher.decrypt(encrypted_data)
                
                # Записываем результат
                with open(self.output_file, 'wb') as file:
                    file.write(decrypted_data)
            
            # Обновляем прогресс
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка ChaCha20: {str(e)}")

    def _handle_salsa20(self):
        try:
            # Преобразуем ключ в байты
            if isinstance(self.key, str):
                key = self.key.encode()
            else:
                key = self.key
                
            # Salsa20 требует 32 байта
            # Если ключ короче, повторяем его
            if len(key) < 32:
                key = key * (32 // len(key) + 1)
            key = key[:32]
            
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            # Шифруем или дешифруем данные
            if self.mode == 'encrypt':
                # Генерируем случайный nonce
                nonce = os.urandom(8)
                cipher = Salsa20.new(key=key, nonce=nonce)
                encrypted_data = cipher.encrypt(data)
                
                # Сохраняем nonce и зашифрованные данные
                with open(self.output_file, 'wb') as file:
                    file.write(nonce)
                    file.write(encrypted_data)
            else:
                # Читаем nonce из начала файла
                with open(self.input_file, 'rb') as file:
                    nonce = file.read(8)
                    encrypted_data = file.read()
                
                # Создаем шифр с сохраненным nonce
                cipher = Salsa20.new(key=key, nonce=nonce)
                decrypted_data = cipher.decrypt(encrypted_data)
                
                # Записываем результат
                with open(self.output_file, 'wb') as file:
                    file.write(decrypted_data)
            
            # Обновляем прогресс
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка Salsa20: {str(e)}")

    def _handle_cast(self):
        try:
            key = self.key.encode('utf-8')
            key = pad(key, CAST.block_size)[:16]
            cipher = CAST.new(key, CAST.MODE_ECB)
            
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                encrypted_data = cipher.encrypt(pad(data, CAST.block_size))
            else:
                try:
                    encrypted_data = unpad(cipher.decrypt(data), CAST.block_size)
                except ValueError as e:
                    # Обработка ошибки при неправильном паддинге
                    self.error.emit(f"Ошибка при расшифровке CAST (неверный ключ или формат): {str(e)}")
                    return
            
            with open(self.output_file, 'wb') as file:
                file.write(encrypted_data)
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка CAST: {str(e)}")
            
    def _handle_des(self):
        try:
            key = self.key.encode('utf-8')
            key = pad(key, DES.block_size)[:8]
            cipher = DES.new(key, DES.MODE_ECB)
            
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                encrypted_data = cipher.encrypt(pad(data, DES.block_size))
            else:
                try:
                    encrypted_data = unpad(cipher.decrypt(data), DES.block_size)
                except ValueError as e:
                    # Обработка ошибки при неправильном паддинге
                    self.error.emit(f"Ошибка при расшифровке DES (неверный ключ или формат): {str(e)}")
                    return
            
            with open(self.output_file, 'wb') as file:
                file.write(encrypted_data)
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка DES: {str(e)}")
            
    def _handle_arc4(self):
        try:
            key = self.key.encode('utf-8')
            cipher = ARC4.new(key)
            
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                encrypted_data = cipher.encrypt(data)
            else:
                try:
                    encrypted_data = cipher.decrypt(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке ARC4 (неверный ключ или формат): {str(e)}")
                    return
            
            with open(self.output_file, 'wb') as file:
                file.write(encrypted_data)
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка ARC4: {str(e)}")
            
    def _handle_bcrypt(self):
        try:
            # bcrypt используется для хеширования паролей, а не для шифрования файлов
            # Мы будем использовать его для хеширования содержимого файла
            
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Хешируем данные с помощью bcrypt
                # bcrypt имеет ограничение на длину входных данных, поэтому хешируем SHA256
                data_hash = hashlib.sha256(data).digest()
                hashed = bcrypt(data_hash, 12)
                
                # Сохраняем хеш и данные
                with open(self.output_file, 'wb') as file:
                    file.write(hashed)  # Уже байты, не нужно вызывать .encode()
                    file.write(b"\n")   # Добавляем разделитель
                    file.write(data)
            else:
                try:
                    # Для дешифрования просто извлекаем данные
                    with open(self.input_file, 'rb') as file:
                        lines = file.readlines()
                        if len(lines) > 1:
                            # Пропускаем первую строку (хеш) и получаем данные
                            data = b''.join(lines[1:])
                        else:
                            # Если нет разделителя, предполагаем стандартную длину хеша
                            hashed = lines[0][:60]  # Размер хеша bcrypt
                            data = lines[0][60:]
                    
                    # Сохраняем данные
                    with open(self.output_file, 'wb') as file:
                        file.write(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке bcrypt: {str(e)}")
            
            # Обновляем прогресс
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка bcrypt: {str(e)}")
            
    def _handle_scrypt(self):
        salt = get_random_bytes(16)
        
        with open(self.input_file, 'rb') as file:
            data = file.read()
            
        if self.mode == 'encrypt':
            # Use scrypt to derive a key from the password
            key = scrypt(self.key.encode(), salt, key_len=32, N=16384, r=8, p=1)
            
            # Encrypt with AES
            iv = get_random_bytes(16)
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Write salt, IV, and encrypted data
            with open(self.output_file, 'wb') as file:
                file.write(salt)
                file.write(iv)
                file.write(encrypted_data)
        else:
            try:
                # Read salt, IV, and encrypted data
                with open(self.input_file, 'rb') as file:
                    salt = file.read(16)
                    iv = file.read(16)
                    encrypted_data = file.read()
                    
                # Derive key from password
                # Используем те же параметры, что и при шифровании
                key = scrypt(self.key.encode(), salt, key_len=32, N=16384, r=8, p=1)
                
                # Decrypt with AES
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                
                decryptor = cipher.decryptor()
                decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
                
                with open(self.output_file, 'wb') as file:
                    file.write(decrypted_data)
            except Exception as e:
                self.error.emit(f"Ошибка при расшифровке scrypt: {str(e)}")
            
    def _handle_hmac(self):
        key = self.key.encode('utf-8')
        
        with open(self.input_file, 'rb') as file:
            data = file.read()
            
        if self.mode == 'encrypt':
            # HMAC is for message authentication, not encryption
            # We'll use it to create a MAC of the file
            h = hmac.new(key, data, hashlib.sha256)
            mac = h.hexdigest()
            
            # Записываем хеш и данные
            with open(self.output_file, 'wb') as file:
                file.write(mac.encode())
                file.write(b"\n")  # Добавляем разделитель
                file.write(data)
        else:
            try:
                # Для расшифрования просто извлекаем данные без MAC
                with open(self.input_file, 'rb') as file:
                    lines = file.readlines()
                    if len(lines) > 1:
                        # Пропускаем первую строку (MAC) и получаем данные
                        data = b''.join(lines[1:])
                    else:
                        # Если нет разделителя, пытаемся найти конец хеша
                        first_line = lines[0]
                        # HMAC с SHA256 имеет длину 64 символа в hex + возможный символ новой строки
                        if len(first_line) > 65:
                            # Ищем символ новой строки после MAC
                            newline_pos = first_line.find(b"\n")
                            if newline_pos != -1:
                                data = first_line[newline_pos+1:]
                            else:
                                # Если не найден, берем все после длины MAC
                                data = first_line[64:]
                        else:
                            data = first_line  # Вероятно это не MAC-защищенный файл
                
                # Сохраняем данные
                with open(self.output_file, 'wb') as file:
                    file.write(data)
            except Exception as e:
                self.error.emit(f"Ошибка при расшифровке HMAC: {str(e)}")
            
    def _handle_zlib(self):
        with open(self.input_file, 'rb') as file:
            data = file.read()
            
        if self.mode == 'encrypt':
            # zlib is for compression, not encryption
            # We'll use it to compress the file
            compressed_data = zlib.compress(data)
            
            with open(self.output_file, 'wb') as file:
                file.write(compressed_data)
        else:
            # Decompress the file
            decompressed_data = zlib.decompress(data)
            
            with open(self.output_file, 'wb') as file:
                file.write(decompressed_data)

    def _handle_sha256(self):
        """Обрабатывает хеширование SHA256"""
        try:
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Хешируем данные
                hash_obj = SHA256.new(data)
                hash_value = hash_obj.hexdigest()
                
                # Записываем хеш и данные
                with open(self.output_file, 'wb') as file:
                    file.write(hash_value.encode())
                    file.write(b"\n")
                    file.write(data)
            else:
                try:
                    # Чтение не имеет смысла для хешей, т.к. они односторонние
                    # Просто извлекаем исходные данные без хеша
                    with open(self.input_file, 'rb') as file:
                        lines = file.readlines()
                        if len(lines) > 1:
                            # Пропускаем первую строку (хеш) и получаем данные
                            data = b''.join(lines[1:])
                        else:
                            # Если нет разделителя, пытаемся найти конец хеша
                            first_line = lines[0]
                            # SHA256 хеш имеет длину 64 символа в hex + возможные символы новой строки
                            if len(first_line) > 65:
                                # Ищем символ новой строки после хеша
                                newline_pos = first_line.find(b"\n")
                                if newline_pos != -1:
                                    data = first_line[newline_pos+1:]
                                else:
                                    # Если не найден, берем все после длины хеша
                                    data = first_line[64:]
                            else:
                                data = first_line  # Вероятно это не хешированный файл
                    
                    # Сохраняем данные
                    with open(self.output_file, 'wb') as file:
                        file.write(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке SHA256: {str(e)}")
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка SHA256: {str(e)}")
    
    def _handle_sha512(self):
        """Обрабатывает хеширование SHA512"""
        try:
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Хешируем данные
                hash_obj = SHA512.new(data)
                hash_value = hash_obj.hexdigest()
                
                # Записываем хеш и данные
                with open(self.output_file, 'wb') as file:
                    file.write(hash_value.encode())
                    file.write(b"\n")
                    file.write(data)
            else:
                try:
                    # Чтение не имеет смысла для хешей, т.к. они односторонние
                    # Просто извлекаем исходные данные без хеша
                    with open(self.input_file, 'rb') as file:
                        lines = file.readlines()
                        if len(lines) > 1:
                            # Пропускаем первую строку (хеш) и получаем данные
                            data = b''.join(lines[1:])
                        else:
                            # Если нет разделителя, пытаемся найти конец хеша
                            first_line = lines[0]
                            # SHA512 хеш имеет длину 128 символов в hex + возможные символы новой строки
                            if len(first_line) > 129:
                                # Ищем символ новой строки после хеша
                                newline_pos = first_line.find(b"\n")
                                if newline_pos != -1:
                                    data = first_line[newline_pos+1:]
                                else:
                                    # Если не найден, берем все после длины хеша
                                    data = first_line[128:]
                            else:
                                data = first_line  # Вероятно это не хешированный файл
                    
                    # Сохраняем данные
                    with open(self.output_file, 'wb') as file:
                        file.write(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке SHA512: {str(e)}")
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка SHA512: {str(e)}")
    
    def _handle_md5(self):
        """Обрабатывает хеширование MD5"""
        try:
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Хешируем данные
                hash_obj = MD5.new(data)
                hash_value = hash_obj.hexdigest()
                
                # Записываем хеш и данные
                with open(self.output_file, 'wb') as file:
                    file.write(hash_value.encode())
                    file.write(b"\n")
                    file.write(data)
            else:
                try:
                    # Чтение не имеет смысла для хешей, т.к. они односторонние
                    # Просто извлекаем исходные данные без хеша
                    with open(self.input_file, 'rb') as file:
                        lines = file.readlines()
                        if len(lines) > 1:
                            # Пропускаем первую строку (хеш) и получаем данные
                            data = b''.join(lines[1:])
                        else:
                            # Если нет разделителя, пытаемся найти конец хеша
                            first_line = lines[0]
                            # MD5 хеш имеет длину 32 символа в hex + возможные символы новой строки
                            if len(first_line) > 33:
                                # Ищем символ новой строки после хеша
                                newline_pos = first_line.find(b"\n")
                                if newline_pos != -1:
                                    data = first_line[newline_pos+1:]
                                else:
                                    # Если не найден, берем все после длины хеша
                                    data = first_line[32:]
                            else:
                                data = first_line  # Вероятно это не хешированный файл
                    
                    # Сохраняем данные
                    with open(self.output_file, 'wb') as file:
                        file.write(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке MD5: {str(e)}")
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка MD5: {str(e)}")
    
    def _handle_ripemd160(self):
        """Обрабатывает хеширование RIPEMD160"""
        try:
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Хешируем данные
                hash_obj = RIPEMD160.new(data)
                hash_value = hash_obj.hexdigest()
                
                # Записываем хеш и данные
                with open(self.output_file, 'wb') as file:
                    file.write(hash_value.encode())
                    file.write(b"\n")
                    file.write(data)
            else:
                try:
                    # Чтение не имеет смысла для хешей, т.к. они односторонние
                    # Просто извлекаем исходные данные без хеша
                    with open(self.input_file, 'rb') as file:
                        lines = file.readlines()
                        if len(lines) > 1:
                            # Пропускаем первую строку (хеш) и получаем данные
                            data = b''.join(lines[1:])
                        else:
                            # Если нет разделителя, пытаемся найти конец хеша
                            first_line = lines[0]
                            # RIPEMD160 хеш имеет длину 40 символов в hex + возможные символы новой строки
                            if len(first_line) > 41:
                                # Ищем символ новой строки после хеша
                                newline_pos = first_line.find(b"\n")
                                if newline_pos != -1:
                                    data = first_line[newline_pos+1:]
                                else:
                                    # Если не найден, берем все после длины хеша
                                    data = first_line[40:]
                            else:
                                data = first_line  # Вероятно это не хешированный файл
                    
                    # Сохраняем данные
                    with open(self.output_file, 'wb') as file:
                        file.write(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке RIPEMD160: {str(e)}")
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка RIPEMD160: {str(e)}")
    
    def _handle_sha1(self):
        """Обрабатывает хеширование SHA1"""
        try:
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Хешируем данные
                hash_obj = SHA1.new(data)
                hash_value = hash_obj.hexdigest()
                
                # Записываем хеш и данные
                with open(self.output_file, 'wb') as file:
                    file.write(hash_value.encode())
                    file.write(b"\n")
                    file.write(data)
            else:
                try:
                    # Чтение не имеет смысла для хешей, т.к. они односторонние
                    # Просто извлекаем исходные данные без хеша
                    with open(self.input_file, 'rb') as file:
                        lines = file.readlines()
                        if len(lines) > 1:
                            # Пропускаем первую строку (хеш) и получаем данные
                            data = b''.join(lines[1:])
                        else:
                            # Если нет разделителя, пытаемся найти конец хеша
                            first_line = lines[0]
                            # SHA1 хеш имеет длину 40 символов в hex + возможные символы новой строки
                            if len(first_line) > 41:
                                # Ищем символ новой строки после хеша
                                newline_pos = first_line.find(b"\n")
                                if newline_pos != -1:
                                    data = first_line[newline_pos+1:]
                                else:
                                    # Если не найден, берем все после длины хеша
                                    data = first_line[40:]
                            else:
                                data = first_line  # Вероятно это не хешированный файл
                    
                    # Сохраняем данные
                    with open(self.output_file, 'wb') as file:
                        file.write(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке SHA1: {str(e)}")
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка SHA1: {str(e)}")
    
    def _handle_sha3_256(self):
        """Обрабатывает хеширование SHA3-256"""
        try:
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Хешируем данные
                hash_obj = SHA3_256.new(data)
                hash_value = hash_obj.hexdigest()
                
                # Записываем хеш и данные
                with open(self.output_file, 'wb') as file:
                    file.write(hash_value.encode())
                    file.write(b"\n")
                    file.write(data)
            else:
                try:
                    # Чтение не имеет смысла для хешей, т.к. они односторонние
                    # Просто извлекаем исходные данные без хеша
                    with open(self.input_file, 'rb') as file:
                        lines = file.readlines()
                        if len(lines) > 1:
                            # Пропускаем первую строку (хеш) и получаем данные
                            data = b''.join(lines[1:])
                        else:
                            # Если нет разделителя, пытаемся найти конец хеша
                            first_line = lines[0]
                            # SHA3-256 хеш имеет длину 64 символа в hex + возможные символы новой строки
                            if len(first_line) > 65:
                                # Ищем символ новой строки после хеша
                                newline_pos = first_line.find(b"\n")
                                if newline_pos != -1:
                                    data = first_line[newline_pos+1:]
                                else:
                                    # Если не найден, берем все после длины хеша
                                    data = first_line[64:]
                            else:
                                data = first_line  # Вероятно это не хешированный файл
                    
                    # Сохраняем данные
                    with open(self.output_file, 'wb') as file:
                        file.write(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке SHA3-256: {str(e)}")
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка SHA3-256: {str(e)}")
    
    def _handle_sha3_512(self):
        """Обрабатывает хеширование SHA3-512"""
        try:
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Хешируем данные
                hash_obj = SHA3_512.new(data)
                hash_value = hash_obj.hexdigest()
                
                # Записываем хеш и данные
                with open(self.output_file, 'wb') as file:
                    file.write(hash_value.encode())
                    file.write(b"\n")
                    file.write(data)
            else:
                try:
                    # Чтение не имеет смысла для хешей, т.к. они односторонние
                    # Просто извлекаем исходные данные без хеша
                    with open(self.input_file, 'rb') as file:
                        lines = file.readlines()
                        if len(lines) > 1:
                            # Пропускаем первую строку (хеш) и получаем данные
                            data = b''.join(lines[1:])
                        else:
                            # Если нет разделителя, пытаемся найти конец хеша
                            first_line = lines[0]
                            # SHA3-512 хеш имеет длину 128 символов в hex + возможные символы новой строки
                            if len(first_line) > 129:
                                # Ищем символ новой строки после хеша
                                newline_pos = first_line.find(b"\n")
                                if newline_pos != -1:
                                    data = first_line[newline_pos+1:]
                                else:
                                    # Если не найден, берем все после длины хеша
                                    data = first_line[128:]
                            else:
                                data = first_line  # Вероятно это не хешированный файл
                    
                    # Сохраняем данные
                    with open(self.output_file, 'wb') as file:
                        file.write(data)
                except Exception as e:
                    self.error.emit(f"Ошибка при расшифровке SHA3-512: {str(e)}")
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка SHA3-512: {str(e)}")
    
    def _handle_pbkdf2(self):
        """Обрабатывает хеширование PBKDF2"""
        try:
            salt = get_random_bytes(16)
            iterations = 10000
            
            # Читаем данные из файла
            with open(self.input_file, 'rb') as file:
                data = file.read()
            
            if self.mode == 'encrypt':
                # Генерируем ключ с использованием PBKDF2
                key = PBKDF2(self.key.encode(), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
                
                # Шифруем с использованием AES
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_data = pad(data, AES.block_size)
                encrypted_data = cipher.encrypt(padded_data)
                
                # Записываем соль, iv и зашифрованные данные
                with open(self.output_file, 'wb') as file:
                    file.write(salt)
                    file.write(iv)
                    file.write(encrypted_data)
            else:
                # Читаем соль, iv и зашифрованные данные
                with open(self.input_file, 'rb') as file:
                    salt = file.read(16)
                    iv = file.read(16)
                    encrypted_data = file.read()
                
                # Генерируем ключ с использованием PBKDF2
                key = PBKDF2(self.key.encode(), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
                
                # Расшифровываем данные
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                
                # Записываем расшифрованные данные
                with open(self.output_file, 'wb') as file:
                    file.write(decrypted_data)
            
            self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"Ошибка PBKDF2: {str(e)}")

class FileHistory:
    def __init__(self, max_items=10):
        self.max_items = max_items
        self.history = []
        self.load_history()
        
    def add_item(self, file_path, method, operation):
        item = {
            'file_path': file_path,
            'method': method,
            'operation': operation,
            'timestamp': QDateTime.currentDateTime().toString()
        }
        
        # Удаляем дубликаты
        self.history = [x for x in self.history if x['file_path'] != file_path]
        
        # Добавляем новый элемент в начало
        self.history.insert(0, item)
        
        # Ограничиваем количество элементов
        if len(self.history) > self.max_items:
            self.history = self.history[:self.max_items]
            
        self.save_history()
        
    def get_history(self):
        return self.history
        
    def clear_history(self):
        self.history = []
        self.save_history()
        
    def save_history(self):
        history_file = get_settings_path('history.json')
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2)
        
    def load_history(self):
        history_file = get_settings_path('history.json')
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r', encoding='utf-8') as f:
                    self.history = json.load(f)
            except:
                self.history = []
        else:
            self.history = []

class Favorites:
    def __init__(self):
        self.favorites = []
        self.load_favorites()
        
    def add_favorite(self, path, name=None):
        if name is None:
            name = os.path.basename(path)
            
        # Проверяем, не существует ли уже такой путь
        for fav in self.favorites:
            if fav['path'] == path:
                return
                
        self.favorites.append({
            'path': path,
            'name': name
        })
        self.save_favorites()
        
    def remove_favorite(self, path):
        self.favorites = [fav for fav in self.favorites if fav['path'] != path]
        self.save_favorites()
        
    def get_favorites(self):
        return self.favorites
        
    def save_favorites(self):
        favorites_file = get_settings_path('favorites.json')
        with open(favorites_file, 'w', encoding='utf-8') as f:
            json.dump(self.favorites, f, ensure_ascii=False, indent=2)
        
    def load_favorites(self):
        favorites_file = get_settings_path('favorites.json')
        if os.path.exists(favorites_file):
            try:
                with open(favorites_file, 'r', encoding='utf-8') as f:
                    self.favorites = json.load(f)
            except:
                self.favorites = []
        else:
            self.favorites = []

class BatchWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    file_processed = pyqtSignal(str, bool, str, str)  # путь к файлу, успех операции, метод, режим

    def __init__(self, files, key, method, mode='encrypt'):
        super().__init__()
        self.files = files
        self.key = key
        self.method = method
        self.mode = mode
        self.total_files = len(files)
        self.processed_files = 0

    def run(self):
        try:
            for file_path in self.files:
                try:
                    output_file = file_path + ('.encrypted' if self.mode == 'encrypt' else '.decrypted')
                    
                    # Создаем воркер для каждого файла
                    worker = EncryptionWorker(
                        file_path,
                        output_file,
                        self.key,
                        self.method,
                        self.mode
                    )
                    
                    # Запускаем воркер и ждем завершения
                    worker.run()
                    
                    # Обновляем прогресс
                    self.processed_files += 1
                    progress = int((self.processed_files / self.total_files) * 100)
                    self.progress.emit(progress)
                    
                    # Отправляем сигнал об успешной обработке файла с методом и режимом
                    self.file_processed.emit(file_path, True, self.method, self.mode)
                    
                except Exception as e:
                    # Отправляем сигнал об ошибке для конкретного файла с методом и режимом
                    self.file_processed.emit(file_path, False, self.method, self.mode)
                    self.error.emit(f"Ошибка при обработке {os.path.basename(file_path)}: {str(e)}")
            
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

class FileOperationsWorker(QThread):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(str)

    def __init__(self, operation, path, target_path=None):
        super().__init__()
        self.operation = operation
        self.path = path
        self.target_path = target_path

    def run(self):
        try:
            if self.operation == 'list_files':
                # Подсчитываем количество файлов и папок
                total_files = 0
                total_dirs = 0
                total_size = 0
                
                for root, dirs, files in os.walk(self.path):
                    total_dirs += len(dirs)
                    total_files += len(files)
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            total_size += os.path.getsize(file_path)
                        except:
                            pass
                
                # Форматируем размер
                if total_size < 1024:
                    size_str = f"{total_size} байт"
                elif total_size < 1024 * 1024:
                    size_str = f"{total_size / 1024:.2f} КБ"
                elif total_size < 1024 * 1024 * 1024:
                    size_str = f"{total_size / (1024 * 1024):.2f} МБ"
                else:
                    size_str = f"{total_size / (1024 * 1024 * 1024):.2f} ГБ"
                
                self.result.emit(f"Файлов: {total_files}, Папок: {total_dirs}, Общий размер: {size_str}")
                
            elif self.operation == 'delete':
                if os.path.isfile(self.path):
                    os.remove(self.path)
                else:
                    shutil.rmtree(self.path)
                self.finished.emit()
                
            elif self.operation == 'rename':
                os.rename(self.path, self.target_path)
                self.finished.emit()
                
            elif self.operation == 'copy':
                if os.path.isfile(self.path):
                    shutil.copy2(self.path, self.target_path)
                else:
                    shutil.copytree(self.path, self.target_path)
                self.finished.emit()
                
            elif self.operation == 'move':
                shutil.move(self.path, self.target_path)
                self.finished.emit()
                
        except Exception as e:
            self.error.emit(str(e))

class FileExplorer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.data_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        # Создаем папку data, если её нет
        if not os.path.exists(self.data_folder):
            os.makedirs(self.data_folder)
        # Используем экземпляр Favorites из родительского класса, если он доступен
        if parent and hasattr(parent, 'favorites'):
            self.favorites = parent.favorites
        else:
            self.favorites = Favorites()
        self.initUI()
        
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем виджет с вкладками для проводника
        self.explorer_tabs = QTabWidget()
        
        # Вкладка "Общее"
        self.general_tab = QWidget()
        general_layout = QVBoxLayout(self.general_tab)
        general_layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем модель файловой системы
        self.model = QFileSystemModel()
        self.model.setRootPath(QDir.rootPath())
        
        # Создаем дерево файлов
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setRootIndex(self.model.index(self.data_folder))  # Начинаем с папки data
        self.tree.setAnimated(True)
        self.tree.setIndentation(20)
        self.tree.setSortingEnabled(True)
        self.tree.setColumnWidth(0, 250)
        self.tree.setAlternatingRowColors(True)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        
        # Скрываем ненужные колонки (размер, тип, дата изменения)
        self.tree.setColumnHidden(1, True)
        self.tree.setColumnHidden(2, True)
        self.tree.setColumnHidden(3, True)
        
        # Подключаем двойной клик для выбора файла
        self.tree.doubleClicked.connect(self.on_file_selected)
        
        general_layout.addWidget(self.tree)
        
        # Добавляем строку поиска для вкладки "Общее" внизу
        general_search_layout = QHBoxLayout()
        self.general_search_edit = QLineEdit()
        self.general_search_edit.setPlaceholderText("Поиск...")
        self.general_search_edit.textChanged.connect(self.filter_files_in_general)
        self.general_search_edit.installEventFilter(self)
        general_search_layout.addWidget(self.general_search_edit)
        
        general_layout.addLayout(general_search_layout)
        
        # Вкладка "Избранное"
        self.favorites_tab = QWidget()
        favorites_layout = QVBoxLayout(self.favorites_tab)
        favorites_layout.setContentsMargins(0, 0, 0, 0)
        
        self.favorites_list = QListWidget()
        self.favorites_list.setObjectName("favorites_list")
        self.favorites_list.itemDoubleClicked.connect(self.load_from_favorites)
        self.favorites_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.favorites_list.customContextMenuRequested.connect(self.show_favorites_context_menu)
        
        favorites_layout.addWidget(self.favorites_list)
        
        # Добавляем строку поиска для вкладки "Избранное" внизу
        favorites_search_layout = QHBoxLayout()
        self.favorites_search_edit = QLineEdit()
        self.favorites_search_edit.setPlaceholderText("Поиск в избранном...")
        self.favorites_search_edit.textChanged.connect(self.filter_favorites)
        self.favorites_search_edit.installEventFilter(self)
        favorites_search_layout.addWidget(self.favorites_search_edit)
        
        favorites_layout.addLayout(favorites_search_layout)
        
        # Добавляем вкладки в табвиджет
        self.explorer_tabs.addTab(self.general_tab, "Общее")
        self.explorer_tabs.addTab(self.favorites_tab, "Избранное")
        
        layout.addWidget(self.explorer_tabs)
        
        # Обновляем заголовок главного окна
        self.update_window_title()
        
        # Настраиваем автоматическое обновление файлов
        self.setup_file_watcher()
        
        # Обновляем список избранного
        self.update_favorites_list()
        
    def filter_files_in_general(self, text):
        """Фильтрует файлы в дереве файлов по тексту поиска"""
        if not text:
            # Если поиск пустой, показываем все файлы
            self.tree.setRootIndex(self.model.index(self.data_folder))
            self.model.setNameFilters([])
            return
            
        # Показываем только файлы и папки, содержащие текст поиска
        # Для QFileSystemModel мы можем просто использовать встроенную фильтрацию
        self.model.setNameFilterDisables(False)  # Скрывать файлы вместо отключения
        self.model.setNameFilters([f"*{text}*"])
        
    def clear_general_search(self):
        """Очищает поле поиска в общем проводнике"""
        self.general_search_edit.clear()
        # Возвращаем исходное отображение
        self.model.setNameFilters([])
        
    def filter_favorites(self, text):
        """Фильтрует избранное по тексту поиска"""
        if not text:
            # Если поиск пустой, показываем все избранное
            self.update_favorites_list()
            return
            
        # Фильтруем список избранного
        for i in range(self.favorites_list.count()):
            item = self.favorites_list.item(i)
            if text.lower() in item.text().lower():
                item.setHidden(False)
            else:
                item.setHidden(True)
                
    def clear_favorites_search(self):
        """Очищает поле поиска в избранном"""
        self.favorites_search_edit.clear()
        # Показываем все элементы
        for i in range(self.favorites_list.count()):
            self.favorites_list.item(i).setHidden(False)
            
    def update_window_title(self):
        """Обновляет заголовок главного окна, включая текущий путь"""
        if self.parent:
            current_path = self.model.filePath(self.tree.rootIndex())
            self.parent.setWindowTitle(f'MetrosCrypt - {current_path}')
        
    def setup_file_watcher(self):
        # Создаем наблюдатель за файловой системой
        self.file_watcher = QFileSystemWatcher(self)
        
        # Добавляем текущую директорию для отслеживания
        self.watch_directory(self.data_folder)
        
        # Подключаем сигналы для обновления при изменении файлов
        self.file_watcher.directoryChanged.connect(self.on_directory_changed)
        self.file_watcher.fileChanged.connect(self.on_file_changed)
        
    def watch_directory(self, directory):
        """Добавляет директорию для отслеживания"""
        try:
            # Проверяем, существует ли директория
            if not os.path.exists(directory):
                os.makedirs(directory)
                self.parent.status_bar.showMessage(f'Создана директория: {directory}', 3000)

            # Пытаемся добавить директорию для отслеживания
            # Не выдаем ошибку если директория уже отслеживается
            if not self.file_watcher.directories().count(directory):
                self.file_watcher.addPath(directory)
            
            # Рекурсивно добавляем все поддиректории
            for root, dirs, _ in os.walk(directory):
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    if os.path.exists(dir_path) and not self.file_watcher.directories().count(dir_path):
                        try:
                            self.file_watcher.addPath(dir_path)
                        except:
                            pass  # Игнорируем ошибки при добавлении поддиректорий
        except Exception as e:
            if self.parent:
                self.parent.status_bar.showMessage(f'Ошибка отслеживания директории: {str(e)}', 5000)
            else:
                print(f"Ошибка при добавлении директории для отслеживания: {directory}, {str(e)}")
            
    def on_directory_changed(self, path):
        # Обновляем список наблюдаемых директорий
        self.watch_directory(path)
        # Обновляем отображение
        self.refresh()
        
    def on_file_changed(self, path):
        # Обновляем отображение при изменении файла
        self.refresh()
        
    def filter_files(self):
        # This method is kept for compatibility but is no longer used
        pass
        
    def change_folder(self, folder_name):
        # This method is kept for compatibility but is no longer used
        pass
        
    def on_file_selected(self, index):
        """Обрабатывает выбор файла двойным кликом"""
        file_path = self.model.filePath(index)
        if os.path.isfile(file_path):
            if self.parent:
                self.parent.set_file_path(file_path)

    def show_context_menu(self, position):
        menu = QMenu()
        
        # Получаем индекс элемента под курсором
        index = self.tree.indexAt(position)
        
        # Если клик был на элементе, показываем контекстное меню для элемента
        if index.isValid():
            file_path = self.model.filePath(index)
            file_dir = os.path.dirname(file_path)
            
            # Новая структура меню для файлов и папок
            open_action = menu.addAction("Открыть файл")
            menu.addSeparator()
            
            open_submenu = QMenu("Открыть файл...", self)
            open_windows_action = open_submenu.addAction("Открыть файл [windows]")
            open_in_new_window_action = open_submenu.addAction("Открыть файл в новом окне")
            menu.addMenu(open_submenu)
            
            menu.addSeparator()
            
            open_folder_action = menu.addAction("Открыть папку файла в проводнике")
            open_cmd_action = menu.addAction("Открыть папку файла в cmd")
            menu.addSeparator()
            
            copy_folder_action = menu.addAction("Скопировать папку файла в буфер")
            menu.addSeparator()
            
            rename_action = menu.addAction("Переименовать")
            delete_action = menu.addAction("Удалить")
            menu.addSeparator()
            
            add_to_favorites_action = menu.addAction("Добавить папку файла в избранное")
            
            action = menu.exec_(self.tree.mapToGlobal(position))
            
            if action == open_action:
                self.on_file_selected(index)
            elif action == open_windows_action:
                self.open_file_with_windows(file_path)
            elif action == open_in_new_window_action:
                if self.parent:
                    self.parent.set_file_path(file_path)
                    self.parent.open_current_file_in_new_window()
            elif action == open_folder_action:
                self.open_folder_in_explorer(file_dir)
            elif action == open_cmd_action:
                self.open_folder_in_cmd(file_dir)
            elif action == copy_folder_action:
                self.copy_to_clipboard(file_dir)
            elif action == delete_action:
                self.delete_selected()
            elif action == rename_action:
                self.rename_selected()
            elif action == add_to_favorites_action:
                self.add_to_favorites(file_dir)
        else:
            # Если клик был на пустом месте, показываем контекстное меню для виджета
            current_path = self.model.filePath(self.tree.rootIndex())
            
            select_folder_action = menu.addAction("Выбрать папку...")
            menu.addSeparator()
            open_in_explorer_action = menu.addAction("Открыть папку в проводнике Windows")
            open_in_cmd_action = menu.addAction("Открыть папку в cmd")
            menu.addSeparator()
            copy_path_action = menu.addAction("Копировать путь папки файла в буфер")
            menu.addSeparator()
            add_to_favorites_action = menu.addAction("Добавить папку в избранное")
            
            action = menu.exec_(self.tree.mapToGlobal(position))
            
            if action == select_folder_action:
                self.select_folder()
            elif action == open_in_explorer_action:
                self.open_in_explorer()
            elif action == open_in_cmd_action:
                self.open_in_cmd()
            elif action == copy_path_action:
                clipboard = QApplication.clipboard()
                clipboard.setText(current_path)
                self.parent.status_bar.showMessage(f'Путь скопирован: {current_path}', 3000)
            elif action == add_to_favorites_action:
                self.add_to_favorites()

    def select_folder(self):
        """Открывает диалог выбора папки и устанавливает её как корневую"""
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if folder:
            self.tree.setRootIndex(self.model.index(folder))
            self.update_window_title()
            
    def open_in_explorer(self):
        """Открывает текущую папку в проводнике Windows"""
        current_path = self.model.filePath(self.tree.rootIndex())
        self.open_folder_in_explorer(current_path)
                
    def open_in_cmd(self):
        """Открывает текущую папку в командной строке"""
        current_path = self.model.filePath(self.tree.rootIndex())
        self.open_folder_in_cmd(current_path)

    def open_file_with_windows(self, file_path):
        """Открывает файл с помощью стандартного приложения Windows"""
        if os.path.exists(file_path):
            os.startfile(file_path)
            
    def open_folder_in_explorer(self, folder_path):
        """Открывает указанную папку в проводнике Windows"""
        if os.path.exists(folder_path):
            if platform.system() == 'Windows':
                os.startfile(folder_path)
            else:
                # Для других ОС используем соответствующие команды
                if platform.system() == 'Darwin':  # macOS
                    subprocess.Popen(['open', folder_path])
                else:  # Linux
                    subprocess.Popen(['xdg-open', folder_path])
                    
    def open_folder_in_cmd(self, folder_path):
        """Открывает командную строку в указанной папке"""
        if os.path.exists(folder_path):
            if platform.system() == 'Windows':
                subprocess.Popen(f'cmd.exe /K cd /d "{folder_path}"', shell=True)
            else:
                # Для других ОС используем соответствующие терминалы
                if platform.system() == 'Darwin':  # macOS
                    subprocess.Popen(['open', '-a', 'Terminal', folder_path])
                else:  # Linux
                    subprocess.Popen(['gnome-terminal', '--working-directory=' + folder_path])
                    
    def copy_to_clipboard(self, text):
        """Копирует текст в буфер обмена"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.parent.status_bar.showMessage(f'Путь скопирован: {text}', 3000)
    
    def delete_selected(self):
        index = self.tree.currentIndex()
        if not index.isValid():
            return
            
        file_path = self.model.filePath(index)
        reply = QMessageBox.question(self, 'Подтверждение', 
                                   f'Удалить {os.path.basename(file_path)}?',
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.worker = FileOperationsWorker('delete', file_path)
            self.worker.finished.connect(self.refresh)
            self.worker.error.connect(lambda msg: QMessageBox.warning(self, 'Ошибка', msg))
            self.worker.start()
                
    def rename_selected(self):
        index = self.tree.currentIndex()
        if not index.isValid():
            return
            
        old_path = self.model.filePath(index)
        old_name = os.path.basename(old_path)
        new_name, ok = QInputDialog.getText(self, 'Переименовать', 
                                          'Введите новое имя:', 
                                          QLineEdit.Normal, old_name)
        
        if ok and new_name:
            new_path = os.path.join(os.path.dirname(old_path), new_name)
            self.worker = FileOperationsWorker('rename', old_path, new_path)
            self.worker.finished.connect(self.refresh)
            self.worker.error.connect(lambda msg: QMessageBox.warning(self, 'Ошибка', msg))
            self.worker.start()
            
    def copy_selected(self):
        index = self.tree.currentIndex()
        if not index.isValid():
            return
            
        src_path = self.model.filePath(index)
        dst_path, _ = QFileDialog.getExistingDirectory(self, 'Выберите папку назначения')
        
        if dst_path:
            dst_path = os.path.join(dst_path, os.path.basename(src_path))
            self.worker = FileOperationsWorker('copy', src_path, dst_path)
            self.worker.finished.connect(self.refresh)
            self.worker.error.connect(lambda msg: QMessageBox.warning(self, 'Ошибка', msg))
            self.worker.start()
            
    def move_selected(self):
        index = self.tree.currentIndex()
        if not index.isValid():
            return
            
        src_path = self.model.filePath(index)
        dst_path, _ = QFileDialog.getExistingDirectory(self, 'Выберите папку назначения')
        
        if dst_path:
            dst_path = os.path.join(dst_path, os.path.basename(src_path))
            self.worker = FileOperationsWorker('move', src_path, dst_path)
            self.worker.finished.connect(self.refresh)
            self.worker.error.connect(lambda msg: QMessageBox.warning(self, 'Ошибка', msg))
            self.worker.start()
        
    def refresh(self):
        current_path = self.model.filePath(self.tree.rootIndex())
        self.tree.setRootIndex(self.model.index(current_path))
        # Обновляем заголовок окна
        self.update_window_title()
        
    def on_file_selected(self, index):
        file_path = self.model.filePath(index)
        if os.path.isfile(file_path):
            if self.parent:
                self.parent.set_file_path(file_path)
                
    def add_to_favorites(self, folder_path=None):
        """Добавляет папку в избранное"""
        if folder_path is None:
            folder_path = self.model.filePath(self.tree.rootIndex())
            
        name, ok = QInputDialog.getText(self, 'Добавить в избранное', 
                                      'Введите имя для избранного:',
                                      QLineEdit.Normal, os.path.basename(folder_path))
        
        if ok and name:
            self.favorites.add_favorite(folder_path, name)
            # Обновляем список избранного напрямую
            if self.parent:
                # Обновляем список избранного в родительском окне
                self.parent.update_favorites_list()
                # Находим виджет списка избранного в главном окне
                for child in self.parent.findChildren(QListWidget):
                    if child.objectName() == "favorites_list":
                        child.clear()
                        for fav in self.favorites.get_favorites():
                            list_item = QListWidgetItem(fav['name'])
                            list_item.setData(Qt.UserRole, fav)
                            child.addItem(list_item)
                        break
            QMessageBox.information(self, 'Избранное', f'Папка "{name}" добавлена в избранное')

    def show_favorites_context_menu(self, position):
        """Показывает контекстное меню для списка избранного"""
        menu = QMenu()
        
        # Проверяем, есть ли выбранный элемент
        if self.favorites_list.currentItem():
            delete_action = menu.addAction("Удалить из избранного")
            delete_action.triggered.connect(self.remove_from_favorites)
            menu.addSeparator()
        
        clear_all_action = menu.addAction("Очистить все")
        clear_all_action.triggered.connect(self.clear_favorites)
        
        menu.exec_(self.favorites_list.mapToGlobal(position))
    
    def update_favorites_list(self):
        """Обновляет список избранного"""
        self.favorites_list.clear()
        for fav in self.favorites.get_favorites():
            list_item = QListWidgetItem(fav['name'])
            list_item.setData(Qt.UserRole, fav)
            self.favorites_list.addItem(list_item)
    
    def load_from_favorites(self, item):
        """Загружает папку из избранного"""
        fav_item = item.data(Qt.UserRole)
        self.tree.setRootIndex(self.model.index(fav_item['path']))
        # Переключаемся на вкладку Общее
        self.explorer_tabs.setCurrentIndex(0)
        # Обновляем заголовок окна
        self.update_window_title()
    
    def clear_favorites(self):
        """Очищает весь список избранного"""
        reply = QMessageBox.question(self, 'Подтверждение', 
                                   'Вы уверены, что хотите очистить все избранное?',
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.favorites.favorites = []
            self.favorites.save_favorites()
        self.update_favorites_list()
        
    def remove_from_favorites(self):
        """Удаляет выбранный элемент из избранного"""
        current_item = self.favorites_list.currentItem()
        if current_item:
            fav_item = current_item.data(Qt.UserRole)
            self.favorites.remove_favorite(fav_item['path'])
            self.update_favorites_list()
            # Обновляем список избранного в основном окне, если оно доступно
            if self.parent and hasattr(self.parent, 'update_favorites_list'):
                self.parent.update_favorites_list()

    def eventFilter(self, obj, event):
        """Обработчик событий для отлавливания нажатия ESC в полях поиска"""
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape:
            if obj == self.general_search_edit:
                self.clear_general_search()
                return True
            elif obj == self.favorites_search_edit:
                self.clear_favorites_search()
                return True
        return super().eventFilter(obj, event)

class PasswordLineEdit(QLineEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEchoMode(QLineEdit.Password)
        
        # Add toggle password visibility action with proper icons
        self.show_password_action = QAction(self)
        self.show_password_action.setIcon(QIcon("resource/assets/show_pass.png"))
        self.show_password_action.triggered.connect(self.toggle_password_visibility)
        self.addAction(self.show_password_action, QLineEdit.TrailingPosition)
        
        # Initially hide the action
        self.show_password_action.setVisible(False)
        
        # Connect text changed signal to update visibility
        self.textChanged.connect(self.update_password_visibility)
        
    def toggle_password_visibility(self):
        if self.echoMode() == QLineEdit.Password:
            self.setEchoMode(QLineEdit.Normal)
            self.show_password_action.setIcon(QIcon("resource/assets/hide_pass.png"))
        else:
            self.setEchoMode(QLineEdit.Password)
            self.show_password_action.setIcon(QIcon("resource/assets/show_pass.png"))
            
    def update_password_visibility(self, text):
        """Show/hide password visibility toggle based on text presence"""
        self.show_password_action.setVisible(bool(text))

class TextEditor(QWidget):
    """Расширенный текстовый редактор с функциями поиска и перехода по строкам"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.current_search_position = 0
        self.search_highlights = []
        self.setup_shortcuts()
        
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Текстовый редактор
        self.editor = QTextEdit()
        self.editor.setReadOnly(True)
        self.editor.installEventFilter(self)
        
        # Создаем поле поиска (изначально скрыто)
        self.search_widget = QWidget()
        search_layout = QHBoxLayout(self.search_widget)
        search_layout.setContentsMargins(1, 1, 1, 1)
        
        search_label = QLabel("Поиск:")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск... (F3 - следующий, Shift+F3 - предыдущий)")
        self.search_edit.textChanged.connect(self.highlight_search)
        self.search_edit.returnPressed.connect(self.find_next)
        self.search_edit.installEventFilter(self)
        
        # Search close button using QLabel
        close_search_label = QLabel()
        close_search_label.setPixmap(QIcon("resource/assets/close.png").pixmap(16, 16))
        close_search_label.setCursor(Qt.PointingHandCursor)  # Change cursor to hand when hovering
        close_search_label.mousePressEvent = lambda event: self.hide_search()
        
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_edit)
        search_layout.addWidget(close_search_label)
        
        # Создаем поле для перехода к строке (изначально скрыто)
        self.goto_widget = QWidget()
        goto_layout = QHBoxLayout(self.goto_widget)
        goto_layout.setContentsMargins(1, 1, 1, 1)
        
        goto_label = QLabel("Перейти к строке:")
        self.goto_edit = QLineEdit()
        self.goto_edit.setPlaceholderText("Введите номер строки...")
        self.goto_edit.setValidator(QIntValidator(1, 999999))
        # Connect to textChanged instead of returnPressed to go to line as user types
        self.goto_edit.textChanged.connect(self.goto_line_on_type)
        self.goto_edit.installEventFilter(self)
        
        # Goto close button using QLabel
        close_goto_label = QLabel()
        close_goto_label.setPixmap(QIcon("resource/assets/close.png").pixmap(16, 16))
        close_goto_label.setCursor(Qt.PointingHandCursor)  # Change cursor to hand when hovering
        close_goto_label.mousePressEvent = lambda event: self.hide_goto()
        
        goto_layout.addWidget(goto_label)
        goto_layout.addWidget(self.goto_edit)
        goto_layout.addWidget(close_goto_label)
        
        # Добавляем компоненты в основной макет
        layout.addWidget(self.editor)
        layout.addWidget(self.search_widget)
        layout.addWidget(self.goto_widget)
        
        # Скрываем виджеты по умолчанию
        self.search_widget.hide()
        self.goto_widget.hide()

    def setup_shortcuts(self):
        """Настройка горячих клавиш"""
        # Ctrl+F для поиска
        self.shortcut_search = QShortcut(QKeySequence("Ctrl+F"), self)
        self.shortcut_search.activated.connect(self.show_search)
        
        # F3 для перехода к следующему результату поиска
        self.shortcut_find_next = QShortcut(QKeySequence("F3"), self)
        self.shortcut_find_next.activated.connect(self.find_next)
        
        # Shift+F3 для перехода к предыдущему результату поиска
        self.shortcut_find_prev = QShortcut(QKeySequence("Shift+F3"), self)
        self.shortcut_find_prev.activated.connect(self.find_previous)
        
        # Ctrl+G для перехода к строке
        self.shortcut_goto = QShortcut(QKeySequence("Ctrl+G"), self)
        self.shortcut_goto.activated.connect(self.show_goto)
        
    def show_search(self):
        """Показывает поле поиска и устанавливает фокус"""
        # Скрываем поле перехода к строке
        self.goto_widget.hide()
        
        # Показываем поле поиска
        self.search_widget.show()
        self.search_edit.setFocus()
        self.search_edit.selectAll()
        
    def hide_search(self):
        """Скрывает поле поиска"""
        self.search_widget.hide()
        self.editor.setFocus()
        
    def show_goto(self):
        """Показывает поле перехода к строке и устанавливает фокус"""
        # Скрываем поле поиска
        self.search_widget.hide()
        
        # Показываем поле перехода к строке
        self.goto_widget.show()
        self.goto_edit.setFocus()
        self.goto_edit.selectAll()
        
    def hide_goto(self):
        """Скрывает поле перехода к строке"""
        self.goto_widget.hide()
        self.editor.setFocus()
    
    def eventFilter(self, obj, event):
        """Фильтр событий для перехвата клавиатурных сочетаний"""
        if event.type() == QEvent.KeyPress:
            # Если это редактор или поле поиска/перехода - обрабатываем клавиши
            if obj == self.editor:
                # Проверяем Ctrl+F для поиска
                if event.modifiers() & Qt.ControlModifier and event.key() == Qt.Key_F:
                    self.show_search()
                    return True
                # Проверяем Ctrl+G для перехода к строке
                elif event.modifiers() & Qt.ControlModifier and event.key() == Qt.Key_G:
                    self.show_goto()
                    return True
                # Проверяем F3 для перехода к следующему результату поиска
                elif event.key() == Qt.Key_F3 and not (event.modifiers() & Qt.ShiftModifier):
                    self.find_next()
                    return True
                # Проверяем Shift+F3 для перехода к предыдущему результату поиска
                elif event.key() == Qt.Key_F3 and (event.modifiers() & Qt.ShiftModifier):
                    self.find_previous()
                    return True
            elif obj == self.search_edit:
                # Проверяем Esc для скрытия поиска
                if event.key() == Qt.Key_Escape:
                    self.hide_search()
                    return True
            elif obj == self.goto_edit:
                # Проверяем Esc для скрытия перехода к строке
                if event.key() == Qt.Key_Escape:
                    self.hide_goto()
                    return True
        
        return super().eventFilter(obj, event)
        
    def setPlainText(self, text):
        """Устанавливает текст в редакторе"""
        self.editor.setPlainText(text)
        
    def clear(self):
        """Очищает текст редактора"""
        self.editor.clear()
        
    def highlight_search(self, text):
        """Подсвечивает все вхождения поискового текста"""
        # Удаляем предыдущие подсветки
        self.clear_highlights()
        
        if not text:
            return
            
        # Создаем формат для подсветки
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(255, 255, 0, 100))  # Желтый фон с прозрачностью
        
        # Ищем все вхождения
        cursor = self.editor.textCursor()
        cursor.setPosition(0)
        self.editor.setTextCursor(cursor)
        
        document = self.editor.document()
        cursor = QTextCursor(document)
        
        # Находим все вхождения и сохраняем позиции
        self.search_highlights = []
        self.current_search_position = 0
        
        while not cursor.isNull() and not cursor.atEnd():
            cursor = document.find(text, cursor)
            if not cursor.isNull():
                extra_selection = QTextEdit.ExtraSelection()
                extra_selection.format = highlight_format
                extra_selection.cursor = cursor
                self.search_highlights.append(extra_selection)
        
        # Применяем подсветку
        self.editor.setExtraSelections(self.search_highlights)
        
        # Если есть результаты, перемещаемся к первому
        if self.search_highlights:
            self.editor.setTextCursor(self.search_highlights[0].cursor)
            
    def clear_highlights(self):
        """Удаляет все подсветки поиска"""
        self.search_highlights = []
        self.editor.setExtraSelections([])
        
    def find_next(self):
        """Переходит к следующему результату поиска"""
        if not self.search_highlights:
            return
            
        self.current_search_position = (self.current_search_position + 1) % len(self.search_highlights)
        search_cursor = self.search_highlights[self.current_search_position].cursor
        self.editor.setTextCursor(search_cursor)
        self.ensure_cursor_visible()
        
    def find_previous(self):
        """Переходит к предыдущему результату поиска"""
        if not self.search_highlights:
            return
            
        self.current_search_position = (self.current_search_position - 1) % len(self.search_highlights)
        search_cursor = self.search_highlights[self.current_search_position].cursor
        self.editor.setTextCursor(search_cursor)
        self.ensure_cursor_visible()
        
    def goto_line_on_type(self, text):
        """Переходит к указанной строке при вводе текста"""
        if not text:  # Если поле пустое, ничего не делаем
            return
            
        try:
            line_number = int(text)
            document = self.editor.document()
            
            # Проверяем, не больше ли номер строки, чем количество строк в документе
            if line_number > document.blockCount():
                return  # Просто игнорируем неверные значения без сообщения
                
            # Перемещаем курсор к нужной строке
            cursor = QTextCursor(document.findBlockByNumber(line_number - 1))
            self.editor.setTextCursor(cursor)
            self.ensure_cursor_visible()
            
        except ValueError:
            pass  # Игнорируем ошибки преобразования
    
    def goto_line(self):
        """Переходит к указанной строке по нажатию Enter и скрывает поле"""
        text = self.goto_edit.text()
        if not text:
            self.hide_goto()
            return
            
        try:
            line_number = int(text)
            if line_number <= 0:
                self.hide_goto()
                return
                
            document = self.editor.document()
            
            # Проверяем, не больше ли номер строки, чем количество строк в документе
            if line_number > document.blockCount():
                QMessageBox.warning(self, "Ошибка", f"Документ содержит только {document.blockCount()} строк")
                return
                
            # Перемещаем курсор к нужной строке
            cursor = QTextCursor(document.findBlockByNumber(line_number - 1))
            self.editor.setTextCursor(cursor)
            self.ensure_cursor_visible()
            
            # Скрываем поле перехода к строке после успешного перехода
            self.hide_goto()
            
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Введите корректный номер строки")
    
    def ensure_cursor_visible(self):
        """Прокручивает редактор, чтобы курсор был виден"""
        self.editor.ensureCursorVisible()

class FileEncryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.file_history = FileHistory()
        self.favorites = Favorites()
        self.selected_files = []
        self.selected_file_path = None
        self.is_dark_theme = True
        self.plugins = {}  # Dictionary to store loaded plugins
        self.load_plugins()  # Load available plugins
        self.initUI()
        self.create_menu()
     
        self.create_status_bar()
        self.create_docks()
        
        # Устанавливаем размеры и позиции доков
        self.update_dock_positions()
        
        self.load_settings()
        self.save_settings()
        
        # Update UI with plugins after everything is set up
        self.update_encryption_methods_in_ui()
        
        # Ensure there's no Information tab
        self.remove_information_tab()
        
        # Create a timer to periodically check for and remove Information tab
        self.remove_info_timer = QTimer(self)
        self.remove_info_timer.timeout.connect(self.remove_information_tab)
        self.remove_info_timer.start(1000)  # Check every 1 second

    def update_dock_positions(self):
        # Обновляем размеры горизонтального сплиттера
        if hasattr(self, 'main_splitter'):
            width = self.width()
            # Устанавливаем соотношение размеров 1:2:1
            self.main_splitter.setSizes([width//4, width//2, width//4])
            
            # Добавляем стиль для всех панелей
            for i in range(self.main_splitter.count()):
                widget = self.main_splitter.widget(i)
                 
        # Обновляем размеры вертикального сплиттера
        if hasattr(self, 'main_vertical_splitter'):
            height = self.height()
            # Устанавливаем соотношение размеров 3:1
            self.main_vertical_splitter.setSizes([height*3//4, height//4])

    def showEvent(self, event):
        QMainWindow.showEvent(self, event)
        # Обновляем расположение доков при первом показе окна
        QTimer.singleShot(100, self.update_dock_positions)
        
    def resizeEvent(self, event):
        QMainWindow.resizeEvent(self, event)
        # Обновляем расположение доков при изменении размера окна
        self.update_dock_positions()

    def initUI(self):
        self.setWindowTitle('MetrosCrypt')
        self.setGeometry(100, 100, 1200, 800)
        
        # Создаем боковую панель в стиле VS Code
        self.create_side_toolbar()
        
        # Центральный виджет будет создан в create_docks

    def create_menu(self):
        menubar = self.menuBar()
        
        # ================ Меню "Файл" ================
        file_menu = menubar.addMenu('Файл')
        
        # Новый файл
        new_action = QAction(QIcon("resource/assets/new.png"), 'Новый', self)
        new_action.setShortcut('Ctrl+N')
        new_action.setStatusTip('Создать новый файл')
        new_action.triggered.connect(self.new_file)
        file_menu.addAction(new_action)
        
        # Открыть файл
        open_action = QAction(QIcon("resource/assets/open.png"), 'Открыть...', self)
        open_action.setShortcut('Ctrl+O')
        open_action.setStatusTip('Открыть файл')
        open_action.triggered.connect(self.browse_file)
        file_menu.addAction(open_action)
        
        # Сохранить
        save_action = QAction(QIcon("resource/assets/save.png"), 'Сохранить как...', self)
        save_action.setShortcut('Ctrl+S')
        save_action.setStatusTip('Сохранить текущий файл')
        save_action.triggered.connect(self.save_as)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        # Подменю "Вкладки"
        tabs_menu = QMenu('Вкладки', self)
        
        # Закрыть текущую вкладку
        close_tab_action = QAction('Закрыть вкладку', self)
        close_tab_action.setShortcut('Ctrl+W')
        close_tab_action.setStatusTip('Закрыть текущую вкладку')
        close_tab_action.triggered.connect(lambda: self.close_file_tab(self.file_tabs.currentIndex()) if self.file_tabs.count() > 0 else None)
        tabs_menu.addAction(close_tab_action)
        
        # Закрыть все вкладки
        close_all_tabs_action = QAction('Закрыть все вкладки', self)
        close_all_tabs_action.setShortcut('Ctrl+Shift+W')
        close_all_tabs_action.setStatusTip('Закрыть все открытые вкладки')
        close_all_tabs_action.triggered.connect(self.close_all_tabs)
        tabs_menu.addAction(close_all_tabs_action)
        
        # Открыть в новом окне
        open_in_new_window_action = QAction('Открыть в новом окне', self)
        open_in_new_window_action.setShortcut('Ctrl+Shift+N')
        open_in_new_window_action.setStatusTip('Открыть текущий файл в новом окне')
        open_in_new_window_action.triggered.connect(self.open_current_file_in_new_window)
        tabs_menu.addAction(open_in_new_window_action)
        
        file_menu.addMenu(tabs_menu)
        
        file_menu.addSeparator()
        
        # Пакетная обработка
        batch_action = QAction(QIcon("resource/assets/batch.png"), 'Пакетная обработка', self)
        batch_action.setShortcut('Ctrl+B')
        batch_action.setStatusTip('Открыть пакетную обработку файлов')
        batch_action.triggered.connect(self.show_batch_tab)
       
        
        file_menu.addSeparator()
        
        # Выход
        exit_action = QAction(QIcon("resource/assets/exit.png"), 'Выход', self)
        exit_action.setShortcut('Alt+F4')
        exit_action.setStatusTip('Выйти из приложения')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        
        # ================ Меню "Правка" ================
        edit_menu = menubar.addMenu('Правка')
        
        # Поиск в текущем файле
        search_action = QAction(QIcon("resource/assets/search.png"), 'Поиск', self)
       
        search_action.setStatusTip('Поиск в текущем файле')
        search_action.triggered.connect(self.search_in_current_tab)
        edit_menu.addAction(search_action)
        
        # Перейти к строке
        goto_action = QAction(QIcon("resource/assets/goto.png"), 'Перейти к строке', self)
     
        goto_action.setStatusTip('Перейти к указанной строке')
        goto_action.triggered.connect(self.goto_line_in_current_tab)
        edit_menu.addAction(goto_action)
        
        
        # ================ Меню "Шифрование" ================
        encrypt_menu = menubar.addMenu('Шифрование')
        
        # Зашифровать текущий файл
        encrypt_action = QAction(QIcon("resource/assets/encrypt.png"), 'Зашифровать', self)
        encrypt_action.setShortcut('Ctrl+E')
        encrypt_action.setStatusTip('Зашифровать текущий файл')
        encrypt_action.triggered.connect(lambda: self.process_file('encrypt'))
        encrypt_menu.addAction(encrypt_action)
        
        # Расшифровать текущий файл
        decrypt_action = QAction(QIcon("resource/assets/decrypt.png"), 'Расшифровать', self)
        decrypt_action.setShortcut('Ctrl+D')
        decrypt_action.setStatusTip('Расшифровать текущий файл')
        decrypt_action.triggered.connect(lambda: self.process_file('decrypt'))
        encrypt_menu.addAction(decrypt_action)
        
        encrypt_menu.addSeparator()
        
        # Подменю с алгоритмами шифрования
        algorithms_menu = QMenu('Алгоритмы', self)
        
        # Подменю "Симметричные шифры"
        symmetric_menu = QMenu('Симметричные шифры', self)
        symmetric_menu.addAction(QAction('Fernet', self))
        symmetric_menu.addAction(QAction('AES', self))
        symmetric_menu.addAction(QAction('AES-CBC', self))
        symmetric_menu.addAction(QAction('ChaCha20', self))
        symmetric_menu.addAction(QAction('Salsa20', self))
        symmetric_menu.addAction(QAction('CAST', self))
        symmetric_menu.addAction(QAction('DES', self))
        symmetric_menu.addAction(QAction('ARC4', self))
        algorithms_menu.addMenu(symmetric_menu)
        
        # Подменю "Асимметричные шифры"
        asymmetric_menu = QMenu('Асимметричные шифры', self)
        asymmetric_menu.addAction(QAction('RSA', self))
        algorithms_menu.addMenu(asymmetric_menu)
        
        # Подменю "Хеш-функции"
        hash_menu = QMenu('Хеш-функции', self)
        hash_menu.addAction(QAction('SHA256', self))
        hash_menu.addAction(QAction('SHA512', self))
        hash_menu.addAction(QAction('MD5', self))
        hash_menu.addAction(QAction('RIPEMD160', self))
        hash_menu.addAction(QAction('SHA1', self))
        hash_menu.addAction(QAction('SHA3_256', self))
        hash_menu.addAction(QAction('SHA3_512', self))
        algorithms_menu.addMenu(hash_menu)
        
        # Подменю "Алгоритмы для паролей"
        password_menu = QMenu('Алгоритмы для паролей', self)
        password_menu.addAction(QAction('PBKDF2', self))
        password_menu.addAction(QAction('bcrypt', self))
        password_menu.addAction(QAction('scrypt', self))
        password_menu.addAction(QAction('HMAC', self))
        algorithms_menu.addMenu(password_menu)
        
        # Подменю "Другое"
        other_menu = QMenu('Другое', self)
        other_menu.addAction(QAction('zlib', self))
        algorithms_menu.addMenu(other_menu)
        
        encrypt_menu.addMenu(algorithms_menu)
        
        
        # ================ Меню "Вид" ================
        view_menu = menubar.addMenu('Вид')
        
        # Переключение темы
        theme_action = QAction(QIcon("resource/assets/theme.png"), 'Сменить тему', self)
        theme_action.setShortcut('Ctrl+T')
        theme_action.setStatusTip('Переключить между светлой и темной темой')
        theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(theme_action)
        
        view_menu.addSeparator()
        
        # Подменю "Панели"
        panels_menu = QMenu('Панели', self)
        
        # Показать/скрыть проводник
        explorer_action = QAction('Проводник', self)
        explorer_action.setCheckable(True)
        explorer_action.setChecked(True)
        explorer_action.triggered.connect(lambda checked: self.toggle_panel_visibility('explorer', checked))
        panels_menu.addAction(explorer_action)
        
        # Показать/скрыть действия
        actions_action = QAction('Действия', self)
        actions_action.setCheckable(True)
        actions_action.setChecked(True)
        actions_action.triggered.connect(lambda checked: self.toggle_panel_visibility('actions', checked))
        panels_menu.addAction(actions_action)
        
        # Показать/скрыть информацию
        info_action = QAction('Информация', self)
        info_action.setCheckable(True)
        info_action.setChecked(True)
        info_action.triggered.connect(lambda checked: self.toggle_panel_visibility('info', checked))
        panels_menu.addAction(info_action)
        
        view_menu.addMenu(panels_menu)
        
        view_menu.addSeparator()
        
        # Показывать скрытые файлы
        show_hidden_action = QAction('Показывать скрытые файлы', self)
        show_hidden_action.setCheckable(True)
        show_hidden_action.setStatusTip('Отображать скрытые файлы в проводнике')
        show_hidden_action.triggered.connect(self.toggle_hidden_files)
        view_menu.addAction(show_hidden_action)
        
        # Обновить проводник
        refresh_action = QAction(QIcon("resource/assets/refresh.png"), 'Обновить проводник', self)
        refresh_action.setShortcut('F5')
        refresh_action.setStatusTip('Обновить содержимое проводника')
        refresh_action.triggered.connect(self.refresh_explorer)
        view_menu.addAction(refresh_action)
        
        
        # ================ Меню "Инструменты" ================
        tools_menu = menubar.addMenu('Инструменты')
        
        # Избранное
        favorites_submenu = QMenu('Избранное', self)
        
        # Показать избранное
        show_favorites_action = QAction('Показать избранное', self)
        show_favorites_action.setStatusTip('Показать список избранного')
        show_favorites_action.triggered.connect(lambda: self.explorer.explorer_tabs.setCurrentIndex(1) if hasattr(self.explorer, 'explorer_tabs') else None)
        favorites_submenu.addAction(show_favorites_action)
        
        # Добавить текущую папку в избранное
        add_to_favorites_action = QAction('Добавить текущую папку в избранное', self)
        add_to_favorites_action.setStatusTip('Добавить текущую папку в избранное')
        add_to_favorites_action.triggered.connect(self.add_current_folder_to_favorites)
        favorites_submenu.addAction(add_to_favorites_action)
        
        # Очистить избранное
        clear_favorites_action = QAction('Очистить избранное', self)
        clear_favorites_action.setStatusTip('Удалить все элементы из избранного')
        clear_favorites_action.triggered.connect(self.clear_favorites)
        favorites_submenu.addAction(clear_favorites_action)
        
        tools_menu.addMenu(favorites_submenu)
        
        # История
        history_submenu = QMenu('История', self)
        
        # Показать историю
        show_history_action = QAction('Показать историю', self)
        show_history_action.setStatusTip('Показать историю операций')
        show_history_action.triggered.connect(self.show_history)
        history_submenu.addAction(show_history_action)
        
        # Очистить историю
        clear_history_action = QAction('Очистить историю', self)
        clear_history_action.setStatusTip('Удалить все записи из истории')
        clear_history_action.triggered.connect(self.clear_history)
        history_submenu.addAction(clear_history_action)
        
        tools_menu.addMenu(history_submenu)
        
        tools_menu.addSeparator()
        
        # Показать терминал
        terminal_action = QAction(QIcon("resource/assets/terminal.png"), 'Терминал', self)
        terminal_action.setStatusTip('Открыть встроенный терминал')
        terminal_action.triggered.connect(self.show_terminal)
        tools_menu.addAction(terminal_action)
        
        
        # ================ Меню "Справка" ================
        help_menu = menubar.addMenu('Справка')
        
        # О программе
        about_action = QAction(QIcon("resource/assets/about.png"), 'О программе', self)
        about_action.setStatusTip('Информация о программе')
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        # Справка
        help_action = QAction(QIcon("resource/assets/help.png"), 'Справка', self)
        help_action.setShortcut('F1')
        help_action.setStatusTip('Показать справку')
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
 
        
    
        
    # Вспомогательные методы для новых функций меню и тулбара
    def toggle_panel_visibility(self, panel_name, visible):
        """Показывает или скрывает указанную панель"""
        if panel_name == 'explorer':
            self.main_splitter.widget(2).setVisible(visible)  # Проводник
        elif panel_name == 'actions':
            self.main_splitter.widget(0).setVisible(visible)  # Действия
        elif panel_name == 'info':
            self.main_vertical_splitter.widget(1).setVisible(visible)  # Информация
            
    def refresh_explorer(self):
        """Обновляет содержимое проводника файлов"""
        if hasattr(self, 'explorer') and hasattr(self.explorer, 'refresh'):
            self.explorer.refresh()
            self.status_bar.showMessage('Проводник файлов обновлен', 3000)
            
    def add_current_folder_to_favorites(self):
        """Добавляет текущую папку в избранное"""
        if hasattr(self, 'explorer'):
            current_path = self.explorer.model.filePath(self.explorer.tree.rootIndex())
            self.explorer.add_to_favorites(current_path)
            
    def show_history(self):
        """Показывает вкладку истории"""
        # Переключаемся на вкладку История в информационной панели
        for i in range(self.info_tab_widget.count()):
            if self.info_tab_widget.tabText(i) == "История":
                self.info_tab_widget.setCurrentIndex(i)
                break
                
    def show_terminal(self):
        """Показывает вкладку терминала"""
        # Переключаемся на вкладку Терминал в информационной панели
        for i in range(self.info_tab_widget.count()):
            if self.info_tab_widget.tabText(i) == "Терминал":
                self.info_tab_widget.setCurrentIndex(i)
                break
                
    def search_in_current_tab(self):
        """Активирует поиск в текущей вкладке"""
        if self.file_tabs.count() > 0:
            current_tab = self.file_tabs.currentWidget()
            if hasattr(current_tab, 'show_search'):
                current_tab.show_search()
                
    def goto_line_in_current_tab(self):
        """Активирует переход к строке в текущей вкладке"""
        if self.file_tabs.count() > 0:
            current_tab = self.file_tabs.currentWidget()
            if hasattr(current_tab, 'show_goto'):
                current_tab.show_goto()
                
    def show_help(self):
        """Show help window with keyboard shortcuts"""
        help_text = """
MetrosCrypt

Эта программа позволяет шифровать и расшифровывать файлы различными методами.

Основные сочетания клавиш:
Ctrl+F - Поиск в файле
Ctrl+G - Перейти к строке
Ctrl+S - Сохранить файл
Ctrl+W - Закрыть вкладку
F5 - Обновить проводник

За дополнительной информацией обращайтесь к документации.
        """
        QMessageBox.information(self, "Справка", help_text)

    def new_file(self):
        self.selected_file_path = None
        self.key_input.clear()
        self.method_combo.setCurrentIndex(0)
        self.update_file_title(None)
        # Create new empty tab
        text_editor = TextEditor()
        self.file_tabs.addTab(text_editor, "Новый файл")
        self.file_tabs.setCurrentIndex(self.file_tabs.count() - 1)

    def save_as(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, 'Ошибка', 'Сначала выберите файл!')
            return
            
        file_name, _ = QFileDialog.getSaveFileName(self, 'Сохранить как', 
                                                 self.selected_file_path + '.encrypted')
        if file_name:
            self.process_file('encrypt', file_name)
            
    def toggle_hidden_files(self, checked):
        self.explorer.model.setFilter(QDir.AllDirs | QDir.Files | 
                                    (QDir.Hidden if checked else QDir.NoDotAndDotDot))
        self.explorer.refresh()

    def set_file_path(self, path):
        """Устанавливает путь к выбранному файлу и открывает его во вкладке"""
        self.selected_file_path = path
        self.update_file_title(path)
        # Обновляем поле с путем к файлу
        self.file_path_edit.setText(path if path else "")
        self.open_file_in_tab(path)
        
    def open_file_in_tab(self, file_path):
        """Открывает файл в новой вкладке или переключается на существующую"""
        # Проверяем, не открыт ли уже этот файл
        for tab_index, file_info in self.open_files.items():
            if file_info['path'] == file_path:
                # Если файл уже открыт, переключаемся на его вкладку
                self.file_tabs.setCurrentIndex(tab_index)
                # Обновляем поле с путем к файлу
                self.file_path_edit.setText(file_path)
                return
                
        # Создаем новую вкладку для файла
        file_name = os.path.basename(file_path)
        text_editor = TextEditor()  # Используем наш расширенный редактор
        tab_index = self.file_tabs.addTab(text_editor, file_name)
        
        # Сохраняем информацию о файле
        self.open_files[tab_index] = {
            'path': file_path,
            'name': file_name
        }
        
        # Загружаем содержимое файла
        self.load_file_content(file_path, tab_index)
        
        # Переключаемся на новую вкладку
        self.file_tabs.setCurrentIndex(tab_index)
        
        # Обновляем поле с путем к файлу
        self.file_path_edit.setText(file_path)
        
    def load_file_content(self, file_path, tab_index):
        """Загружает содержимое файла во вкладку"""
        try:
            # Проверяем размер файла
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # Если файл больше 10MB
                self.file_tabs.widget(tab_index).setPlainText("Файл слишком большой для предварительного просмотра")
                return
            
            # Пробуем открыть файл как текст
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.file_tabs.widget(tab_index).setPlainText(content)
            except UnicodeDecodeError:
                # Если не удалось декодировать как текст, показываем информацию о файле
                self.file_tabs.widget(tab_index).setPlainText(
                    f"Тип файла: Бинарный\n"
                    f"Размер: {file_size / 1024:.2f} КБ\n"
                    f"Дата изменения: {os.path.getmtime(file_path)}"
                )
        except Exception as e:
            self.file_tabs.widget(tab_index).setPlainText(f"Ошибка при чтении файла: {str(e)}")
            
    def close_file_tab(self, tab_index):
        """Закрывает вкладку с файлом"""
        # Удаляем информацию о файле
        if tab_index in self.open_files:
            del self.open_files[tab_index]
            
        # Удаляем вкладку
        self.file_tabs.removeTab(tab_index)
        
        # Обновляем индексы в словаре open_files
        new_open_files = {}
        for i, (old_index, file_info) in enumerate(self.open_files.items()):
            new_open_files[i] = file_info
        self.open_files = new_open_files
        
        # Если все вкладки закрыты, сбрасываем выбранный файл и заголовок
        if self.file_tabs.count() == 0:
            self.selected_file_path = None
            self.update_file_title(None)
            # Очищаем поле с путем к файлу
            self.file_path_edit.clear()

    def on_tab_changed(self, index):
        """Обрабатывает переключение между вкладками"""
        if index >= 0 and index in self.open_files:
            file_info = self.open_files[index]
            self.selected_file_path = file_info['path']
            self.update_file_title(file_info['path'])
            # Обновляем поле с путем к файлу
            self.file_path_edit.setText(file_info['path'])
        else:
            # Если нет активной вкладки, очищаем поле
            self.file_path_edit.clear()

    def update_file_title(self, file_path):
        """Обновляет заголовок панели шифрования с названием выбранного файла"""
        if file_path:
            filename = os.path.basename(file_path)
            self.encryption_label.setText(f"Файл - {filename}")
        else:
            self.encryption_label.setText("Просмотр")

    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Выберите файл')
        if file_name:
            self.set_file_path(file_name)

    def update_progress(self, value):
        pass # self.progress_bar.setValue(value)

    def load_settings(self):
        settings_file = get_settings_path('settings.json')
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    self.is_dark_theme = settings.get('dark_theme', True)
            except:
                self.is_dark_theme = True
        else:
            self.is_dark_theme = True
        self.apply_theme()

    def save_settings(self):
        settings_file = get_settings_path('settings.json')
        settings = {'dark_theme': self.is_dark_theme}
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)

    def apply_theme(self):
        if self.is_dark_theme:
            self.apply_dark_style()
        else:
            self.apply_light_style()

    def apply_light_style(self):
        """Применяет светлую тему из файла"""
        style_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resource', 'styles', 'light.qss')
        if os.path.exists(style_file):
            with open(style_file, 'r', encoding='utf-8') as f:
                self.setStyleSheet(f.read())
        else:
            QMessageBox.warning(self, 'Ошибка', f'Файл стиля не найден: {style_file}')

    def apply_dark_style(self):
        """Применяет темную тему из файла"""
        style_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resource', 'styles', 'dark.qss')
        if os.path.exists(style_file):
            with open(style_file, 'r', encoding='utf-8') as f:
                self.setStyleSheet(f.read())
        else:
            QMessageBox.warning(self, 'Ошибка', f'Файл стиля не найден: {style_file}')

    def create_status_bar(self):
        self.status_bar = self.statusBar()
        self.status_bar.showMessage('Готово')
        
    def remove_information_tab(self):
        """Удаляет вкладку "Информация" из info_tab_widget, если она существует."""
        if hasattr(self, 'info_tab_widget'):
            for i in range(self.info_tab_widget.count()):
                if self.info_tab_widget.tabText(i) == "Информация":
                    self.info_tab_widget.removeTab(i)
                    break
                    
    def create_docks(self):
        # Создаем главный вертикальный сплиттер
        self.main_vertical_splitter = QSplitter(Qt.Vertical)
        
        # Создаем горизонтальный сплиттер для основных панелей
        self.main_splitter = QSplitter(Qt.Horizontal)
        
        # Создаем левую панель (Проводник)
        explorer_widget = QWidget()
        explorer_layout = QVBoxLayout(explorer_widget)
        explorer_layout.setContentsMargins(0, 0, 0, 0)
        
        explorer_label = QLabel("Проводник файлов")
        explorer_label.setAlignment(Qt.AlignCenter)
        explorer_label.setStyleSheet("background-color: #1E1E1E; padding: 6px ")
        
        self.explorer = FileExplorer(self)
        
        explorer_layout.addWidget(explorer_label)
        explorer_layout.addWidget(self.explorer)
        
        # Создаем центральную панель (Файлы)
        encryption_widget = QWidget()
        encryption_layout = QVBoxLayout(encryption_widget)
        encryption_layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем виджет заголовка с кнопкой "Открыть в новом окне"
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем контейнер для заголовка
        header_container = QWidget()
        header_container.setStyleSheet("background-color: #1E1E1E; padding: 6px;")
        header_container_layout = QHBoxLayout(header_container)
        header_container_layout.setContentsMargins(10, 0, 10, 0)
        
        # Добавляем пустой растягивающийся элемент слева
        header_container_layout.addStretch(1)
        
        # Создаем метку с текстом "Просмотр" по центру
        self.encryption_label = QLabel("Просмотр")
        self.encryption_label.setAlignment(Qt.AlignCenter)
        header_container_layout.addWidget(self.encryption_label, 1)  # 1 = stretch для полного заполнения
        
        # Добавляем растягивающийся элемент между заголовком и кнопкой
        header_container_layout.addStretch(1)
        
        
        
        # Добавляем контейнер с заголовком в основной макет
        header_layout.addWidget(header_container, 1)  # 1 = stretch factor
        
        # Создаем панель для содержимого файлов с вкладками
        file_panel = QWidget()
        file_layout = QVBoxLayout(file_panel)
        
        # Создаем виджет с вкладками для файлов
        self.file_tabs = QTabWidget()
        self.file_tabs.setTabsClosable(True)
        self.file_tabs.tabCloseRequested.connect(self.close_file_tab)
        self.file_tabs.currentChanged.connect(self.on_tab_changed)
        self.file_tabs.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_tabs.customContextMenuRequested.connect(self.show_tab_context_menu)
        
        # Словарь для хранения открытых файлов
        self.open_files = {}  # {tab_index: {'path': file_path, 'name': file_name, 'original_content': content, 'has_changes': False}}
        
        file_layout.addWidget(self.file_tabs)
        
        encryption_layout.addWidget(header_widget)
        encryption_layout.addWidget(file_panel)
        
        # Создаем правую панель (Действия)
        actions_widget = QWidget()
        actions_layout = QVBoxLayout(actions_widget)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        
        actions_label = QLabel("Действия")
        actions_label.setAlignment(Qt.AlignCenter)
        actions_label.setStyleSheet("background-color: #1E1E1E; padding: 6px ")
        
        # Создаем виджет с вкладками
        actions_tab_widget = QTabWidget()
        
        # Вкладка Шифрование
        encryption_tab = QWidget()
        encryption_tab_layout = QVBoxLayout(encryption_tab)
        
        # Создаем панель для шифрования
        encrypt_panel = QWidget()
        encrypt_layout = QVBoxLayout(encrypt_panel)
        
        # Поле для отображения пути к файлу
        file_path_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        file_path_layout.addWidget(QLabel('Имя файла:'))
        file_path_layout.addWidget(self.file_path_edit)
        encrypt_layout.addLayout(file_path_layout)
        
        # Operation selection with ComboBox instead of buttons
        operation_layout = QHBoxLayout()
        self.operation_combo = QComboBox()
        self.operation_combo.addItems(['Зашифровать', 'Расшифровать'])
        self.operation_combo.currentIndexChanged.connect(self.update_confirm_key_visibility)
        operation_layout.addWidget(QLabel('Операция:'))
        operation_layout.addWidget(self.operation_combo)
        encrypt_layout.addLayout(operation_layout)
        
        # Encryption method selection
        method_layout = QHBoxLayout()
        self.method_combo = QComboBox()
        
        # Добавляем методы шифрования с категориями
        self.method_combo.addItem("-- Симметричные шифры --")
        self.method_combo.model().item(0).setEnabled(False)
        self.method_combo.addItem('Fernet')
        self.method_combo.addItem('AES')
        self.method_combo.addItem('AES-CBC')
        self.method_combo.addItem('ChaCha20')
        self.method_combo.addItem('Salsa20')
        self.method_combo.addItem('CAST')
        self.method_combo.addItem('DES')
        self.method_combo.addItem('ARC4')
        
        self.method_combo.insertSeparator(9)
        self.method_combo.addItem("-- Асимметричные шифры --")
        self.method_combo.model().item(10).setEnabled(False)
        self.method_combo.addItem('RSA')
        
        self.method_combo.insertSeparator(12)
        self.method_combo.addItem("-- Хеш-функции --")
        self.method_combo.model().item(13).setEnabled(False)
        self.method_combo.addItem('SHA256')
        self.method_combo.addItem('SHA512')
        self.method_combo.addItem('MD5')
        self.method_combo.addItem('RIPEMD160')
        self.method_combo.addItem('SHA1')
        self.method_combo.addItem('SHA3_256')
        self.method_combo.addItem('SHA3_512')
        
        self.method_combo.insertSeparator(21)
        self.method_combo.addItem("-- Алгоритмы для паролей --")
        self.method_combo.model().item(22).setEnabled(False)
        self.method_combo.addItem('PBKDF2')
        self.method_combo.addItem('bcrypt')
        self.method_combo.addItem('scrypt')
        self.method_combo.addItem('HMAC')
        
        self.method_combo.insertSeparator(27)
        self.method_combo.addItem("-- Другое --")
        self.method_combo.model().item(28).setEnabled(False)
        self.method_combo.addItem('zlib')
        
        # Выбираем первый активный элемент
        self.method_combo.setCurrentIndex(1)
        
        method_layout.addWidget(QLabel('Метод шифрования:'))
        method_layout.addWidget(self.method_combo)
        encrypt_layout.addLayout(method_layout)
        
        # Key input
        key_layout = QHBoxLayout()
        self.key_input = PasswordLineEdit(self)
        key_layout.addWidget(QLabel('Ключ:'))
        key_layout.addWidget(self.key_input)
        encrypt_layout.addLayout(key_layout)
        
        # Confirm key input (only visible for encryption)
        confirm_key_layout = QHBoxLayout()
        self.confirm_key_input = PasswordLineEdit(self)
        self.confirm_key_label = QLabel('Подтвердить ключ:')
        confirm_key_layout.addWidget(self.confirm_key_label)
        confirm_key_layout.addWidget(self.confirm_key_input)
        encrypt_layout.addLayout(confirm_key_layout)
        
        # Initial visibility for confirm key field
        self.update_confirm_key_visibility(0)  # Default is Encrypt (index 0)
        
        # Добавляем растягивающееся пространство
        encrypt_layout.addStretch(1)
        
        # Single button for processing
        process_btn = QPushButton('Выполнить')
        process_btn.clicked.connect(self.process_selected_operation)
        encrypt_layout.addWidget(process_btn)
        
        encryption_tab_layout.addWidget(encrypt_panel)
        actions_tab_widget.addTab(encryption_tab, "Шифрование")
        
        # Вкладка Пакетная обработка
        batch_tab = QWidget()
        batch_tab_layout = QVBoxLayout(batch_tab)
        
        # Создаем панель для пакетной обработки
        batch_panel = QWidget()
        batch_layout = QVBoxLayout(batch_panel)
        
        # Настройки шифрования
        batch_encrypt_group = QGroupBox('Настройки шифрования')
        batch_encrypt_layout = QVBoxLayout(batch_encrypt_group)
        
        # Выбор операции
        batch_operation_layout = QHBoxLayout()
        self.batch_operation_combo = QComboBox()
        self.batch_operation_combo.addItems(['Зашифровать', 'Расшифровать'])
        self.batch_operation_combo.currentIndexChanged.connect(self.update_batch_confirm_key_visibility)
        batch_operation_layout.addWidget(QLabel('Операция:'))
        batch_operation_layout.addWidget(self.batch_operation_combo)
        batch_encrypt_layout.addLayout(batch_operation_layout)
        
        # Выбор метода
        batch_method_layout = QHBoxLayout()
        self.batch_method_combo = QComboBox()
        
        # Добавляем методы шифрования с категориями
        self.batch_method_combo.addItem("-- Симметричные шифры --")
        self.batch_method_combo.model().item(0).setEnabled(False)
        self.batch_method_combo.addItem('Fernet')
        self.batch_method_combo.addItem('AES')
        self.batch_method_combo.addItem('AES-CBC')
        self.batch_method_combo.addItem('ChaCha20')
        self.batch_method_combo.addItem('Salsa20')
        self.batch_method_combo.addItem('CAST')
        self.batch_method_combo.addItem('DES')
        self.batch_method_combo.addItem('ARC4')
        
        self.batch_method_combo.insertSeparator(9)
        self.batch_method_combo.addItem("-- Асимметричные шифры --")
        self.batch_method_combo.model().item(10).setEnabled(False)
        self.batch_method_combo.addItem('RSA')
        
        self.batch_method_combo.insertSeparator(12)
        self.batch_method_combo.addItem("-- Хеш-функции --")
        self.batch_method_combo.model().item(13).setEnabled(False)
        self.batch_method_combo.addItem('SHA256')
        self.batch_method_combo.addItem('SHA512')
        self.batch_method_combo.addItem('MD5')
        self.batch_method_combo.addItem('RIPEMD160')
        self.batch_method_combo.addItem('SHA1')
        self.batch_method_combo.addItem('SHA3_256')
        self.batch_method_combo.addItem('SHA3_512')
        
        self.batch_method_combo.insertSeparator(21)
        self.batch_method_combo.addItem("-- Алгоритмы для паролей --")
        self.batch_method_combo.model().item(22).setEnabled(False)
        self.batch_method_combo.addItem('PBKDF2')
        self.batch_method_combo.addItem('bcrypt')
        self.batch_method_combo.addItem('scrypt')
        self.batch_method_combo.addItem('HMAC')
        
        self.batch_method_combo.insertSeparator(27)
        self.batch_method_combo.addItem("-- Другое --")
        self.batch_method_combo.model().item(28).setEnabled(False)
        self.batch_method_combo.addItem('zlib')
        
        # Выбираем первый активный элемент
        self.batch_method_combo.setCurrentIndex(1)
        
        batch_method_layout.addWidget(QLabel('Метод шифрования:'))
        batch_method_layout.addWidget(self.batch_method_combo)
        batch_encrypt_layout.addLayout(batch_method_layout)
        
        # Ввод ключа
        batch_key_layout = QHBoxLayout()
        self.batch_key_input = PasswordLineEdit(self)
        batch_key_layout.addWidget(QLabel('Ключ:'))
        batch_key_layout.addWidget(self.batch_key_input)
        batch_encrypt_layout.addLayout(batch_key_layout)
        
        # Подтверждение ключа (видимо только при шифровании)
        batch_confirm_key_layout = QHBoxLayout()
        self.batch_confirm_key_input = PasswordLineEdit(self)
        self.batch_confirm_key_label = QLabel('Подтвердить ключ:')
        batch_confirm_key_layout.addWidget(self.batch_confirm_key_label)
        batch_confirm_key_layout.addWidget(self.batch_confirm_key_input)
        batch_encrypt_layout.addLayout(batch_confirm_key_layout)
        
        # Начальная видимость поля подтверждения ключа
        self.update_batch_confirm_key_visibility(0)  # По умолчанию Зашифровать (индекс 0)
        
        batch_layout.addWidget(batch_encrypt_group)
        
        # Список файлов
        batch_files_group = QGroupBox('Выбранные файлы')
        batch_files_layout = QVBoxLayout(batch_files_group)
        
        self.batch_files_list = QListWidget()
        batch_files_layout.addWidget(self.batch_files_list)
        
        # Кнопки для выбора файлов
        batch_files_buttons_layout = QHBoxLayout()
        add_files_btn = QPushButton('Добавить файлы')
        add_files_btn.clicked.connect(self.add_batch_files)
        remove_file_btn = QPushButton('Удалить файл')
        remove_file_btn.clicked.connect(self.remove_batch_file)
        batch_files_buttons_layout.addWidget(add_files_btn)
        batch_files_buttons_layout.addWidget(remove_file_btn)
        batch_files_layout.addLayout(batch_files_buttons_layout)
        
        batch_layout.addWidget(batch_files_group)
        
        # Добавляем растягивающееся пространство
        batch_layout.addStretch(1)
        
        # Кнопка для запуска обработки
        start_batch_btn = QPushButton('Начать обработку')
        start_batch_btn.clicked.connect(self.start_batch_processing_from_tab)
        batch_layout.addWidget(start_batch_btn)
        
        batch_tab_layout.addWidget(batch_panel)
        actions_tab_widget.addTab(batch_tab, "Пакетная обработка")
        
        # Вкладка Избранное - REMOVED FROM HERE (moved to Information section)
        
        actions_layout.addWidget(actions_label)
        actions_layout.addWidget(actions_tab_widget)
        
        # Добавляем все панели в горизонтальный сплиттер
        self.main_splitter.addWidget(actions_widget)
        self.main_splitter.addWidget(encryption_widget)
        self.main_splitter.addWidget(explorer_widget)
        
        # Устанавливаем пропорции сплиттера
        self.main_splitter.setSizes([250, 600, 250])
        
        # Добавляем горизонтальный сплиттер в вертикальный
        self.main_vertical_splitter.addWidget(self.main_splitter)
        
        # Создаем информационную панель снизу
        info_widget = QWidget()
        info_layout = QVBoxLayout(info_widget)
        info_layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем панель с вкладками для информации
        self.info_tab_widget = QTabWidget()
        
        # Сохраняем оригинальный метод addTab
        original_addTab = self.info_tab_widget.addTab
        
        # Переопределяем метод addTab для блокировки добавления вкладки "Информация"
        def filtered_addTab(widget, title):
            if title == "Информация":
                return -1  # Don't add the Information tab
            return original_addTab(widget, title)
            
        # Заменяем метод addTab на наш фильтрующий метод
        self.info_tab_widget.addTab = filtered_addTab
        
        # Вкладка История
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        
        # Список истории
        self.history_list = QListWidget()
        self.history_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_list.customContextMenuRequested.connect(self.show_history_context_menu)
        self.history_list.itemDoubleClicked.connect(self.load_from_history)
        
        # Обновляем историю
        history_layout.addWidget(self.history_list)
        
        # Вкладка Терминал
        terminal_tab = QWidget()
        terminal_layout = QVBoxLayout(terminal_tab)
        terminal_layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем терминал
        self.terminal = CustomTerminalWidget()
        terminal_layout.addWidget(self.terminal)
        
        # Добавляем вкладки
        self.info_tab_widget.addTab(history_tab, "История")
        self.info_tab_widget.addTab(terminal_tab, "Терминал")
        
        # Удаляем вкладку "Информация" если она существует
        for i in range(self.info_tab_widget.count()):
            if self.info_tab_widget.tabText(i) == "Информация":
                self.info_tab_widget.removeTab(i)
                break
        
        info_layout.addWidget(self.info_tab_widget)
        
        # Добавляем информационную панель в вертикальный сплиттер
        self.main_vertical_splitter.addWidget(info_widget)
        
        # Устанавливаем пропорции вертикального сплиттера
        self.main_vertical_splitter.setSizes([600, 200])
        
        # Устанавливаем главный сплиттер как центральный виджет главного экрана
        main_layout = QVBoxLayout(self.main_view)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.main_vertical_splitter)
        self.main_view.setLayout(main_layout)
        
        # Обновляем списки
        self.update_history_list()
        self.update_favorites_list()
        
    def show_history_context_menu(self, position):
        """Показывает контекстное меню для списка истории"""
        menu = QMenu()
        
        # Проверяем, есть ли выбранный элемент
        if self.history_list.currentItem():
            delete_action = menu.addAction("Удалить из истории")
            delete_action.triggered.connect(self.remove_from_history)
            menu.addSeparator()
        
        clear_all_action = menu.addAction("Очистить все")
        clear_all_action.triggered.connect(self.clear_history)
        
        menu.exec_(self.history_list.mapToGlobal(position))
        
    def show_favorites_context_menu(self, position):
        """Показывает контекстное меню для списка избранного"""
        menu = QMenu()
        
        # Проверяем, есть ли выбранный элемент
        if self.favorites_list.currentItem():
            delete_action = menu.addAction("Удалить из избранного")
            delete_action.triggered.connect(self.remove_from_favorites)
            menu.addSeparator()
        
        clear_all_action = menu.addAction("Очистить все")
        clear_all_action.triggered.connect(self.clear_favorites)
        
        menu.exec_(self.favorites_list.mapToGlobal(position))
        
    def remove_from_history(self):
        """Удаляет выбранный элемент из истории"""
        current_item = self.history_list.currentItem()
        if current_item:
            history_item = current_item.data(Qt.UserRole)
            # Удаляем элемент из истории
            self.file_history.history.remove(history_item)
            self.file_history.save_history()
            self.update_history_list()
            
    def clear_favorites(self):
        """Очищает весь список избранного и обновляет его в проводнике"""
        reply = QMessageBox.question(self, 'Подтверждение', 
                                   'Вы уверены, что хотите очистить все избранное?',
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.favorites.favorites = []
            self.favorites.save_favorites()
            self.update_favorites_list()

    def update_history_list(self):
        self.history_list.clear()
        for item in self.file_history.get_history():
            list_item = QListWidgetItem(f"{item['operation']}: {os.path.basename(item['file_path'])} ({item['method']})")
            list_item.setData(Qt.UserRole, item)
            self.history_list.addItem(list_item)

    def update_favorites_list(self):
        """Обновляет список избранного в проводнике"""
        if hasattr(self, 'explorer') and hasattr(self.explorer, 'update_favorites_list'):
            self.explorer.update_favorites_list()

    def load_from_history(self, item):
        history_item = item.data(Qt.UserRole)
        file_path = history_item['file_path']
        self.method_combo.setCurrentText(history_item['method'])
        
        # Если это операция расшифровки, удаляем .encrypted из имени файла
        if history_item['operation'] == 'decrypt':
            file_path = file_path.replace('.encrypted', '')
            
        self.set_file_path(file_path)

    def load_from_favorites(self, item):
        """Переадресует загрузку избранного в проводник"""
        if hasattr(self, 'explorer') and hasattr(self.explorer, 'load_from_favorites'):
            self.explorer.load_from_favorites(item)

    def clear_history(self):
        reply = QMessageBox.question(self, 'Подтверждение', 
                                   'Вы уверены, что хотите очистить историю?',
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.file_history.clear_history()
            self.update_history_list()

    def remove_from_favorites(self):
        """Функция удаления из избранного переадресована в проводник"""
        if hasattr(self, 'explorer') and hasattr(self.explorer, 'remove_from_favorites'):
            self.explorer.remove_from_favorites()

    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.apply_theme()

    def toggle_password_visibility(self):
        pass  # This method is now handled by the PasswordLineEdit class
        
    def toggle_batch_password_visibility(self):
        pass  # This method is now handled by the PasswordLineEdit class
        
    def update_password_visibility(self, text):
        pass  # This method is now handled by the PasswordLineEdit class
        
    def update_batch_password_visibility(self, text):
        pass  # This method is now handled by the PasswordLineEdit class

    def show_batch_dialog(self):
        """Теперь просто переключается на вкладку пакетной обработки"""
        self.show_batch_tab()

    def add_batch_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, 'Выберите файлы')
        for file in files:
            self.batch_files_list.addItem(file)

    def remove_batch_file(self):
        current_item = self.batch_files_list.currentItem()
        if current_item:
            self.batch_files_list.takeItem(self.batch_files_list.row(current_item))

    def start_batch_processing_from_tab(self):
        """Запускает пакетную обработку из вкладки (без диалога)"""
        if self.batch_files_list.count() == 0:
            QMessageBox.warning(self, 'Ошибка', 'Выберите хотя бы один файл!')
            return
            
        if not self.batch_key_input.text() and self.batch_method_combo.currentText() != 'RSA':
            QMessageBox.warning(self, 'Ошибка', 'Введите ключ шифрования!')
            return
        
        # Проверка совпадения ключей при шифровании
        is_encrypt = self.batch_operation_combo.currentText() == 'Зашифровать'
        if is_encrypt:
            if self.batch_key_input.text() != self.batch_confirm_key_input.text():
                QMessageBox.warning(self, 'Ошибка', 'Ключи не совпадают!')
                return
            
        # Собираем список файлов
        files = []
        for i in range(self.batch_files_list.count()):
            files.append(self.batch_files_list.item(i).text())
            
        # Определяем режим
        mode = 'encrypt' if self.batch_operation_combo.currentText() == 'Зашифровать' else 'decrypt'
        
        # Создаем воркер для пакетной обработки
        self.batch_worker = BatchWorker(
            files,
            self.batch_key_input.text(),
            self.batch_method_combo.currentText(),
            mode
        )
        
        self.batch_worker.progress.connect(self.update_progress)
        self.batch_worker.finished.connect(self.batch_operation_finished)
        self.batch_worker.error.connect(self.batch_operation_error)
        self.batch_worker.file_processed.connect(self.batch_file_processed)
        
        # self.progress_bar.setValue(0)
        self.status_bar.showMessage(f'Пакетная обработка: {mode}ing...')
        self.batch_worker.start()

    def batch_file_processed(self, file_path, success, method, mode):
        if success:
            self.status_bar.showMessage(f'Обработан файл: {os.path.basename(file_path)}')
            # Добавляем в историю
            try:
                self.file_history.add_item(file_path, method, mode)
                self.update_history_list()
            except Exception as e:
                print(f"Предупреждение при обновлении истории: {str(e)}")
        else:
            self.status_bar.showMessage(f'Ошибка при обработке файла: {os.path.basename(file_path)}')

    def batch_operation_finished(self):
        self.status_bar.showMessage('Пакетная обработка успешно завершена!')
        QMessageBox.information(self, 'Успех', 'Пакетная обработка успешно завершена!')
        # Обновляем проводник после завершения операции
        self.explorer.refresh()

    def batch_operation_error(self, error_message):
        self.status_bar.showMessage('Произошла ошибка!')
        QMessageBox.critical(self, 'Ошибка', f'Произошла ошибка: {error_message}')

    def process_selected_operation(self):
        """Process the selected operation from the combo box"""
        operation = self.operation_combo.currentText()
        
        if operation == 'Зашифровать':
            # For encryption, verify that keys match
            if self.key_input.text() != self.confirm_key_input.text():
                QMessageBox.warning(self, 'Ошибка', 'Ключи не совпадают!')
                return
            self.process_file('encrypt')
        else:  # Расшифровать
            self.process_file('decrypt')

    def process_file(self, mode, output_file=None):
        if not self.selected_file_path:
            QMessageBox.warning(self, 'Ошибка', 'Сначала выберите файл!')
            return

        method = self.method_combo.currentText()
        
        # Check if this is a plugin method
        if method in self.plugins:
            plugin = self.plugins[method]
            if plugin.requires_key and not self.key_input.text():
                QMessageBox.warning(self, 'Ошибка', 'Введите ключ шифрования!')
                return
        elif not self.key_input.text() and method != 'RSA':
            QMessageBox.warning(self, 'Ошибка', 'Введите ключ шифрования!')
            return

        input_file = self.selected_file_path
        if not output_file:
            output_file = input_file + ('.encrypted' if mode == 'encrypt' else '.decrypted')
        
        # Create worker thread
        self.worker = EncryptionWorker(
            input_file,
            output_file,
            self.key_input.text(),
            method,
            mode
        )
        
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.operation_finished)
        self.worker.error.connect(self.operation_error)
        
        self.status_bar.showMessage(f'{mode.capitalize()}ing...')
        self.worker.start()
        
        # Добавляем в историю
        self.file_history.add_item(input_file, method, mode)
        self.update_history_list()

    def operation_finished(self):
        """Called when encryption/decryption operation is finished"""
        self.statusBar().showMessage('Операция успешно завершена', 5000)
        
        # Обновляем проводник после завершения операции
        self.explorer.refresh()
        
        # Показываем уведомление об успешном завершении
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Успех")
        msg_box.setText("Операция успешно завершена")
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.setDefaultButton(QMessageBox.Ok)
        msg_box.exec_()

    def operation_error(self, error_message):
        self.status_bar.showMessage('Произошла ошибка!')
        QMessageBox.critical(self, 'Ошибка', f'Произошла ошибка: {error_message}')

    def show_about(self):
        QMessageBox.about(self, 'О программе',
                         'File Encryptor/Decryptor\n\n'
                         'Версия 1.1\n\n'
                         'Программа для шифрования и дешифрования файлов\n'
                         'с использованием различных алгоритмов шифрования.\n\n'
                         'Новые возможности:\n'
                         '- История операций\n'
                         '- Избранные папки\n'
                         '- Пакетная обработка файлов\n'
                         '- Темная и светлая темы\n'
                         '- Улучшенный интерфейс')

    def show_favorites(self):
        # Показываем вкладку избранного в панели информации
        info_widget = self.main_vertical_splitter.widget(1)  # Получаем панель информации
        if info_widget:
            # Находим QTabWidget внутри панели информации
            for child in info_widget.children():
                if isinstance(child, QTabWidget):
                    # Находим индекс вкладки "Избранное"
                    for i in range(child.count()):
                        if child.tabText(i) == "Избранное":
                            child.setCurrentIndex(i)
                            break
                    break

    def update_confirm_key_visibility(self, index):
        """Update the visibility of confirm key field based on operation selection"""
        # If Encrypt (index 0), show confirm key field; if Decrypt (index 1), hide it
        is_encrypt = index == 0
        self.confirm_key_label.setVisible(is_encrypt)
        self.confirm_key_input.setVisible(is_encrypt)

    def show_tab_context_menu(self, position):
        menu = QMenu()
        
        # Получаем индекс вкладки под курсором
        index = self.file_tabs.tabBar().tabAt(position)
        
        # Если клик был на вкладке, показываем контекстное меню
        if index >= 0:
            file_info = self.open_files[index]
            file_path = file_info['path']
            file_dir = os.path.dirname(file_path)
            
            # Добавляем действия для вкладки
            close_tab_action = menu.addAction("Закрыть вкладку")
            close_tab_action.setShortcut(QKeySequence("Ctrl+W"))
            
            close_all_tabs_action = menu.addAction("Закрыть все вкладки")
            close_all_tabs_action.setShortcut(QKeySequence("Ctrl+Shift+W"))
            
            menu.addSeparator()
            
            open_windows_action = menu.addAction("Открыть файл [windows]")
            open_in_new_window_action = menu.addAction("Открыть файл в новом окне")
            open_in_new_window_action.setShortcut(QKeySequence("Ctrl+Shift+N"))
            
            menu.addSeparator()
            
            open_folder_action = menu.addAction("Открыть папку файла в проводнике")
            open_cmd_action = menu.addAction("Открыть папку файла в cmd")
            
            menu.addSeparator()
            
            copy_path_action = menu.addAction("Копировать полный путь в буфер обмена")
            
            action = menu.exec_(self.file_tabs.mapToGlobal(position))
            
            if action == close_tab_action:
                self.close_file_tab(index)
            elif action == close_all_tabs_action:
                self.close_all_tabs()
            elif action == open_windows_action:
                if os.path.exists(file_path):
                    os.startfile(file_path)
            elif action == open_in_new_window_action:
                self.open_current_file_in_new_window()
            elif action == open_folder_action:
                self.open_folder_in_explorer(file_dir)
            elif action == open_cmd_action:
                self.open_folder_in_cmd(file_dir)
            elif action == copy_path_action:
                self.copy_to_clipboard(file_path)  # Копируем полный путь, а не только директорию
                
    def close_all_tabs(self):
        """Закрывает все открытые вкладки"""
        while self.file_tabs.count() > 0:
            self.close_file_tab(0)
            
    def open_folder_in_explorer(self, folder_path):
        """Открывает указанную папку в проводнике Windows"""
        if os.path.exists(folder_path):
            os.startfile(folder_path)
        
    def open_folder_in_cmd(self, folder_path):
        """Открывает командную строку в указанной папке"""
        if os.path.exists(folder_path):
            subprocess.Popen(f'cmd.exe /K cd /d "{folder_path}"', shell=True)
            
    def copy_to_clipboard(self, text):
        """Копирует текст в буфер обмена"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.status_bar.showMessage(f'Путь скопирован: {text}', 3000)
    
    def delete_selected(self):
        index = self.tree.currentIndex()
        if not index.isValid():
            return
            
        file_path = self.model.filePath(index)
        reply = QMessageBox.question(self, 'Подтверждение', 
                                   f'Удалить {os.path.basename(file_path)}?',
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.worker = FileOperationsWorker('delete', file_path)
            self.worker.finished.connect(self.refresh)
            self.worker.error.connect(lambda msg: QMessageBox.warning(self, 'Ошибка', msg))
            self.worker.start()
                
    def rename_selected(self):
        index = self.tree.currentIndex()
        if not index.isValid():
            return
            
        old_path = self.model.filePath(index)
        old_name = os.path.basename(old_path)
        new_name, ok = QInputDialog.getText(self, 'Переименовать', 
                                          'Введите новое имя:', 
                                          QLineEdit.Normal, old_name)
        
        if ok and new_name:
            new_path = os.path.join(os.path.dirname(old_path), new_name)
            self.worker = FileOperationsWorker('rename', old_path, new_path)
            self.worker.finished.connect(self.refresh)
            self.worker.error.connect(lambda msg: QMessageBox.warning(self, 'Ошибка', msg))
            self.worker.start()
            
    def copy_selected(self):
        index = self.tree.currentIndex()
        if not index.isValid():
            return
            
        src_path = self.model.filePath(index)
        dst_path, _ = QFileDialog.getExistingDirectory(self, 'Выберите папку назначения')
        
        if dst_path:
            dst_path = os.path.join(dst_path, os.path.basename(src_path))
            self.worker = FileOperationsWorker('copy', src_path, dst_path)
            self.worker.finished.connect(self.refresh)
            self.worker.error.connect(lambda msg: QMessageBox.warning(self, 'Ошибка', msg))
            self.worker.start()
            
    def move_selected(self):
        index = self.tree.currentIndex()
        if not index.isValid():
            return
            
        src_path = self.model.filePath(index)
        dst_path, _ = QFileDialog.getExistingDirectory(self, 'Выберите папку назначения')
        
        if dst_path:
            dst_path = os.path.join(dst_path, os.path.basename(src_path))
            self.worker = FileOperationsWorker('move', src_path, dst_path)
            self.worker.finished.connect(self.refresh)
            self.worker.error.connect(lambda msg: QMessageBox.warning(self, 'Ошибка', msg))
            self.worker.start()
        
    def refresh(self):
        current_path = self.model.filePath(self.tree.rootIndex())
        self.tree.setRootIndex(self.model.index(current_path))
        # Обновляем заголовок окна
        self.update_window_title()
        
    def on_file_selected(self, index):
        file_path = self.model.filePath(index)
        if os.path.isfile(file_path):
            if self.parent:
                self.parent.set_file_path(file_path)
                
    def add_to_favorites(self, folder_path=None):
        """Добавляет папку в избранное"""
        if folder_path is None:
            folder_path = self.model.filePath(self.tree.rootIndex())
            
        name, ok = QInputDialog.getText(self, 'Добавить в избранное', 
                                      'Введите имя для избранного:',
                                      QLineEdit.Normal, os.path.basename(folder_path))
        
        if ok and name:
            self.favorites.add_favorite(folder_path, name)
            # Обновляем список избранного напрямую
            if self.parent:
                # Обновляем список избранного в родительском окне
                self.parent.update_favorites_list()
                # Находим виджет списка избранного в главном окне
                for child in self.parent.findChildren(QListWidget):
                    if child.objectName() == "favorites_list":
                        child.clear()
                        for fav in self.favorites.get_favorites():
                            list_item = QListWidgetItem(fav['name'])
                            list_item.setData(Qt.UserRole, fav)
                            child.addItem(list_item)
                        break
            QMessageBox.information(self, 'Избранное', f'Папка "{name}" добавлена в избранное')

    def show_favorites_context_menu(self, position):
        """Функция показа контекстного меню избранного переадресована в проводник"""
        pass  # Функциональность перенесена в класс FileExplorer
        
    def remove_from_favorites(self):
        """Функция удаления из избранного переадресована в проводник"""
        pass  # Функциональность перенесена в класс FileExplorer
        
    def load_from_favorites(self, item):
        """Функция загрузки из избранного переадресована в проводник"""
        pass  # Функциональность перенесена в класс FileExplorer
        
    def clear_favorites(self):
        """Функция очистки избранного переадресована в проводник"""
        pass  # Функциональность перенесена в класс FileExplorer

    def update_batch_confirm_key_visibility(self, index):
        """Update the visibility of confirm key field in batch dialog based on operation selection"""
        # If Encrypt (index 0), show confirm key field; if Decrypt (index 1), hide it
        is_encrypt = index == 0
        self.batch_confirm_key_label.setVisible(is_encrypt)
        self.batch_confirm_key_input.setVisible(is_encrypt)

    def show_batch_tab(self):
        """Переключается на вкладку пакетной обработки в секции Действия"""
        # Найти TabWidget в секции Действия и переключить его на вкладку "Пакетная обработка"
        actions_widget = self.main_splitter.widget(0)  # Первый виджет в основном сплиттере (индекс 0)
        if actions_widget:
            tab_widget = actions_widget.findChild(QTabWidget)
            if tab_widget:
                # Найти индекс вкладки "Пакетная обработка"
                for i in range(tab_widget.count()):
                    if tab_widget.tabText(i) == "Пакетная обработка":
                        tab_widget.setCurrentIndex(i)
                        break

    def start_batch_processing(self, dialog=None):
        """Сохранено для обратной совместимости, но теперь использует start_batch_processing_from_tab"""
        if dialog:
            dialog.accept()
        self.start_batch_processing_from_tab()

    def open_current_file_in_new_window(self):
        """Открывает текущий файл в диалоговом окне с текстовым редактором"""
        current_tab_index = self.file_tabs.currentIndex()
        
        if current_tab_index >= 0 and current_tab_index in self.open_files:
            file_path = self.open_files[current_tab_index]['path']
            
            if file_path and os.path.exists(file_path):
                try:
                    # Создаем диалог для просмотра файла
                    file_dialog = QDialog(self)
                    file_dialog.setWindowTitle(f"Просмотр файла - {os.path.basename(file_path)}")
                    file_dialog.resize(800, 600)
                    
                    # Создаем компоненты интерфейса
                    layout = QVBoxLayout(file_dialog)
                    
                    # Информация о файле
                    info_label = QLabel(f"Файл: {file_path}")
                    layout.addWidget(info_label)
                    
                    # Текстовый редактор
                    text_edit = QTextEdit()
                    text_edit.setReadOnly(True)  # Только для чтения
                    layout.addWidget(text_edit)
                    
                    # Кнопки
                    button_box = QHBoxLayout()
                    close_button = QPushButton("Закрыть")
                    close_button.clicked.connect(file_dialog.close)
                    button_box.addStretch()
                    button_box.addWidget(close_button)
                    layout.addLayout(button_box)
                    
                    # Загружаем содержимое файла
                    try:
                        # Проверяем размер файла
                        file_size = os.path.getsize(file_path)
                        
                        if file_size > 10 * 1024 * 1024:  # Если файл больше 10MB
                            text_edit.setPlainText("Файл слишком большой для отображения.")
                        else:
                            # Пробуем открыть как текстовый файл
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                text_edit.setPlainText(content)
                            except UnicodeDecodeError:
                                # Если не удалось декодировать как текст, показываем информацию о файле
                                text_edit.setPlainText(
                                    f"Тип файла: Бинарный\n"
                                    f"Размер: {file_size / 1024:.2f} КБ\n"
                                    f"Дата изменения: {datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')}"
                                )
                    except Exception as e:
                        text_edit.setPlainText(f"Ошибка при чтении файла: {str(e)}")
                    
                    # Показываем диалог
                    file_dialog.exec_()
                    
                    self.status_bar.showMessage(f'Файл открыт в диалоговом окне: {file_path}', 3000)
                except Exception as e:
                    QMessageBox.warning(self, 'Ошибка', f'Не удалось открыть файл: {str(e)}')
            else:
                QMessageBox.warning(self, 'Ошибка', 'Файл не найден')
        else:
            QMessageBox.information(self, 'Информация', 'Нет открытых файлов для отображения')

    def create_side_toolbar(self):
        """Создает вертикальную панель инструментов в стиле VS Code"""
        # Создаем вертикальный тулбар
        self.side_toolbar = QToolBar("Боковая панель")
        self.side_toolbar.setIconSize(QSize(32, 32))
        self.side_toolbar.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.side_toolbar.setOrientation(Qt.Vertical)
        self.side_toolbar.setMovable(False)
        self.side_toolbar.setFloatable(False)
        self.side_toolbar.setFixedWidth(50)
        self.addToolBar(Qt.LeftToolBarArea, self.side_toolbar)
        
        # Главная (основной экран)
        home_action = QAction(QIcon("resource/assets/home.png"), 'Главная', self)
        home_action.setStatusTip('Вернуться на главный экран')
        home_action.triggered.connect(self.show_main_view)
        self.side_toolbar.addAction(home_action)
        
        # Плагины
        plugins_action = QAction(QIcon("resource/assets/plugins.png"), 'Плагины', self)
        plugins_action.setStatusTip('Управление плагинами')
        plugins_action.triggered.connect(self.show_plugins_view)
        self.side_toolbar.addAction(plugins_action)
        
        # Добавляем растягивающийся элемент перед последней кнопкой
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.side_toolbar.addWidget(spacer)
        
        # Настройки (в самом низу)
        settings_action = QAction(QIcon("resource/assets/help.png"), 'Справка', self)
        settings_action.setStatusTip('Открыть справку программы')
        settings_action.triggered.connect(self.show_settings_view)
        self.side_toolbar.addAction(settings_action)
        
        # Создаем стековый виджет для различных представлений
        self.view_stack = QStackedWidget()
        
        # Добавляем основной виджет в стек (будет создан в create_docks)
        self.main_view = QWidget()
        self.view_stack.addWidget(self.main_view)
        
        # Добавляем виджет плагинов в стек
        self.plugins_view = self.create_plugins_view()
        self.view_stack.addWidget(self.plugins_view)
        
        # Добавляем виджет настроек в стек
        self.settings_view = self.create_settings_view()
        self.view_stack.addWidget(self.settings_view)
        
        # Устанавливаем стековый виджет в качестве центрального
        self.setCentralWidget(self.view_stack)
    
    def show_main_view(self):
        """Показывает главный экран с редактором"""
        self.view_stack.setCurrentWidget(self.main_view)
        self.remove_information_tab()
    
    def show_plugins_view(self):
        """Показывает экран управления плагинами"""
        self.view_stack.setCurrentWidget(self.plugins_view)
    
    def show_settings_view(self):
        """Показывает локальную справку в стиле Apple вместо GitHub"""
        readme_path = os.path.join(current_dir, 'readme', 'index.html')
        # Проверяем, существует ли файл
        if os.path.exists(readme_path):
            file_url = QUrl.fromLocalFile(readme_path)
            self.view_stack.setCurrentWidget(self.settings_view)
            # Обновляем URL на локальную справку
            if hasattr(self, 'web_view'):
                self.web_view.setUrl(file_url)
        else:
            # Если справка не найдена, открываем GitHub
            self.view_stack.setCurrentWidget(self.settings_view)
            if hasattr(self, 'web_view'):
                self.web_view.setUrl(QUrl("https://github.com/metros-software/MetrosCrypt"))
    
    def create_plugins_view(self):
        """Создает виджет для управления плагинами"""
        plugins_widget = QWidget()
        plugins_layout = QVBoxLayout(plugins_widget)
        plugins_layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем сплиттер для разделения области плагинов и текстового редактора
        plugins_splitter = QSplitter(Qt.Horizontal)
        
        # Создаем QDockWidget для плагинов
        plugins_dock = QDockWidget("Плагины")
        plugins_dock.setFeatures(QDockWidget.NoDockWidgetFeatures)  # Отключаем возможность перемещения
        
        # Создаем контейнер для содержимого дока
        dock_content = QWidget()
        dock_layout = QVBoxLayout(dock_content)
        dock_layout.setContentsMargins(5, 5, 5, 5)
        
        # Создаем строку поиска и помещаем её в док
        search_layout = QHBoxLayout()
        search_label = QLabel("Поиск:")
        self.plugins_search = QLineEdit()
        self.plugins_search.setPlaceholderText("Введите текст для поиска плагинов...")
        self.plugins_search.textChanged.connect(self.filter_plugins)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.plugins_search)
        dock_layout.addLayout(search_layout)
        
        # Кнопки для управления плагинами
        plugin_buttons_layout = QHBoxLayout()
        
        add_plugin_btn = QPushButton("Добавить плагин")
        add_plugin_btn.clicked.connect(self.add_plugin_from_file)
        
        refresh_plugins_btn = QPushButton("Обновить")
        refresh_plugins_btn.clicked.connect(self.refresh_plugins)
        
        plugin_buttons_layout.addWidget(add_plugin_btn)
        plugin_buttons_layout.addWidget(refresh_plugins_btn)
        dock_layout.addLayout(plugin_buttons_layout)
        
        # Создаем виджет для отображения плагинов
        plugins_widget_content = QWidget()
        plugins_widget_layout = QVBoxLayout(plugins_widget_content)
        plugins_widget_layout.setContentsMargins(10, 10, 10, 10)
        
        # Заголовок для плагинов
        plugins_label = QLabel("Плагины")
        plugins_label.setStyleSheet("font-weight: bold;")
        plugins_widget_layout.addWidget(plugins_label)
        
        # Добавляем QListWidget для отображения плагинов
        self.plugins_list = QListWidget()
        self.plugins_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.plugins_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.plugins_list.customContextMenuRequested.connect(self.show_plugin_context_menu)
        self.plugins_list.itemSelectionChanged.connect(self.show_plugin_info)
        
        # Заполняем список плагинов
        self.update_plugins_list()
        
        # Добавляем список плагинов в лейаут
        plugins_widget_layout.addWidget(self.plugins_list)
        
        # Добавляем виджет в док
        dock_layout.addWidget(plugins_widget_content)
        
        # Устанавливаем виджет-контейнер как содержимое дока
        plugins_dock.setWidget(dock_content)
        
        # Создаем текстовый редактор для информации о плагине
        self.plugin_info_editor = QTextEdit()
        self.plugin_info_editor.setReadOnly(True)
        self.plugin_info_editor.setPlaceholderText("Информация о плагине и документация...")
        
        # Добавляем виджеты в сплиттер
        plugins_splitter.addWidget(plugins_dock)
        plugins_splitter.addWidget(self.plugin_info_editor)
        
        # Устанавливаем начальные размеры сплиттера (40% для плагинов, 60% для редактора)
        plugins_splitter.setSizes([400, 600])
        
        # Добавляем сплиттер в основной layout
        plugins_layout.addWidget(plugins_splitter)
        
        return plugins_widget
    
    def create_settings_view(self):
        """Создает веб-виджет для отображения GitHub страницы"""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Создаем веб-виджет
        self.web_view = QWebEngineView()
        self.web_view.setUrl(QUrl("https://github.com/metros-software/MetrosCrypt"))
        
        # Добавляем веб-виджет в лейаут
        layout.addWidget(self.web_view)
        
        return settings_widget

    def load_plugins(self):
        """Loads all available encryption plugins"""
        try:
            # Ensure plugins directory exists
            plugins_dir = os.path.join(current_dir, 'plugins')
            if not os.path.exists(plugins_dir):
                os.makedirs(plugins_dir)
                print(f"Created plugins directory at {plugins_dir}")
                return

            # Try to import plugins
            try:
                from plugins import available_plugins
                for plugin_class in available_plugins:
                    try:
                        plugin = plugin_class()
                        self.plugins[plugin.name] = plugin
                        print(f"Loaded plugin: {plugin.name} v{plugin.version} by {plugin.author}")
                    except Exception as plugin_error:
                        print(f"Error initializing plugin {plugin_class.__name__}: {str(plugin_error)}")
            except ImportError as import_error:
                print(f"Error importing plugins: {str(import_error)}")
                print("Make sure plugins/__init__.py exists and is properly configured")
        except Exception as e:
            print(f"Error in plugin system: {str(e)}")
            import traceback
            traceback.print_exc()
            
    def update_encryption_methods_in_ui(self):
        """Updates all UI elements to include plugin encryption methods"""
        if not hasattr(self, 'method_combo'):
            return
            
        # Try to get plugin categories
        plugin_categories = {}
        category_labels = {}
        try:
            from plugins import plugin_categories, CATEGORIES
            category_labels = CATEGORIES
        except ImportError:
            pass
            
        # Group plugins by category
        plugins_by_category = {}
        for name, plugin in self.plugins.items():
            category = plugin_categories.get(name, "plugin")
            if category not in plugins_by_category:
                plugins_by_category[category] = []
            plugins_by_category[category].append(name)
            
        # Add plugins to method_combo with categories
        for category, plugins in plugins_by_category.items():
            category_label = category_labels.get(category, f"-- {category.capitalize()} --")
            
            # Check if category already exists in combobox
            category_exists = False
            for i in range(self.method_combo.count()):
                if self.method_combo.itemText(i) == category_label:
                    category_exists = True
                    break
                    
            if not category_exists:
                self.method_combo.addItem(category_label)
                # Make category entry non-selectable
                self.method_combo.model().setData(
                    self.method_combo.model().index(self.method_combo.count()-1, 0), 
                    0, 
                    Qt.UserRole - 1
                )
                
            # Add plugins under the category
            for name in plugins:
                if self.method_combo.findText(name) == -1:
                    self.method_combo.addItem(name)
                
        # Similarly for batch_method_combo if it exists
        if hasattr(self, 'batch_method_combo'):
            for category, plugins in plugins_by_category.items():
                category_label = category_labels.get(category, f"-- {category.capitalize()} --")
                
                # Check if category already exists in combobox
                category_exists = False
                for i in range(self.batch_method_combo.count()):
                    if self.batch_method_combo.itemText(i) == category_label:
                        category_exists = True
                        break
                        
                if not category_exists:
                    self.batch_method_combo.addItem(category_label)
                    # Make category entry non-selectable
                    self.batch_method_combo.model().setData(
                        self.batch_method_combo.model().index(self.batch_method_combo.count()-1, 0), 
                        0, 
                        Qt.UserRole - 1
                    )
                    
                # Add plugins under the category
                for name in plugins:
                    if self.batch_method_combo.findText(name) == -1:
                        self.batch_method_combo.addItem(name)
            
        # Update plugins list if it exists
        if hasattr(self, 'plugins_list'):
            self.update_plugins_list()
            
        # Add plugins to encryption menu if it exists
        if hasattr(self, 'encryption_menu'):
            for category, plugins in plugins_by_category.items():
                category_label = category_labels.get(category, f"-- {category.capitalize()} --")
                
                # Check if category already exists in menu
                category_exists = False
                for action in self.encryption_menu.actions():
                    if action.text() == category_label:
                        category_exists = True
                        break
                        
                if not category_exists:
                    # Add category separator
                    self.encryption_menu.addSeparator()
                    category_action = QAction(category_label, self)
                    category_action.setEnabled(False)
                    self.encryption_menu.addAction(category_action)
                
                # Add plugins under the category
                for name in plugins:
                    # Check if action already exists
                    action_exists = False
                    for action in self.encryption_menu.actions():
                        if action.text() == name:
                            action_exists = True
                            break
                            
                    if not action_exists:
                        plugin_action = QAction(name, self)
                        plugin_action.setStatusTip(f'Использовать метод шифрования {name}')
                        plugin_action.triggered.connect(lambda checked, method=name: self.set_encryption_method(method))
                        self.encryption_menu.addAction(plugin_action)

    def set_encryption_method(self, method):
        """Sets the selected encryption method in the UI"""
        if hasattr(self, 'method_combo') and self.method_combo.findText(method) != -1:
            self.method_combo.setCurrentText(method)
        
    def update_plugins_list(self):
        """Обновляет список доступных плагинов"""
        self.plugins_list.clear()
        for name, plugin in self.plugins.items():
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, plugin)
            self.plugins_list.addItem(item)
            
    def add_plugin_to_ui(self, plugin):
        """Adds a new plugin to all related UI elements"""
        # Get plugin categories
        plugin_categories = {}
        category_labels = {}
        try:
            from plugins import plugin_categories, CATEGORIES
            category_labels = CATEGORIES
        except ImportError:
            pass
            
        # Determine plugin category
        category = plugin_categories.get(plugin.name, "plugin")
        category_label = category_labels.get(category, f"-- {category.capitalize()} --")
        
        # Add to comboboxes
        if hasattr(self, 'method_combo'):
            # Check if category exists in combobox
            category_exists = False
            for i in range(self.method_combo.count()):
                if self.method_combo.itemText(i) == category_label:
                    category_exists = True
                    break
                    
            if not category_exists:
                self.method_combo.addItem(category_label)
                # Make category entry non-selectable
                self.method_combo.model().setData(
                    self.method_combo.model().index(self.method_combo.count()-1, 0), 
                    0, 
                    Qt.UserRole - 1
                )
                
            # Add plugin
            if self.method_combo.findText(plugin.name) == -1:
                self.method_combo.addItem(plugin.name)
            
        if hasattr(self, 'batch_method_combo'):
            # Check if category exists in combobox
            category_exists = False
            for i in range(self.batch_method_combo.count()):
                if self.batch_method_combo.itemText(i) == category_label:
                    category_exists = True
                    break
                    
            if not category_exists:
                self.batch_method_combo.addItem(category_label)
                # Make category entry non-selectable
                self.batch_method_combo.model().setData(
                    self.batch_method_combo.model().index(self.batch_method_combo.count()-1, 0), 
                    0, 
                    Qt.UserRole - 1
                )
                
            # Add plugin
            if self.batch_method_combo.findText(plugin.name) == -1:
                self.batch_method_combo.addItem(plugin.name)
            
        # Add to encryption menu
        if hasattr(self, 'encryption_menu'):
            # Check if category already exists in menu
            category_exists = False
            for action in self.encryption_menu.actions():
                if action.text() == category_label:
                    category_exists = True
                    break
                    
            if not category_exists:
                # Add category separator
                self.encryption_menu.addSeparator()
                category_action = QAction(category_label, self)
                category_action.setEnabled(False)
                self.encryption_menu.addAction(category_action)
            
            # Check if action already exists
            action_exists = False
            for action in self.encryption_menu.actions():
                if action.text() == plugin.name:
                    action_exists = True
                    break
                    
            if not action_exists:
                plugin_action = QAction(plugin.name, self)
                plugin_action.setStatusTip(f'Использовать метод шифрования {plugin.name}')
                plugin_action.triggered.connect(lambda checked, method=plugin.name: self.set_encryption_method(method))
                self.encryption_menu.addAction(plugin_action)
                
        # Update plugins list if it exists
        if hasattr(self, 'plugins_list'):
            item = QListWidgetItem(plugin.name)
            item.setData(Qt.UserRole, plugin)
            self.plugins_list.addItem(item)

    def filter_plugins(self, text):
        """Фильтрует список плагинов по поисковому запросу"""
        for i in range(self.plugins_list.count()):
            item = self.plugins_list.item(i)
            plugin = item.data(Qt.UserRole)
            item.setHidden(
                text.lower() not in plugin.name.lower() and
                text.lower() not in plugin.description.lower()
            )

    def show_plugin_context_menu(self, position):
        """Показывает контекстное меню для плагина"""
        menu = QMenu()
        
        if self.plugins_list.currentItem():
            plugin = self.plugins_list.currentItem().data(Qt.UserRole)
            
            info_action = menu.addAction("Информация")
            info_action.triggered.connect(lambda: self.show_plugin_info())
            
            menu.addSeparator()
            
            use_action = menu.addAction("Использовать")
            use_action.triggered.connect(lambda: self.use_plugin(plugin))
            
            menu.addSeparator()
            
            edit_action = menu.addAction("Просмотреть код")
            edit_action.triggered.connect(lambda: self.edit_plugin(plugin))
            
            delete_action = menu.addAction("Удалить")
            delete_action.triggered.connect(lambda: self.delete_plugin(plugin))
            
            menu.exec_(self.plugins_list.mapToGlobal(position))

    def show_plugin_info(self):
        """Показывает информацию о выбранном плагине"""
        if self.plugins_list.currentItem():
            plugin = self.plugins_list.currentItem().data(Qt.UserRole)
            info = f"Название: {plugin.name}\n"
            info += f"Версия: {plugin.version}\n"
            info += f"Автор: {plugin.author}\n"
            info += f"\nОписание:\n{plugin.description}"
            self.plugin_info_editor.setPlainText(info)

    def use_plugin(self, plugin):
        """Устанавливает выбранный плагин как текущий метод шифрования"""
        if hasattr(self, 'method_combo'):
            self.method_combo.setCurrentText(plugin.name)
        self.show_main_view()  # Возвращаемся к главному экрану

    def add_plugin_from_file(self):
        """Добавляет новый плагин из Python файла"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self, 
            "Выберите файл плагина", 
            "", 
            "Python Files (*.py)"
        )
        
        if not file_path:
            return
            
        try:
            # Копируем файл плагина в папку plugins
            plugin_name = os.path.basename(file_path)
            destination = os.path.join("plugins", plugin_name)
            
            # Если файл уже существует, спрашиваем о перезаписи
            if os.path.exists(destination):
                reply = QMessageBox.question(
                    self, 
                    'Плагин уже существует', 
                    f'Плагин {plugin_name} уже существует. Перезаписать?',
                    QMessageBox.Yes | QMessageBox.No, 
                    QMessageBox.No
                )
                
                if reply == QMessageBox.No:
                    return
            
            # Копируем файл
            import shutil
            shutil.copy2(file_path, destination)
            
            # Спрашиваем название плагина для категоризации
            plugin_class_name = ""
            with open(file_path, 'r') as f:
                content = f.read()
                # Ищем имя класса плагина
                import re
                class_pattern = re.compile(r'class\s+(\w+)\s*\(\s*BaseEncryptionPlugin\s*\)')
                match = class_pattern.search(content)
                if match:
                    plugin_class_name = match.group(1)
            
            # Обновляем __init__.py файл, чтобы добавить плагин
            self.update_init_file_with_new_plugin(destination, plugin_class_name)
            
            # Перезагружаем плагины
            self.refresh_plugins()
            
            QMessageBox.information(
                self, 
                'Плагин добавлен', 
                f'Плагин {plugin_name} успешно добавлен.'
            )
            
        except Exception as e:
            QMessageBox.critical(
                self, 
                'Ошибка', 
                f'Не удалось добавить плагин: {str(e)}'
            )
            
    def update_init_file_with_new_plugin(self, plugin_path, class_name):
        """Обновляет __init__.py файл, чтобы добавить новый плагин"""
        if not class_name:
            return
            
        # Определяем имя модуля из пути к файлу
        module_name = os.path.basename(plugin_path)
        if module_name.endswith('.py'):
            module_name = module_name[:-3]  # Убираем расширение .py
            
        init_path = os.path.join("plugins", "__init__.py")
        
        if os.path.exists(init_path):
            with open(init_path, 'r') as f:
                content = f.read()
                
            # Добавляем импорт плагина, если его еще нет
            import_statement = f"from .{module_name} import {class_name}"
            if import_statement not in content:
                # Находим первую пустую строку после других импортов
                import_section_end = content.find('\n\n')
                if import_section_end != -1:
                    content = content[:import_section_end] + f"\n{import_statement}" + content[import_section_end:]
                else:
                    # Добавляем в начало файла
                    content = import_statement + "\n" + content
            
            # Добавляем плагин в список available_plugins
            available_plugins_pattern = re.compile(r'available_plugins\s*=\s*\[(.*?)\]', re.DOTALL)
            match = available_plugins_pattern.search(content)
            
            if match:
                plugins_list = match.group(1).strip()
                if class_name not in plugins_list:
                    if plugins_list:
                        # Добавляем запятую, если список не пустой
                        if not plugins_list.endswith(','):
                            plugins_list += ','
                        plugins_list += f"\n    {class_name}"
                    else:
                        plugins_list = f"\n    {class_name}\n"
                        
                    content = content.replace(match.group(0), f"available_plugins = [{plugins_list}]")
            
            # Добавляем запись в plugin_categories
            plugin_name = None
            # Пытаемся определить имя плагина из файла
            with open(plugin_path, 'r') as f:
                plugin_content = f.read()
                name_pattern = re.compile(r'def\s+name.*?return\s+[\'"]([^\'"]+)[\'"]', re.DOTALL)
                name_match = name_pattern.search(plugin_content)
                if name_match:
                    plugin_name = name_match.group(1)
            
            if plugin_name:
                plugin_categories_pattern = re.compile(r'plugin_categories\s*=\s*\{(.*?)\}', re.DOTALL)
                match = plugin_categories_pattern.search(content)
                
                if match:
                    categories_dict = match.group(1).strip()
                    new_entry = f'    "{plugin_name}": "plugin"'
                    
                    if new_entry not in categories_dict:
                        if categories_dict:
                            # Добавляем запятую, если словарь не пустой
                            if not categories_dict.endswith(','):
                                categories_dict += ','
                            categories_dict += f"\n{new_entry}"
                        else:
                            categories_dict = f"\n{new_entry}\n"
                            
                        content = content.replace(match.group(0), f"plugin_categories = {{{categories_dict}}}")
            
            # Записываем обновленный контент
            with open(init_path, 'w') as f:
                f.write(content)

    def refresh_plugins(self):
        """Перезагружает все плагины из директории plugins"""
        try:
            # Сохраняем текущие плагины для очистки UI
            old_plugins = list(self.plugins.keys())
            
            # Очищаем текущие плагины
            self.plugins = {}
            
            # Удаляем старые модули плагинов из системы
            import sys
            for module_name in list(sys.modules.keys()):
                if module_name.startswith('plugins.'):
                    del sys.modules[module_name]
            
            # Удаляем плагины из UI перед их перезагрузкой
            self.clean_plugins_from_ui(old_plugins)
            
            # Перезагружаем модуль plugins
            if 'plugins' in sys.modules:
                del sys.modules['plugins']
                
            # Загружаем плагины заново
            self.load_plugins()
            
            # Обновляем интерфейс
            self.update_encryption_methods_in_ui()
            
            # Очищаем информацию о плагине
            self.plugin_info_editor.clear()
            
        except Exception as e:
            QMessageBox.critical(
                self, 
                'Ошибка', 
                f'Не удалось обновить плагины: {str(e)}'
            )

    def clean_plugins_from_ui(self, plugin_names):
        """Удаляет плагины из элементов интерфейса"""
        # Удаляем из комбобоксов
        if hasattr(self, 'method_combo'):
            for name in plugin_names:
                index = self.method_combo.findText(name)
                if index != -1:
                    self.method_combo.removeItem(index)
                    
        if hasattr(self, 'batch_method_combo'):
            for name in plugin_names:
                index = self.batch_method_combo.findText(name)
                if index != -1:
                    self.batch_method_combo.removeItem(index)
                    
        # Удаляем из меню
        if hasattr(self, 'encryption_menu'):
            for action in self.encryption_menu.actions():
                if action.text() in plugin_names:
                    self.encryption_menu.removeAction(action)

    def edit_plugin(self, plugin):
        """Открывает плагин для редактирования"""
        try:
            # Определяем путь к файлу плагина
            plugin_name = plugin.name
            plugin_module = plugin.__class__.__module__
            module_parts = plugin_module.split('.')
            
            if len(module_parts) > 1:
                module_filename = module_parts[-1]
                plugin_path = os.path.join("plugins", f"{module_filename}.py")
            else:
                # Если не можем определить точный путь, ищем по имени класса
                plugin_class_name = plugin.__class__.__name__
                # Ищем файл плагина, содержащий имя класса
                plugin_path = None
                for file in os.listdir("plugins"):
                    if file.endswith(".py") and file != "__init__.py" and file != "base_plugin.py":
                        with open(os.path.join("plugins", file), 'r') as f:
                            content = f.read()
                            if f"class {plugin_class_name}" in content:
                                plugin_path = os.path.join("plugins", file)
                                break
            
            if plugin_path and os.path.exists(plugin_path):
                # Открываем файл в редакторе
                self.open_file_in_tab(plugin_path)
            else:
                QMessageBox.warning(
                    self, 
                    'Файл не найден', 
                    f'Не удалось найти файл для плагина {plugin_name}'
                )
        except Exception as e:
            QMessageBox.critical(
                self, 
                'Ошибка', 
                f'Не удалось открыть плагин: {str(e)}'
            )

    def delete_plugin(self, plugin):
        """Удаляет плагин из системы"""
        plugin_name = plugin.name
        
        reply = QMessageBox.question(
            self, 
            'Удаление плагина', 
            f'Вы уверены, что хотите удалить плагин {plugin_name}?',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
            
        try:
            # Определяем путь к файлу плагина аналогично edit_plugin
            plugin_module = plugin.__class__.__module__
            module_parts = plugin_module.split('.')
            
            if len(module_parts) > 1:
                module_filename = module_parts[-1]
                plugin_path = os.path.join("plugins", f"{module_filename}.py")
            else:
                # Если не можем определить точный путь, ищем по имени класса
                plugin_class_name = plugin.__class__.__name__
                plugin_path = None
                for file in os.listdir("plugins"):
                    if file.endswith(".py") and file != "__init__.py" and file != "base_plugin.py":
                        with open(os.path.join("plugins", file), 'r') as f:
                            content = f.read()
                            if f"class {plugin_class_name}" in content:
                                plugin_path = os.path.join("plugins", file)
                                break
            
            if plugin_path and os.path.exists(plugin_path):
                # Удаляем файл плагина
                os.remove(plugin_path)
                
                # Обновляем __init__.py, чтобы удалить плагин из available_plugins
                self.update_init_file_after_deletion(plugin_class_name)
                
                # Перезагружаем плагины
                self.refresh_plugins()
                
                QMessageBox.information(
                    self, 
                    'Плагин удален', 
                    f'Плагин {plugin_name} успешно удален'
                )
            else:
                QMessageBox.warning(
                    self, 
                    'Файл не найден', 
                    f'Не удалось найти файл для плагина {plugin_name}'
                )
        except Exception as e:
            QMessageBox.critical(
                self, 
                'Ошибка', 
                f'Не удалось удалить плагин: {str(e)}'
            )

    def update_init_file_after_deletion(self, plugin_class_name):
        """Обновляет __init__.py после удаления плагина"""
        init_path = os.path.join("plugins", "__init__.py")
        
        if os.path.exists(init_path):
            with open(init_path, 'r') as f:
                content = f.read()
                
            # Удаляем импорт плагина
            import_pattern = re.compile(f"from \\..*? import {plugin_class_name}")
            content = import_pattern.sub("", content)
            
            # Удаляем плагин из available_plugins
            plugins_pattern = re.compile(f"[ \t]*{plugin_class_name}[ \t]*,?")
            content = plugins_pattern.sub("", content)
            
            # Удаляем лишние запятые из списка
            content = content.replace(",]", "]")
            content = content.replace("[ ", "[")
            content = content.replace("\n\n\n", "\n\n")
            
            with open(init_path, 'w') as f:
                f.write(content)

# Функция для получения пути к папке настроек
def get_settings_path(filename=None):
    """
    Возвращает путь к папке настроек в AppData/MetrosCrypt
    Если filename указан, добавляет имя файла к пути
    """
    app_data = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'MetrosCrypt')
    
    # Создаем папку, если она не существует
    if not os.path.exists(app_data):
        os.makedirs(app_data)
        
    if filename:
        return os.path.join(app_data, filename)
    return app_data

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setWindowIcon(QIcon('resource/assets/app.png'))
    ex = FileEncryptorApp()
    import pywinstyles
    pywinstyles.apply_style(ex, 'dark')

    ex.show()
    sys.exit(app.exec_()) 
