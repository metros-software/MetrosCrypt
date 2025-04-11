from .base_plugin import BaseEncryptionPlugin
from .xor_plugin import XOREncryptionPlugin

# List of available plugins
available_plugins = [
    XOREncryptionPlugin
]

# Plugin categories
CATEGORIES = {
    "symmetric": "-- Симметричные шифры --",
    "asymmetric": "-- Асимметричные шифры --",
    "hash": "-- Хеш-функции --",
    "password": "-- Алгоритмы для паролей --",
    "other": "-- Другое --",
    "plugin": "-- Плагины --"
}

# Plugin category mapping
plugin_categories = {
    "XOR": "plugin"  # XOR plugin belongs to "plugin" category
} 