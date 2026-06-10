"""
Lisans yönetimi testleri.
"""
import pytest
from app.core.security import generate_license_key


class TestLicenseCreation:
    def test_key_format(self):
        """Üretilen lisans anahtarı doğru formatta olmalı."""
        key = generate_license_key()
        assert key.startswith("NEXUS-")
        parts = key.split("-")
        assert len(parts) == 7  # NEXUS + 6 grup

    def test_key_uniqueness(self):
        """Her üretilen anahtar benzersiz olmalı."""
        keys = {generate_license_key() for _ in range(100)}
        assert len(keys) == 100  # Hiç çakışma yok

    def test_key_length(self):
        """Anahtar uzunluğu sabit olmalı."""
        key = generate_license_key()
        assert len(key) == 6 + 1 + 5 * 6 + 5  # NEXUS- + 6*(5char+dash)


class TestHwidHash:
    def test_same_input_same_hash(self):
        """Aynı HWID her seferinde aynı hash üretmeli."""
        from app.core.security import hash_hwid
        h1 = hash_hwid("test_hwid_12345")
        h2 = hash_hwid("test_hwid_12345")
        assert h1 == h2

    def test_different_inputs_different_hashes(self):
        """Farklı HWID'ler farklı hash üretmeli."""
        from app.core.security import hash_hwid
        h1 = hash_hwid("hwid_aaa")
        h2 = hash_hwid("hwid_bbb")
        assert h1 != h2

    def test_hash_is_64_chars(self):
        """Hash 64 karakter (SHA-256 hex) olmalı."""
        from app.core.security import hash_hwid
        h = hash_hwid("test")
        assert len(h) == 64
