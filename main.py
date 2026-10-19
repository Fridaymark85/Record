from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import base64
import calendar
import ctypes
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import tkinter.font as tkfont
import uuid
import customtkinter as ctk
from PIL import Image
import tkinter as tk
from tkinter import Canvas, PhotoImage, filedialog, messagebox, simpledialog, ttk
from openpyxl import Workbook, load_workbook
from openpyxl.styles import (
    Alignment,
    Border,
    Font,
    PatternFill,
    Side,
)
from openpyxl.utils.exceptions import InvalidFileException
from zipfile import BadZipFile
from xml.etree.ElementTree import ParseError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_asset_path(filename):
  bundle_dir = getattr(
      sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))
  )
  return os.path.join(bundle_dir, "assets", filename)


class AuthManager:

  PROFILE_VERSION = 1
  HASH_ITERATIONS = 600000

  def __init__(self, profile_path=None):
    if profile_path is None:
      app_dir = (
          os.path.dirname(sys.executable)
          if getattr(sys, "frozen", False)
          else os.path.dirname(os.path.abspath(__file__))
      )
      profile_path = os.path.join(
          app_dir, "material_records", ".login.json"
      )
    self.profile_path = profile_path

  @property
  def has_account(self):
    return os.path.isfile(self.profile_path)

  @staticmethod
  def _normalize_username(username):
    return str(username).strip().casefold()

  @staticmethod
  def _normalize_recovery_answer(answer):
    return " ".join(str(answer).strip().casefold().split())

  @classmethod
  def _make_hash(cls, value):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        salt,
        cls.HASH_ITERATIONS,
    )
    return salt.hex(), digest.hex()

  @classmethod
  def _matches_hash(cls, value, salt_hex, digest_hex):
    try:
      salt = bytes.fromhex(salt_hex)
      expected = bytes.fromhex(digest_hex)
    except ValueError:
      return False
    actual = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        salt,
        cls.HASH_ITERATIONS,
    )
    return hmac.compare_digest(actual, expected)

  def _read_profile(self):
    with open(self.profile_path, "r", encoding="utf-8") as profile_file:
      profile = json.load(profile_file)
    required = (
        "username_salt",
        "username_hash",
        "password_salt",
        "password_hash",
        "recovery_question",
        "recovery_salt",
        "recovery_hash",
    )
    if (
        not isinstance(profile, dict)
        or profile.get("version") != self.PROFILE_VERSION
        or any(not isinstance(profile.get(key), str) for key in required)
    ):
      raise ValueError(
          "The local login file is invalid. Keep a copy and contact your "
          "application administrator."
      )
    return profile

  @staticmethod
  def _is_valid_password(password):
    return (
        isinstance(password, str)
        and 8 <= len(password) <= 1024
        and not password.isspace()
    )

  def _write_profile(self, profile):
    os.makedirs(os.path.dirname(self.profile_path), exist_ok=True)
    temporary_path = None
    try:
      with tempfile.NamedTemporaryFile(
          mode="w",
          encoding="utf-8",
          dir=os.path.dirname(self.profile_path),
          suffix=".tmp",
          delete=False,
      ) as temporary_file:
        temporary_path = temporary_file.name
        json.dump(profile, temporary_file, indent=2)
      if os.name != "nt":
        os.chmod(temporary_path, 0o600)
      os.replace(temporary_path, self.profile_path)
      temporary_path = None
      if os.name == "nt":
        attributes = ctypes.windll.kernel32.GetFileAttributesW(
            self.profile_path
        )
        if attributes == -1:
          raise ctypes.WinError(ctypes.get_last_error())
        if not ctypes.windll.kernel32.SetFileAttributesW(
            self.profile_path, attributes | 0x2
        ):
          raise ctypes.WinError(ctypes.get_last_error())
    finally:
      if temporary_path and os.path.exists(temporary_path):
        os.remove(temporary_path)

  def create_account(
      self,
      username,
      password,
      confirm_password,
      recovery_question,
      recovery_answer,
  ):
    username = self._normalize_username(username)
    question = str(recovery_question).strip()
    answer = self._normalize_recovery_answer(recovery_answer)
    if self.has_account:
      return False, "A local account is already configured."
    if not username or len(username) > 64:
      return False, "Enter a username between 1 and 64 characters."
    if not self._is_valid_password(password):
      return False, "Password must be at least 8 characters."
    if password != confirm_password:
      return False, "The passwords do not match."
    if len(question) < 5 or len(question) > 200:
      return False, "Enter a recovery question between 5 and 200 characters."
    if len(answer) < 2 or len(answer) > 200:
      return False, "Enter a recovery answer between 2 and 200 characters."

    username_salt, username_hash = self._make_hash(username)
    password_salt, password_hash = self._make_hash(password)
    recovery_salt, recovery_hash = self._make_hash(answer)
    self._write_profile({
        "version": self.PROFILE_VERSION,
        "hash_iterations": self.HASH_ITERATIONS,
        "username_salt": username_salt,
        "username_hash": username_hash,
        "password_salt": password_salt,
        "password_hash": password_hash,
        "recovery_question": question,
        "recovery_salt": recovery_salt,
        "recovery_hash": recovery_hash,
    })
    return True, "Account created."

  def authenticate(self, username, password):
    if not self.has_account or len(str(password)) > 1024:
      return False
    profile = self._read_profile()
    username_matches = self._matches_hash(
        self._normalize_username(username),
        profile["username_salt"],
        profile["username_hash"],
    )
    password_matches = self._matches_hash(
        str(password),
        profile["password_salt"],
        profile["password_hash"],
    )
    return username_matches and password_matches

  def verify_recovery_answer(self, username, answer):
    if not self.has_account:
      return False
    profile = self._read_profile()
    return self._matches_hash(
        self._normalize_username(username),
        profile["username_salt"],
        profile["username_hash"],
    ) and self._matches_hash(
        self._normalize_recovery_answer(answer),
        profile["recovery_salt"],
        profile["recovery_hash"],
    )

  def get_recovery_question(self, username):
    if not self.has_account:
      return None
    profile = self._read_profile()
    matches = self._matches_hash(
        self._normalize_username(username),
        profile["username_salt"],
        profile["username_hash"],
    )
    return profile["recovery_question"] if matches else None

  def reset_password(
      self,
      username,
      recovery_answer,
      new_password,
      confirm_password,
      data_encryption=None,
  ):
    if not self.has_account:
      return False, "No local account is configured."
    if not self._is_valid_password(new_password):
      return False, "Password must be at least 8 characters."
    if new_password != confirm_password:
      return False, "The passwords do not match."
    profile = self._read_profile()
    if not self._matches_hash(
        self._normalize_username(username),
        profile["username_salt"],
        profile["username_hash"],
    ):
      return False, "The username or recovery answer is incorrect."
    if not self._matches_hash(
        self._normalize_recovery_answer(recovery_answer),
        profile["recovery_salt"],
        profile["recovery_hash"],
    ):
      return False, "The username or recovery answer is incorrect."
    if data_encryption is not None and data_encryption.is_initialized:
      data_encryption.rewrap_password(recovery_answer, new_password)
    salt, digest = self._make_hash(new_password)
    profile["password_salt"] = salt
    profile["password_hash"] = digest
    self._write_profile(profile)
    return True, "Password updated."


class DataEncryptionManager:

  FORMAT_VERSION = 1
  KDF_ITERATIONS = 600000
  KEY_SIZE = 32
  DATA_AAD = b"MaterialTracker inventory JSON v1"
  PASSWORD_AAD = b"MaterialTracker data key password v1"
  RECOVERY_AAD = b"MaterialTracker data key recovery v1"
  ENCRYPTED_FIELD = "_material_tracker_encrypted"

  def __init__(self, data_dir):
    self.data_dir = os.path.abspath(data_dir)
    self.profile_path = os.path.join(self.data_dir, ".data-key.json")
    self.backup_profile_path = os.path.join(
        self.data_dir, "backups", ".data-key.json"
    )
    self._data_key = None

  @property
  def is_initialized(self):
    return (
        os.path.isfile(self.profile_path)
        or os.path.isfile(self.backup_profile_path)
    )

  @staticmethod
  def _derive_key(secret, salt, iterations):
    return hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), salt, iterations, dklen=32
    )

  @staticmethod
  def _encode(value):
    return base64.b64encode(value).decode("ascii")

  @staticmethod
  def _decode(value):
    return base64.b64decode(value.encode("ascii"), validate=True)

  def _read_profile(self):
    profile_path = (
        self.profile_path
        if os.path.isfile(self.profile_path)
        else self.backup_profile_path
    )
    try:
      with open(profile_path, "r", encoding="utf-8") as profile_file:
        profile = json.load(profile_file)
    except (OSError, json.JSONDecodeError) as error:
      raise ValueError(
          f"Unable to read the inventory encryption profile: {error}"
      ) from error
    required_fields = (
        "password_salt",
        "password_nonce",
        "password_key",
        "recovery_salt",
        "recovery_nonce",
        "recovery_key",
    )
    if (
        not isinstance(profile, dict)
        or profile.get("version") != self.FORMAT_VERSION
        or profile.get("kdf_iterations") != self.KDF_ITERATIONS
        or any(not isinstance(profile.get(field), str) for field in required_fields)
    ):
      raise ValueError("The inventory encryption profile is invalid.")
    return profile

  def _wrap_key(self, secret, aad):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    wrapping_key = self._derive_key(secret, salt, self.KDF_ITERATIONS)
    wrapped_key = AESGCM(wrapping_key).encrypt(
        nonce, self._data_key, aad
    )
    return {
        "salt": self._encode(salt),
        "nonce": self._encode(nonce),
        "key": self._encode(wrapped_key),
    }

  def _save_profile(self, profile):
    for profile_path in (self.backup_profile_path, self.profile_path):
      directory = os.path.dirname(profile_path)
      os.makedirs(directory, exist_ok=True)
      temporary_path = None
      try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=directory,
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
          temporary_path = temporary_file.name
          json.dump(profile, temporary_file, indent=2)
        os.replace(temporary_path, profile_path)
        temporary_path = None
        if os.name == "nt":
          attributes = ctypes.windll.kernel32.GetFileAttributesW(
              profile_path
          )
          if attributes == -1:
            raise ctypes.WinError(ctypes.get_last_error())
          if not ctypes.windll.kernel32.SetFileAttributesW(
              profile_path, attributes | 0x2
          ):
            raise ctypes.WinError(ctypes.get_last_error())
      finally:
        if temporary_path and os.path.exists(temporary_path):
          os.remove(temporary_path)

  def initialize(self, password, recovery_answer):
    if self.is_initialized:
      raise ValueError("Inventory JSON encryption is already configured.")
    self._data_key = secrets.token_bytes(self.KEY_SIZE)
    password_fields = self._wrap_key(password, self.PASSWORD_AAD)
    recovery_fields = self._wrap_key(
        AuthManager._normalize_recovery_answer(recovery_answer),
        self.RECOVERY_AAD,
    )
    self._save_profile({
        "version": self.FORMAT_VERSION,
        "kdf_iterations": self.KDF_ITERATIONS,
        "password_salt": password_fields["salt"],
        "password_nonce": password_fields["nonce"],
        "password_key": password_fields["key"],
        "recovery_salt": recovery_fields["salt"],
        "recovery_nonce": recovery_fields["nonce"],
        "recovery_key": recovery_fields["key"],
    })

  def _unwrap_key(self, secret, profile, prefix, aad):
    try:
      salt = self._decode(profile[f"{prefix}_salt"])
      nonce = self._decode(profile[f"{prefix}_nonce"])
      wrapped_key = self._decode(profile[f"{prefix}_key"])
      wrapping_key = self._derive_key(
          secret, salt, profile["kdf_iterations"]
      )
      return AESGCM(wrapping_key).decrypt(nonce, wrapped_key, aad)
    except (InvalidTag, ValueError, TypeError) as error:
      raise ValueError(
          "The password or recovery answer cannot unlock the inventory data."
      ) from error

  def unlock(self, password):
    profile = self._read_profile()
    self._data_key = self._unwrap_key(
        str(password), profile, "password", self.PASSWORD_AAD
    )

  def rewrap_password(self, recovery_answer, new_password):
    profile = self._read_profile()
    self._data_key = self._unwrap_key(
        AuthManager._normalize_recovery_answer(recovery_answer),
        profile,
        "recovery",
        self.RECOVERY_AAD,
    )
    password_fields = self._wrap_key(new_password, self.PASSWORD_AAD)
    profile.update({
        "password_salt": password_fields["salt"],
        "password_nonce": password_fields["nonce"],
        "password_key": password_fields["key"],
    })
    self._save_profile(profile)

  def encrypt_bytes(self, plaintext):
    if self._data_key is None:
      raise ValueError("Inventory data is locked. Sign in to unlock it.")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(self._data_key).encrypt(
        nonce, plaintext, self.DATA_AAD
    )
    envelope = {
        self.ENCRYPTED_FIELD: self.FORMAT_VERSION,
        "nonce": self._encode(nonce),
        "ciphertext": self._encode(ciphertext),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

  def decrypt_bytes(self, content):
    try:
      envelope = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
      raise ValueError("An inventory JSON file is not encrypted.")
    if (
        not isinstance(envelope, dict)
        or envelope.get(self.ENCRYPTED_FIELD) is None
    ):
      raise ValueError("An inventory JSON file is not encrypted.")
    if envelope.get(self.ENCRYPTED_FIELD) != self.FORMAT_VERSION:
      raise ValueError("This inventory JSON uses an unsupported encryption version.")
    if self._data_key is None:
      raise ValueError("Inventory data is locked. Sign in to unlock it.")
    try:
      return AESGCM(self._data_key).decrypt(
          self._decode(envelope["nonce"]),
          self._decode(envelope["ciphertext"]),
          self.DATA_AAD,
      )
    except (InvalidTag, KeyError, ValueError, TypeError) as error:
      raise ValueError(
          "An inventory JSON file failed its encryption integrity check."
      ) from error

  def encrypt_existing_json_files(self):
    if self._data_key is None:
      raise ValueError("Inventory data is locked. Sign in to unlock it.")
    os.makedirs(self.data_dir, exist_ok=True)
    for root, _directories, filenames in os.walk(self.data_dir):
      for filename in filenames:
        if not filename.lower().endswith(".json"):
          continue
        if filename.casefold() in (".login.json", ".data-key.json"):
          continue
        path = os.path.join(root, filename)
        with open(path, "rb") as source_file:
          plaintext = source_file.read()
        try:
          envelope = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
          raise ValueError(
              f"Cannot encrypt invalid JSON file: {path}"
          )
        if (
            isinstance(envelope, dict)
            and self.ENCRYPTED_FIELD in envelope
        ):
          if envelope.get(self.ENCRYPTED_FIELD) != self.FORMAT_VERSION:
            raise ValueError(
                f"Unsupported inventory JSON encryption version: {path}"
            )
          continue
        encrypted = self.encrypt_bytes(plaintext)
        temporary_path = None
        try:
          with tempfile.NamedTemporaryFile(
              mode="wb",
              dir=root,
              suffix=".tmp",
              delete=False,
          ) as temporary_file:
            temporary_path = temporary_file.name
            temporary_file.write(encrypted)
          os.replace(temporary_path, path)
          temporary_path = None
        finally:
          if temporary_path and os.path.exists(temporary_path):
            os.remove(temporary_path)


INVENTORY_HEADERS = [
    "Sr No",
    "Part Number",
    "Component Description",
    "Category",
    "UOM",
    "Storage Location",
    "Min Stock Level",
    "Max Stock Level",
    "Reorder Level",
    "Current Stock",
    "Reserved for Production",
    "Available Stock",
    "Unit Cost",
    "Inventory Value",
    "Supplier",
    "Lead Time (Days)",
    "Shelf Life/Expiry",
    "Last Receipt Date",
    "Last Issue Date",
]
DEFAULT_VISIBLE_HEADERS = [
    "Sr No",
    "Part Number",
    "Component Description",
    "Current Stock",
    "Available Stock",
    "Reorder Level",
]
NUMERIC_INVENTORY_FIELDS = {
    "sr no",
    "min stock level",
    "max stock level",
    "reorder level",
    "current stock",
    "reserved for production",
    "available stock",
    "unit cost",
    "inventory value",
    "lead time (days)",
}
INVENTORY_DATE_FIELDS = {
    "shelf life/expiry",
    "last receipt date",
    "last issue date",
}
STOCK_UNIT_FIELDS = (
    "Unit ID",
    "Status",
    "Storage Location",
    "Received Date",
    "Received Time",
    "Issued To",
    "Issue Location",
    "Issue Date",
    "Issue Time",
)
UOM_OPTIONS = [
    "Square inch",
    "Cubic inch",
    "%",
    "%O",
    "0",
    "1",
    "A/V",
    "ACR",
    "ARM",
    "AU",
    "BAG",
    "BHN",
    "BPH",
    "BRV",
    "BT",
    "C3S",
    "CAN",
    "CAR",
    "CCM",
    "CD3",
    "CL",
    "CM",
    "CM2",
    "CMS",
    "CRT",
    "CV",
    "D",
    "DAN",
    "DAY",
    "DEG",
    "DI",
    "DM",
    "DMI",
    "DR",
    "DZ",
    "EA",
    "EML",
    "EU",
    "FOZ",
    "FT",
    "FT2",
    "FT3",
    "FYR",
    "G",
    "G/L",
    "GAL",
    "GAM",
    "GAU",
    "GLI",
    "GM",
    "GM2",
    "GM3",
    "GOH",
    "GPM",
    "GRO",
    "H",
    "HA",
    "HL",
    "HP",
    "HR",
    "HRC",
    "HRS",
    "HV",
    "IB",
    "JCM",
    "JKG",
    "JMO",
    "K/M",
    "KAI",
    "KAT",
    "KCM",
    "KD3",
    "KG",
    "KGB",
    "KGC",
    "KGM",
    "KGS",
    "KIK",
    "KJK",
    "KJM",
    "KL",
    "KM",
    "KM2",
    "KMH",
    "KMN",
    "KMS",
    "KN",
    "KPA",
    "KPI",
    "KSC",
    "KVA",
    "KWH",
    "L",
    "LB",
    "LHK",
    "LMI",
    "LMS",
    "LPH",
    "LST",
    "LT",
    "M",
    "M-2",
    "M/H",
    "M/L",
    "M/M",
    "M/S",
    "M2",
    "M2S",
    "M3",
    "M3H",
    "M3S",
    "MBT",
    "MEJ",
    "MG",
    "MGL",
    "MGO",
    "MGQ",
    "MHV",
    "MI",
    "MI2",
    "MIN",
    "MIS",
    "ML",
    "MLI",
    "MM",
    "MM2",
    "MM3",
    "MMD",
    "MMI",
    "MMM",
    "MMR",
    "MMT",
    "MN",
    "MNM",
    "MON",
    "MPG",
    "MPL",
    "MPS",
    "MS",
    "MS2",
    "MSC",
    "MSE",
    "MWH",
    "NA",
    "NAM",
    "NEM",
    "NG",
    "NI",
    "NM",
    "NMM",
    "NOS",
    "NS",
    "OC",
    "P",
    "PAA",
    "PAC",
    "PAL",
    "PAS",
    "PC",
    "PCT",
    "PF",
    "PGL",
    "PMI",
    "PPB",
    "PPM",
    "PPT",
    "PRS",
    "PSI",
    "PT",
    "QML",
    "QT",
    "R-U",
    "RF",
    "RHO",
    "ROL",
    "RPM",
    "SET",
    "SMI",
    "ST",
    "T",
    "T/H",
    "THR",
    "TO",
    "TOM",
    "TON",
    "VA",
    "VAC",
    "VAL",
    "VAM",
    "VDC",
    "WH",
    "WK",
    "YD",
    "YD2",
    "YD3",
    "YR",
    "µ/M",
    "µA",
    "µF",
    "µGL",
    "µGQ",
    "µIN",
    "µL",
    "µM",
    "µRA",
    "µRM",
    "µRZ",
]


def is_numeric_column(header, values=()):
  if header.casefold() == "uom":
    return False
  if header.casefold() in NUMERIC_INVENTORY_FIELDS:
    return True
  if not values:
    return False
  try:
    for value in values:
      Decimal(str(value).strip().replace(",", ""))
  except (InvalidOperation, AttributeError):
    return False
  return True


def get_uom_recommendations(typed_value=""):
  prefix = str(typed_value).strip().casefold()
  return [
      unit
      for unit in UOM_OPTIONS
      if unit.casefold().startswith(prefix)
  ]


# --- BACKEND: Data & Schema Engine ---
class StorageManager:

  def __init__(
      self, data_encryption=None, auth_manager=None, authenticated_username=""
  ):
    self.data_dir = os.path.abspath("material_records")
    self.export_dir = "exports"
    self.data_encryption = data_encryption
    self.auth_manager = auth_manager
    self.authenticated_username = authenticated_username
    self.protected_headers = (
        ["Date & Day", "Time"] + INVENTORY_HEADERS + ["Stock In", "Usecase"]
    )
    os.makedirs(self.data_dir, exist_ok=True)
    os.makedirs(self.export_dir, exist_ok=True)

  def _read_json_file(self, filepath):
    with open(filepath, "rb") as source_file:
      content = source_file.read()
    if self.data_encryption is not None:
      content = self.data_encryption.decrypt_bytes(content)
    return json.loads(content.decode("utf-8"))

  def _write_json_file(self, filepath, data, indent=2):
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    content = json.dumps(data, indent=indent).encode("utf-8")
    if self.data_encryption is not None:
      content = self.data_encryption.encrypt_bytes(content)
    temporary_path = None
    try:
      with tempfile.NamedTemporaryFile(
          mode="wb",
          dir=os.path.dirname(os.path.abspath(filepath)),
          suffix=".tmp",
          delete=False,
      ) as temporary_file:
        temporary_path = temporary_file.name
        temporary_file.write(content)
      os.replace(temporary_path, filepath)
      temporary_path = None
    finally:
      if temporary_path and os.path.exists(temporary_path):
        os.remove(temporary_path)

  def get_available_dates(self):
    """Returns sorted list of all dates with existing JSON records."""
    files = [
        f[:-5]
        for f in os.listdir(self.data_dir)
        if f.endswith(".json") and len(f) == 15
    ]
    today = datetime.now().strftime("%Y-%m-%d")
    if today not in files:
      files.append(today)
    return sorted(files, reverse=True)

  def get_filepath(self, date_str=None):
    if not date_str:
      date_str = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(self.data_dir, f"{date_str}.json")

  def get_backup_dir(self):
    backup_dir = os.path.join(self.data_dir, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    return backup_dir

  def get_backups(self, date_str=None):
    backup_date = date_str or datetime.now().strftime("%Y-%m-%d")
    backup_dir = self.get_backup_dir()
    backups = [
        os.path.join(backup_dir, filename)
        for filename in os.listdir(backup_dir)
        if filename.startswith(f"{backup_date}_")
        and filename.lower().endswith(".json")
        and os.path.isfile(os.path.join(backup_dir, filename))
    ]
    return sorted(backups, reverse=True)

  def restore_backup(self, date_str, backup_path):
    backup_dir = os.path.abspath(self.get_backup_dir())
    selected_path = os.path.abspath(backup_path)
    try:
      is_within_backup_dir = (
          os.path.commonpath((backup_dir, selected_path)) == backup_dir
      )
    except ValueError:
      is_within_backup_dir = False
    if not is_within_backup_dir:
      return False, "The selected backup is outside the backup folder."
    valid_backups = {
        os.path.abspath(path) for path in self.get_backups(date_str)
    }
    if selected_path not in valid_backups:
      return False, "The selected backup does not belong to this date."

    try:
      backup_data = self._read_json_file(selected_path)
      if (
          not isinstance(backup_data, dict)
          or not isinstance(backup_data.get("headers"), list)
          or not isinstance(backup_data.get("records"), list)
          or not all(isinstance(record, dict) for record in backup_data["records"])
      ):
        return False, "The selected backup does not contain valid inventory data."

      active_path = self.get_filepath(date_str)
      safety_backup = None
      if os.path.exists(active_path):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        safety_backup = os.path.join(
            backup_dir,
            f"{date_str}_before-restore_{timestamp}.json",
        )
        shutil.copy2(active_path, safety_backup)

      self._write_json_file(active_path, backup_data)

      self._clear_undo_history(date_str)
      marker_path = f"{active_path}.cleared"
      if os.path.exists(marker_path):
        os.remove(marker_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
      return False, f"Unable to restore backup: {error}"

    message = f"Restored {os.path.basename(selected_path)}."
    if safety_backup:
      message += f" Previous live data backed up to {os.path.basename(safety_backup)}."
    return True, message

  def initialize_daily_snapshot(self, date_str):
    target_date = parse_inventory_date(date_str)
    if target_date is None:
      return False
    existing_dates = sorted(
        value
        for value in os.listdir(self.data_dir)
        if value.endswith(".json")
        and len(value) == 15
        and parse_inventory_date(value[:-5]) is not None
        and parse_inventory_date(value[:-5]) <= target_date
    )
    previous_dates = [
        value[:-5]
        for value in existing_dates
        if parse_inventory_date(value[:-5]) < target_date
    ]
    if previous_dates:
      source_date = min(previous_dates)
      current_date = parse_inventory_date(source_date) + timedelta(days=1)
      last_data = self._load_data(source_date)
    else:
      current_date = target_date
      last_data = {
          "headers": (
              ["Date & Day", "Time"]
              + INVENTORY_HEADERS
              + ["Stock In", "Usecase"]
          ),
          "records": [],
      }

    created_any = False
    while current_date <= target_date:
      current_value = current_date.strftime("%Y-%m-%d")
      filepath = self.get_filepath(current_value)
      marker_path = f"{filepath}.cleared"
      if os.path.exists(filepath):
        last_data = self._load_data(current_value)
      elif not os.path.exists(marker_path):
        snapshot = {
            "headers": list(last_data["headers"]),
            "records": [record.copy() for record in last_data["records"]],
            "import_batches": last_data.get("import_batches", []).copy(),
        }
        self._write_json_file(filepath, snapshot)
        last_data = snapshot
        created_any = True
      current_date += timedelta(days=1)
    return created_any

  def _get_undo_filepath(self, date_str=None):
    filepath = self.get_filepath(date_str)
    return f"{os.path.splitext(filepath)[0]}.undo.json"

  def _record_undo_snapshot(self, date_str=None):
    filepath = self.get_filepath(date_str)
    history_path = self._get_undo_filepath(date_str)
    if os.path.exists(filepath):
      previous_data = json.dumps(self._read_json_file(filepath), indent=2)
    else:
      previous_data = None

    history = []
    if os.path.exists(history_path):
      history = self._read_json_file(history_path)
      if not isinstance(history, list):
        raise ValueError(f"Undo history is invalid: {history_path}")
    history.append(previous_data)
    self._write_json_file(history_path, history)

  def _clear_undo_history(self, date_str=None):
    history_path = self._get_undo_filepath(date_str)
    self._write_json_file(history_path, [])

  def has_undo(self, date_str=None):
    history_path = self._get_undo_filepath(date_str)
    if not os.path.exists(history_path):
      return False
    history = self._read_json_file(history_path)
    if not isinstance(history, list):
      raise ValueError(f"Undo history is invalid: {history_path}")
    return bool(history)

  def undo_last_action(self, date_str=None):
    history_path = self._get_undo_filepath(date_str)
    if not os.path.exists(history_path):
      return False, "There is no action to undo for this date."

    history = self._read_json_file(history_path)
    if not isinstance(history, list):
      raise ValueError(f"Undo history is invalid: {history_path}")
    if not history:
      return False, "There is no action to undo for this date."

    previous_data = history[-1]
    filepath = self.get_filepath(date_str)
    if previous_data is None:
      if os.path.exists(filepath):
        os.remove(filepath)
    else:
      self._write_json_file(filepath, json.loads(previous_data))
      marker_path = f"{filepath}.cleared"
      if os.path.exists(marker_path):
        os.remove(marker_path)

    history.pop()
    self._write_json_file(history_path, history)
    return True, "Last action undone."

  def clear_date_data(self, date_str=None):
    filepath = self.get_filepath(date_str)
    backup_path = None
    try:
      data = self._load_data(date_str)
      if os.path.exists(filepath):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup_path = os.path.join(
            self.get_backup_dir(),
            f"{date_str or datetime.now().strftime('%Y-%m-%d')}_{timestamp}.json",
        )
        shutil.copy2(filepath, backup_path)

      self._clear_undo_history(date_str)
      self._write_json_file(
          filepath,
          {
              "headers": data["headers"],
              "records": [],
              "import_batches": [],
          },
      )

      marker_path = f"{filepath}.cleared"
      if os.path.exists(marker_path):
        os.remove(marker_path)
    except OSError as error:
      return False, f"Unable to clear saved data: {error}"
    cleared_date = date_str or datetime.now().strftime("%Y-%m-%d")
    if backup_path:
      return (
          True,
          f"Cleared live data for {cleared_date}. Backup saved to {backup_path}.",
      )
    return True, f"Cleared live data for {cleared_date}; the JSON file was kept."

  def delete_date_json(self, date_str=None, password=None):
    filepath = self.get_filepath(date_str)
    history_path = self._get_undo_filepath(date_str)
    marker_path = f"{filepath}.cleared"
    if (
        self.auth_manager is None
        or not password
        or not self.auth_manager.authenticate(
            self.authenticated_username, password
        )
    ):
      return False, "The app password is incorrect; the JSON file was not deleted."
    backup_path = None
    try:
      if os.path.exists(filepath):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup_path = os.path.join(
            self.get_backup_dir(),
            f"{date_str or datetime.now().strftime('%Y-%m-%d')}_before-delete_{timestamp}.json",
        )
        shutil.copy2(filepath, backup_path)
        os.remove(filepath)
      if os.path.exists(history_path):
        os.remove(history_path)
      with open(marker_path, "w", encoding="utf-8") as marker_file:
        marker_file.write("deleted")
    except OSError as error:
      return False, f"Unable to delete the JSON file: {error}"
    return (
        True,
        (
            f"Deleted the active JSON file for "
            f"{date_str or datetime.now().strftime('%Y-%m-%d')}."
            + (
                f" Encrypted backup saved as {os.path.basename(backup_path)}."
                if backup_path
                else " No active JSON file needed a backup."
            )
        ),
    )

  def _load_data(self, date_str=None):
    """Loads JSON data for a specific date with schema fallback."""
    filepath = self.get_filepath(date_str)
    default_data = {
        "headers": ["Date & Day", "Time"] + INVENTORY_HEADERS + ["Stock In", "Usecase"],
        "records": [],
    }

    if not os.path.exists(filepath):
      return default_data

    try:
      content = self._read_json_file(filepath)
      if isinstance(content, list):
        headers = ["Date & Day", "Time"]
        for record in content:
          for key in record.keys():
            if key not in headers:
              headers.append(key)
        return self._ensure_inventory_schema(
            {"headers": headers, "records": content}
        )
      elif (
          isinstance(content, dict)
          and "headers" in content
          and "records" in content
      ):
        return self._ensure_inventory_schema(content)
    except json.JSONDecodeError:
      pass

    return default_data

  def _ensure_inventory_schema(self, data):
    """Add the standard fields and map legacy inventory names in memory."""
    headers = data.setdefault("headers", [])
    records = data.setdefault("records", [])
    aliases = {
        "material / item": "Component Description",
        "quantity": "Current Stock",
        "stock": "Current Stock",
    }
    canonical = {header.casefold(): header for header in INVENTORY_HEADERS}

    for record_index, record in enumerate(records, start=1):
      legacy_stock = record.get("Stock")
      legacy_opening_stock = next(
          (
              record[key]
              for key in record
              if key.casefold() == "opening stock"
          ),
          None,
      )
      for old_key in list(record):
        destination = aliases.get(old_key.casefold())
        if destination:
          if record.get(destination) in (None, ""):
            record[destination] = record[old_key]
          record.pop(old_key, None)

      for key in list(record):
        standard_key = canonical.get(key.casefold())
        if standard_key and key != standard_key:
          if record.get(standard_key) in (None, ""):
            record[standard_key] = record[key]
          record.pop(key, None)

      if (
          record.get("Current Stock") in (None, "")
          and legacy_opening_stock not in (None, "")
      ):
        record["Current Stock"] = legacy_opening_stock
      for key in list(record):
        if key.casefold() == "opening stock":
          record.pop(key, None)

      for header in INVENTORY_HEADERS:
        record.setdefault(header, "")
      record.setdefault("Stock In", "")
      record.setdefault("Usecase", "")
      if legacy_stock not in (None, ""):
        usecases = self._get_usecase_values(record)
        if usecases:
          try:
            current = Decimal(
                str(usecases[max(usecases)]["remaining"]).replace(",", "")
            )
            if current.is_finite() and current >= 0:
              record["Current Stock"] = (
                  int(current)
                  if current == current.to_integral_value()
                  else float(current)
              )
          except (InvalidOperation, AttributeError):
            pass
      if record.get("Sr No") in (None, ""):
        record["Sr No"] = record_index
      if record.get("Available Stock") in (None, ""):
        try:
          current = Decimal(
              str(record.get("Current Stock") or 0).replace(",", "")
          )
          reserved = Decimal(
              str(record.get("Reserved for Production") or 0).replace(",", "")
          )
          available = max(Decimal(0), current - reserved)
          record["Available Stock"] = (
              int(available)
              if available == available.to_integral_value()
              else float(available)
          )
        except (InvalidOperation, AttributeError):
          record["Available Stock"] = record.get("Current Stock", "")
      if record.get("Inventory Value") in (None, ""):
        try:
          current = Decimal(
              str(record.get("Current Stock") or 0).replace(",", "")
          )
          unit_cost = Decimal(
              str(record.get("Unit Cost") or 0).replace(",", "")
          )
          value = current * unit_cost
          record["Inventory Value"] = (
              int(value) if value == value.to_integral_value() else float(value)
          )
        except (InvalidOperation, AttributeError):
          record["Inventory Value"] = ""

    standard_names = {
        "date & day",
        "time",
        "material / item",
        "quantity",
        "stock",
        "opening stock",
        *(name.casefold() for name in INVENTORY_HEADERS),
    }
    extras = [
        header
        for header in headers
        if header.casefold() not in standard_names
    ]
    for record in records:
      for header in record:
        if (
            not header.startswith("_")
            and header.casefold() not in standard_names
            and header not in extras
        ):
          extras.append(header)
    if not any(header.casefold() == "stock in" for header in extras):
      extras.insert(0, "Stock In")
    data["headers"] = ["Date & Day", "Time"] + INVENTORY_HEADERS + extras
    return data

  def _save_data(self, data, date_str=None):
    filepath = self.get_filepath(date_str)
    self._record_undo_snapshot(date_str)
    self._write_json_file(filepath, data)
    marker_path = f"{filepath}.cleared"
    if os.path.exists(marker_path):
      os.remove(marker_path)

  def save_log(self, date_str=None):
    filepath = self.get_filepath(date_str)
    data = self._load_data(date_str)
    try:
      if os.path.exists(filepath):
        saved_data = self._read_json_file(filepath)
        if saved_data == data:
          return True, f"Log is saved to {filepath}."
      self._save_data(data, date_str)
    except (OSError, ValueError) as error:
      return False, f"Unable to save the log: {error}"
    return True, f"Log saved to {filepath}."

  def get_headers(self, date_str=None):
    return self._load_data(date_str)["headers"]

  def get_deletable_headers(self, date_str=None):
    return [
        h
        for h in self.get_headers(date_str)
        if h not in self.protected_headers and h.casefold() != "stock in"
    ]

  def add_column(self, col_name, date_str=None):
    col_name = col_name.strip()
    if not col_name:
      return False, "Column name cannot be empty."

    data = self._load_data(date_str)
    headers = data["headers"]

    if col_name.lower() in [h.lower() for h in headers]:
      return False, f"Column '{col_name}' already exists!"

    headers.append(col_name)
    for record in data["records"]:
      if col_name not in record:
        record[col_name] = ""

    self._save_data(data, date_str)
    return True, f"Column '{col_name}' added."

  def delete_column(self, col_name, date_str=None):
    if not col_name:
      return False, "Select a column to delete."

    if col_name in self.protected_headers or col_name.casefold() == "stock in":
      return False, f"Cannot delete system column '{col_name}'."

    data = self._load_data(date_str)
    headers = data["headers"]

    if col_name not in headers:
      return False, f"Column '{col_name}' not found."

    headers.remove(col_name)
    for record in data["records"]:
      record.pop(col_name, None)

    self._save_data(data, date_str)
    return True, f"Column '{col_name}' deleted."

  def save_row(self, row_data_dict, date_str=None):
    data = self._load_data(date_str)
    now = datetime.now()

    if date_str:
      try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        date_formatted = dt.strftime("%a, %d %b %Y")
      except ValueError:
        date_formatted = now.strftime("%a, %d %b %Y")
    else:
      date_formatted = now.strftime("%a, %d %b %Y")

    new_record = {
        "Date & Day": date_formatted,
        "Time": now.strftime("%H:%M:%S"),
    }
    new_record.update({header: "" for header in INVENTORY_HEADERS})
    serial_numbers = []
    for record in data["records"]:
      try:
        serial = Decimal(str(record.get("Sr No", "")).strip())
      except (InvalidOperation, AttributeError):
        continue
      if serial.is_finite():
        serial_numbers.append(serial)
    next_serial = max(serial_numbers, default=Decimal(0)) + 1
    new_record["Sr No"] = (
        int(next_serial)
        if next_serial == next_serial.to_integral_value()
        else float(next_serial)
    )
    new_record.update(
        {
            "Current Stock": 0,
            "Reserved for Production": 0,
            "Available Stock": 0,
            "Inventory Value": 0,
        }
    )
    new_record.update(row_data_dict)
    for field in (
        "Min Stock Level",
        "Max Stock Level",
        "Reorder Level",
        "Current Stock",
        "Reserved for Production",
        "Available Stock",
        "Unit Cost",
        "Inventory Value",
        "Lead Time (Days)",
    ):
      value = new_record.get(field)
      if value in (None, ""):
        new_record[field] = 0
        continue
      try:
        number = Decimal(str(value).strip().replace(",", ""))
      except (InvalidOperation, AttributeError):
        return False, f"{field} must be a number."
      if not number.is_finite() or number < 0:
        return False, f"{field} must be a non-negative number."
      new_record[field] = (
          int(number)
          if number == number.to_integral_value()
          else float(number)
      )
    synced, sync_message = self._sync_derived_inventory_fields(
        new_record, ["Current Stock", "Reserved for Production", "Unit Cost"]
    )
    if not synced:
      return False, sync_message
    current_stock = Decimal(str(new_record["Current Stock"]))
    if current_stock > 0:
      self._append_stock_in_entry(new_record, current_stock, date_str)
      if new_record.get("Last Receipt Date") in (None, ""):
        new_record["Last Receipt Date"] = (
            date_str or datetime.now().strftime("%Y-%m-%d")
        )
    data["records"].append(new_record)

    if not any(header.casefold() == "stock in" for header in data["headers"]):
      data["headers"].append("Stock In")
    data = self._ensure_inventory_schema(data)
    self._save_data(data, date_str)
    return True, "Inventory item added."

  def update_record(self, index, updated_dict, date_str=None):
    data = self._load_data(date_str)
    records = data["records"]

    if 0 <= index < len(records):
      record = records[index]
      self._migrate_legacy_sales(data)
      existing_fields = {
          field.casefold(): field for field in record
      }
      updated_dict = {
          existing_fields.get(
              field.casefold(),
              "Current Stock" if field.casefold() == "stock" else field,
          ): value
          for field, value in updated_dict.items()
      }
      numeric_fields = {
          "min stock level",
          "max stock level",
          "reorder level",
          "current stock",
          "reserved for production",
          "available stock",
          "unit cost",
          "inventory value",
          "lead time (days)",
      }
      for field, value in updated_dict.items():
        if field.casefold() not in numeric_fields or value in (None, ""):
          continue
        try:
          number = Decimal(str(value).strip().replace(",", ""))
        except (InvalidOperation, AttributeError):
          return False
        if not number.is_finite() or number < 0:
          return False

      stock_key = next(
          (
              key
              for key in updated_dict
              if key.casefold() in ("current stock", "stock")
          ),
          None,
      )
      new_stock = None
      old_stock = None
      if stock_key is not None:
        try:
          old_stock_value = next(
              (
                  value
                  for key, value in record.items()
                  if key.casefold() in ("current stock", "stock")
              ),
              0,
          )
          old_stock = Decimal(
              str(old_stock_value or 0).strip().replace(",", "")
          )
          new_stock = Decimal(
              str(updated_dict[stock_key]).strip().replace(",", "")
          )
        except (InvalidOperation, AttributeError):
          return False
        if (
            not old_stock.is_finite()
            or old_stock < 0
            or not new_stock.is_finite()
            or new_stock < 0
        ):
          return False

        if "_units" in record and new_stock != old_stock:
          if new_stock < old_stock:
            return False
          added = new_stock - old_stock
          if (
              new_stock != new_stock.to_integral_value()
              or added != added.to_integral_value()
          ):
            return False
          success, _message = self._append_stock_units(
              record, added, date_str
          )
          if not success:
            return False

        record.update(updated_dict)
        if new_stock > old_stock:
          self._append_stock_in_entry(
              record, new_stock - old_stock, date_str
          )
          record["Last Receipt Date"] = date_str or datetime.now().strftime(
              "%Y-%m-%d"
          )
        record["_remaining_stock"] = (
            int(new_stock)
            if new_stock == new_stock.to_integral_value()
            else float(new_stock)
        )
      else:
        record.update(updated_dict)
      synced, _message = self._sync_derived_inventory_fields(
          record, updated_dict.keys()
      )
      if not synced:
        return False
      self._save_data(data, date_str)
      return True
    return False

  @staticmethod
  def _sync_derived_inventory_fields(record, changed_fields):
    changed = {field.casefold() for field in changed_fields}
    if changed.intersection(
        {"current stock", "reserved for production", "available stock"}
    ):
      try:
        current = Decimal(
            str(record.get("Current Stock") or 0).replace(",", "")
        )
        reserved = Decimal(
            str(record.get("Reserved for Production") or 0).replace(",", "")
        )
      except (InvalidOperation, AttributeError, TypeError) as error:
        return False, f"Unable to calculate Available Stock: {error}"
      if (
          not current.is_finite()
          or current < 0
          or not reserved.is_finite()
          or reserved < 0
      ):
        return False, "Stock values must be finite, non-negative numbers."
      available = max(Decimal(0), current - reserved)
      record["Available Stock"] = (
          int(available)
          if available == available.to_integral_value()
          else float(available)
      )
    if changed.intersection(
        {"current stock", "unit cost", "inventory value"}
    ):
      try:
        current = Decimal(
            str(record.get("Current Stock") or 0).replace(",", "")
        )
        unit_cost = Decimal(
            str(record.get("Unit Cost") or 0).replace(",", "")
        )
      except (InvalidOperation, AttributeError, TypeError) as error:
        return False, f"Unable to calculate Inventory Value: {error}"
      if (
          not current.is_finite()
          or current < 0
          or not unit_cost.is_finite()
          or unit_cost < 0
      ):
        return False, "Stock and unit cost must be finite, non-negative numbers."
      value = current * unit_cost
      record["Inventory Value"] = (
          int(value) if value == value.to_integral_value() else float(value)
      )
    return True, ""

  def delete_record(self, index, date_str=None):
    data = self._load_data(date_str)
    records = data["records"]

    if 0 <= index < len(records):
      records.pop(index)
      self._save_data(data, date_str)
      return True
    return False

  def get_all_records(self, date_str=None):
    return self._load_data(date_str)["records"]

  def get_live_records(self, selected_date=None):
    date_value = selected_date or datetime.now().strftime("%Y-%m-%d")
    data = self._load_data(date_value)
    return [
        (date_value, index, record)
        for index, record in enumerate(data["records"])
    ]

  def get_live_records_between(self, start_date, end_date):
    start_value = parse_inventory_date(start_date)
    end_value = parse_inventory_date(end_date)
    if start_value is None or end_value is None or start_value > end_value:
      return []
    self.initialize_daily_snapshot(end_value.strftime("%Y-%m-%d"))
    records = []
    for date_value in sorted(self.get_available_dates()):
      record_date = parse_inventory_date(date_value)
      if (
          record_date is None
          or record_date < start_value
          or record_date > end_value
          or not os.path.exists(self.get_filepath(date_value))
      ):
        continue
      data = self._load_data(date_value)
      self._migrate_legacy_sales(data)
      records.extend(
          (date_value, index, record)
          for index, record in enumerate(data["records"])
      )
    return records

  def get_live_headers_between(self, start_date, end_date):
    headers = []
    start_value = parse_inventory_date(start_date)
    end_value = parse_inventory_date(end_date)
    if start_value is None or end_value is None or start_value > end_value:
      return []
    for date_value in sorted(self.get_available_dates()):
      record_date = parse_inventory_date(date_value)
      if (
          record_date is None
          or record_date < start_value
          or record_date > end_value
          or not os.path.exists(self.get_filepath(date_value))
      ):
        continue
      data = self._load_data(date_value)
      self._migrate_legacy_sales(data)
      for header in data["headers"]:
        if header.startswith("_") or header in headers:
          continue
        headers.append(header)
    if not headers:
      return self.get_live_headers(end_date)
    return headers

  def get_live_headers(self, selected_date=None):
    date_value = selected_date or datetime.now().strftime("%Y-%m-%d")
    return self._load_data(date_value)["headers"]

  def get_column_values(self, column_name, date_str=None):
    """Return the existing distinct values for an editable column."""
    values = {
        str(record.get(column_name)).strip()
        for record in self._load_data(date_str)["records"]
        if record.get(column_name) not in (None, "")
        and str(record.get(column_name)).strip()
    }
    return sorted(values, key=str.casefold)

  def get_usage_recipients(self, date_str=None):
    recipients = set()
    for record in self._load_data(date_str)["records"]:
      for values in self._get_usecase_values(record).values():
        recipient = values.get("customer", "").strip()
        if recipient:
          recipients.add(recipient)
    return sorted(recipients, key=str.casefold)

  @staticmethod
  def _parse_usecase_value(value):
    match = re.fullmatch(
        r"\s*(?:Usecase\s+\d+\s*\|\s*)?"
        r"Customer:\s*(.*?)\s*\|\s*"
        r"(?:Sold|Used):\s*(.*?)\s*\|\s*"
        r"Date:\s*(.*?)\s*\|\s*"
        r"(?:Time:\s*(.*?)\s*\|\s*)?"
        r"Remaining:\s*(.*?)\s*",
        str(value),
        re.IGNORECASE,
    )
    if not match:
      return None
    customer, sold, sale_date, event_time, remaining = match.groups()
    return {
        "customer": customer,
        "sold": sold,
        "date": sale_date,
        "time": event_time or "",
        "remaining": remaining,
    }

  def _get_usecase_values(self, record):
    values = {}
    for key, value in record.items():
      match = re.fullmatch(r"usecase\s+(\d+)", key, re.IGNORECASE)
      if match and value not in (None, ""):
        parsed = self._parse_usecase_value(value)
        if parsed:
          values[int(match.group(1))] = parsed
      elif key.casefold() == "usecase" and value not in (None, ""):
        for line in str(value).splitlines():
          line_match = re.match(
              r"\s*Usecase\s+(\d+)\s*\|\s*(.*)",
              line,
              re.IGNORECASE,
          )
          if not line_match:
            continue
          parsed = self._parse_usecase_value(line)
          if parsed:
            values[int(line_match.group(1))] = parsed
    return values

  def _write_usecase_history(self, record, usecases):
    entries = []
    for slot, values in sorted(usecases.items()):
      if not values.get("sold"):
        continue
      entries.append(
          f"Usecase {slot} | Customer: {values.get('customer', '')} "
          f"| Used: {values.get('sold', '')} "
          f"| Date: {values.get('date', '')} "
          f"| Time: {values.get('time', '')} "
          f"| Remaining: {values.get('remaining', '')}"
      )
    record["Usecase"] = "\n".join(entries)

  def _recalculate_usecase_remaining(self, record, stock):
    remaining = stock
    usecases = self._get_usecase_values(record)
    for slot in sorted(usecases):
      values = usecases[slot]
      sold = Decimal(str(values["sold"]).replace(",", "").strip())
      remaining -= sold
      remaining_value = (
          int(remaining)
          if remaining == remaining.to_integral_value()
          else float(remaining)
      )
      values["remaining"] = remaining_value
    self._write_usecase_history(record, usecases)
    record["_remaining_stock"] = (
        int(remaining)
        if remaining == remaining.to_integral_value()
        else float(remaining)
    )

  @staticmethod
  def _append_stock_in_entry(record, quantity, date_str=None):
    """Append a timestamped receipt without changing earlier stock-in events."""
    event_date = date_str or datetime.now().strftime("%Y-%m-%d")
    event_time = datetime.now().strftime("%H:%M:%S")
    entry = (
        f"Added: {quantity} | Date: {event_date} | Time: {event_time}"
    )
    previous_entries = str(record.get("Stock In", "")).strip()
    record["Stock In"] = (
        f"{previous_entries}\n{entry}" if previous_entries else entry
    )

  def _migrate_legacy_sales(self, data):
    legacy_fields = {
        "remaining",
        "sale date",
        "quantity sold",
        "sold to",
        "sales history",
    }
    for record in data["records"]:
      record_keys = {key.casefold(): key for key in record}
      usecases = self._get_usecase_values(record)
      legacy_usecase = record.get(record_keys.get("usecase"), "")
      for line in str(legacy_usecase).splitlines():
        match = re.match(r"\s*Usecase\s+(\d+)\s*\|\s*(.*)", line, re.IGNORECASE)
        if not match:
          continue
        parsed = self._parse_usecase_value(line)
        if parsed:
          usecases[int(match.group(1))] = parsed
      for key, value in record.items():
        match = re.fullmatch(
            r"usecase\s+(\d+)\s+(quantity|given to|remaining|date)",
            key,
            re.IGNORECASE,
        )
        if match and value not in (None, ""):
          slot = int(match.group(1))
          field = match.group(2).casefold()
          usecases.setdefault(slot, {})[field] = value

      for slot, values in list(usecases.items()):
        if "customer" in values:
          continue
        usecases[slot] = {
            "customer": values.get("given to", ""),
            "sold": values.get("quantity", ""),
            "date": values.get("date", ""),
            "remaining": values.get("remaining", ""),
        }

      history_key = record_keys.get("sales history")
      legacy_sales = []
      if history_key:
        for entry in str(record.get(history_key, "")).split(" | "):
          match = re.fullmatch(
              r"(.+?): sold (.+?) to (.*) \(remaining: (.+)\)",
              entry.strip(),
          )
          if match:
            legacy_sales.append(match.groups())

      if not legacy_sales:
        legacy_date = record.get(record_keys.get("sale date"))
        legacy_quantity = record.get(record_keys.get("quantity sold"))
        if legacy_date and legacy_quantity not in (None, ""):
          legacy_sales.append(
              (
                  str(legacy_date),
                  str(legacy_quantity),
                  str(record.get(record_keys.get("sold to"), "")),
                  str(record.get(record_keys.get("remaining"), "")),
              )
          )

      for sale_date, quantity, customer, remaining in legacy_sales:
        try:
          quantity_value = Decimal(quantity.replace(",", "").strip())
        except (InvalidOperation, AttributeError):
          continue
        if not quantity_value.is_finite() or quantity_value <= 0:
          continue
        slot = max(usecases, default=0) + 1
        quantity_value = (
            int(quantity_value)
            if quantity_value == quantity_value.to_integral_value()
            else float(quantity_value)
        )
        usecases[slot] = {
            "customer": customer,
            "sold": quantity_value,
            "date": sale_date,
            "remaining": remaining,
        }

      legacy_remaining = record.get(record_keys.get("remaining"))
      if legacy_remaining not in (None, ""):
        record["_remaining_stock"] = legacy_remaining

      for field in list(record):
        if field.casefold() in legacy_fields or re.fullmatch(
            r"usecase\s+\d+\s+(quantity|given to|remaining|date)",
            field,
            re.IGNORECASE,
        ) or re.fullmatch(r"usecase\s+\d+", field, re.IGNORECASE):
          record.pop(field, None)
      self._write_usecase_history(record, usecases)

    normalized_headers = []
    for header in data["headers"]:
      if header.casefold() in legacy_fields or re.fullmatch(
          r"usecase\s+\d+\s+(quantity|given to|remaining|date)",
          header,
          re.IGNORECASE,
      ) or re.fullmatch(r"usecase\s+\d+", header, re.IGNORECASE):
        continue
      if header.casefold() == "usecase":
        if "Usecase" not in normalized_headers:
          normalized_headers.append("Usecase")
      else:
        normalized_headers.append(header)
    data["headers"] = normalized_headers
    stock_in_header = next(
        (header for header in data["headers"] if header.casefold() == "stock in"),
        None,
    )
    if stock_in_header is None:
      stock_in_header = "Stock In"
      stock_header = next(
          (header for header in data["headers"] if header.casefold() == "stock"),
          None,
      )
      if stock_header:
        data["headers"].insert(
            data["headers"].index(stock_header) + 1, stock_in_header
        )
      else:
        data["headers"].append(stock_in_header)
    if "Usecase" not in data["headers"]:
      data["headers"].append("Usecase")

  def normalize_usecases(self, date_str=None):
    data = self._load_data(date_str)
    original = json.dumps(data, sort_keys=True)
    self._migrate_legacy_sales(data)
    if json.dumps(data, sort_keys=True) != original:
      self._save_data(data, date_str)

  def get_remaining_stock(self, record):
    return record.get("Current Stock", record.get("_remaining_stock", next(
        (
            value
            for key, value in record.items()
            if key.casefold() == "stock"
        ),
        "unknown",
    )))

  @staticmethod
  def _stock_unit_base(record):
    source = record.get("Part Number") or record.get("Sr No") or "ITEM"
    base = re.sub(r"[^A-Za-z0-9]+", "", str(source)).upper()[:5]
    prefix = str(
        record.get("_unit_id_prefix") or uuid.uuid4().hex[:4]
    )[:4].upper()
    record["_unit_id_prefix"] = prefix
    return f"{base or 'ITEM'}-{prefix}"

  @staticmethod
  def _compact_legacy_unit_id(record, unit_id):
    match = re.fullmatch(r".+-([0-9a-fA-F]{8})-(\d{4,})", unit_id)
    if match is None:
      return None
    source = record.get("Part Number") or record.get("Sr No") or "ITEM"
    base = re.sub(r"[^A-Za-z0-9]+", "", str(source)).upper()[:5] or "ITEM"
    sequence = int(match.group(2))
    return f"{base}-{match.group(1)[:4].upper()}-{sequence:02d}"

  def _append_stock_units(self, record, quantity, date_str, location=None):
    quantity = Decimal(quantity)
    if not quantity.is_finite() or quantity < 0:
      return False, "Unit quantity must be a non-negative number."
    if quantity != quantity.to_integral_value():
      return False, "Unit-level tracking requires whole-number stock."
    units = record.setdefault("_units", [])
    if not isinstance(units, list):
      return False, "Unit details are invalid; repair the unit list before continuing."
    sequence = int(record.get("_unit_sequence", 0) or 0)
    existing_ids = {
        str(unit.get("Unit ID", "")).casefold()
        for unit in units
        if isinstance(unit, dict)
    }
    timestamp = datetime.now()
    received = date_str or timestamp.strftime("%Y-%m-%d")
    current_location = (
        location
        if location is not None
        else str(record.get("Storage Location", "") or "")
    )
    for _ in range(int(quantity)):
      sequence += 1
      unit_id = f"{self._stock_unit_base(record)}-{sequence:02d}"
      while unit_id.casefold() in existing_ids:
        sequence += 1
        unit_id = f"{self._stock_unit_base(record)}-{sequence:02d}"
      existing_ids.add(unit_id.casefold())
      units.append({
          "Unit ID": unit_id,
          "Status": "In Stock",
          "Storage Location": current_location,
          "Received Date": received,
          "Received Time": timestamp.strftime("%H:%M:%S"),
          "Issued To": "",
          "Issue Location": "",
          "Issue Date": "",
          "Issue Time": "",
      })
    record["_unit_sequence"] = sequence
    return True, ""

  def get_stock_units(self, date_str, index):
    """Return a stored, stock-count-matched list of per-unit records."""
    data = self._load_data(date_str)
    if not 0 <= index < len(data["records"]):
      return False, "The selected inventory item no longer exists."
    record = data["records"][index]
    try:
      stock = Decimal(str(self.get_remaining_stock(record)).strip().replace(",", ""))
    except (InvalidOperation, AttributeError, TypeError):
      return False, "Current Stock must be numeric before unit details can be opened."
    if not stock.is_finite() or stock < 0:
      return False, "Current Stock must be a non-negative number."
    if stock != stock.to_integral_value():
      return False, "Unit-level details require whole-number Current Stock."
    units = record.get("_units")
    changed = units is None
    if units is None:
      units = []
      record["_units"] = units
    if not isinstance(units, list) or any(not isinstance(unit, dict) for unit in units):
      return False, "Unit details are invalid; repair the unit list before continuing."
    in_stock = sum(
        1 for unit in units if str(unit.get("Status", "In Stock")).casefold() == "in stock"
    )
    if in_stock > int(stock):
      return False, (
          f"Unit details contain {in_stock} in-stock units, but Current Stock is "
          f"{int(stock)}. Reconcile the stock count before continuing."
      )
    if in_stock < int(stock):
      success, message = self._append_stock_units(
          record, int(stock) - in_stock, date_str
      )
      if not success:
        return False, message
      changed = True
    normalized = []
    migrated_ids = False
    for unit in record["_units"]:
      unit_id = str(unit.get("Unit ID", "") or "")
      compact_id = self._compact_legacy_unit_id(record, unit_id)
      if compact_id:
        unit_id = compact_id
        migrated_ids = True
      normalized.append({
          field: (
              unit_id
              if field == "Unit ID"
              else str(unit.get(field, "") or "")
          )
          for field in STOCK_UNIT_FIELDS
      })
    record["_units"] = normalized
    if normalized != units or migrated_ids:
      changed = True
    if "_unit_sequence" not in record:
      record["_unit_sequence"] = max(
          int(record.get("_unit_sequence", 0) or 0),
          len(normalized),
      )
      changed = True
    if changed:
      self._save_data(data, date_str)
    return True, normalized

  def save_stock_units(self, date_str, index, units):
    data = self._load_data(date_str)
    if not 0 <= index < len(data["records"]):
      return False, "The selected inventory item no longer exists."
    record = data["records"][index]
    try:
      stock = Decimal(str(self.get_remaining_stock(record)).strip().replace(",", ""))
    except (InvalidOperation, AttributeError, TypeError):
      return False, "Current Stock must be numeric before unit details can be saved."
    if stock != stock.to_integral_value():
      return False, "Unit-level details require whole-number Current Stock."
    normalized = []
    seen_ids = set()
    for unit in units:
      item = {field: str(unit.get(field, "") or "").strip() for field in STOCK_UNIT_FIELDS}
      unit_id = item["Unit ID"]
      if not unit_id:
        return False, "Every unit must have a Unit ID."
      if unit_id.casefold() in seen_ids:
        return False, f"Unit ID {unit_id!r} is duplicated."
      seen_ids.add(unit_id.casefold())
      if item["Status"] not in ("In Stock", "Issued"):
        return False, f"Unit {unit_id!r} must be In Stock or Issued."
      if not item["Received Date"]:
        return False, f"Enter the received date for unit {unit_id!r}."
      for date_field in ("Received Date", "Issue Date"):
        if item[date_field] and parse_inventory_date(item[date_field]) is None:
          return False, f"{date_field} for unit {unit_id!r} must be a valid date."
      if item["Status"] == "Issued" and not item["Issued To"]:
        return False, f"Enter who unit {unit_id!r} was issued to."
      if item["Status"] == "Issued" and not item["Issue Date"]:
        return False, f"Enter the issue date for unit {unit_id!r}."
      normalized.append(item)
    in_stock = sum(1 for unit in normalized if unit["Status"] == "In Stock")
    if in_stock != int(stock):
      return False, (
          f"Exactly {int(stock)} units must have status In Stock to match "
          "Current Stock."
      )
    existing_units = record.get("_units", [])
    if normalized == existing_units:
      return True, "No unit details changed."
    record["_units"] = normalized
    record["_unit_sequence"] = max(
        int(record.get("_unit_sequence", 0) or 0),
        len(normalized),
    )
    self._save_data(data, date_str)
    return True, "Unit details saved."

  def record_usage(self, date_str, index, quantity_used, recipient, unit_ids=None):
    data = self._load_data(date_str)
    if not 0 <= index < len(data["records"]):
      return False, "The selected inventory item no longer exists."

    self._migrate_legacy_sales(data)
    record = data["records"][index]

    recipient = recipient.strip()
    if not recipient:
      return False, "Enter the recipient."

    try:
      used = Decimal(quantity_used.strip().replace(",", ""))
    except (InvalidOperation, AttributeError):
      return False, "Enter the quantity used as a number."

    stock_key = next(
        (
            key
            for key in record
            if key.casefold() in ("current stock", "stock")
        ),
        None,
    )
    if stock_key is None:
      return False, "This inventory item has no 'Current Stock' value."

    remaining_value = self.get_remaining_stock(record)

    try:
      stock = Decimal(str(remaining_value).strip().replace(",", ""))
    except (InvalidOperation, AttributeError, TypeError):
      return False, f"The available stock value is not numeric: {remaining_value!r}."

    if not used.is_finite() or used <= 0:
      return False, "Quantity used must be a positive number."
    if not stock.is_finite() or stock < 0:
      return False, "Current Stock must be a non-negative number."
    if used > stock:
      return False, f"Cannot use {used}; only {stock} remain in stock."

    units = record.get("_units")
    if units is not None and unit_ids is None:
      return False, "Select the unit IDs being issued before recording usage."
    if unit_ids is not None:
      if used != used.to_integral_value() or len(unit_ids) != int(used):
        return False, "Select exactly one unit ID for each whole unit used."
      if len(set(unit_ids)) != len(unit_ids):
        return False, "A unit ID can only be selected once."
      by_id = {
          str(unit.get("Unit ID", "")).casefold(): unit
          for unit in units or []
          if isinstance(unit, dict)
      }
      selected = []
      for unit_id in unit_ids:
        unit = by_id.get(str(unit_id).casefold())
        if unit is None or unit.get("Status", "In Stock") != "In Stock":
          return False, f"Unit {unit_id!r} is no longer available."
        selected.append(unit)
      usage_date = date_str or datetime.now().strftime("%Y-%m-%d")
      issue_time = datetime.now().strftime("%H:%M:%S")
      for unit in selected:
        unit["Status"] = "Issued"
        unit["Issued To"] = recipient
        unit["Issue Date"] = usage_date
        unit["Issue Time"] = issue_time
        unit["Issue Location"] = unit.get("Issue Location", "")

    remaining = stock - used

    def json_number(value):
      return int(value) if value == value.to_integral_value() else float(value)

    existing_usecases = self._get_usecase_values(record)
    usecase_number = max(existing_usecases, default=0) + 1
    usage_date = date_str or datetime.now().strftime("%Y-%m-%d")
    record["_remaining_stock"] = (
        int(remaining)
        if remaining == remaining.to_integral_value()
        else float(remaining)
    )
    record[stock_key] = (
        int(remaining)
        if remaining == remaining.to_integral_value()
        else float(remaining)
    )
    record["Last Issue Date"] = usage_date
    synced, message = self._sync_derived_inventory_fields(
        record, ["Current Stock"]
    )
    if not synced:
      return False, message
    event_time = datetime.now().strftime("%H:%M:%S")
    existing_usecases[usecase_number] = {
        "customer": recipient,
        "sold": json_number(used),
        "date": usage_date,
        "time": event_time,
        "remaining": json_number(remaining),
    }
    self._write_usecase_history(record, existing_usecases)
    if "Usecase" not in data["headers"]:
      data["headers"].append("Usecase")
      batch = next(
          (
              item
              for item in data.get("import_batches", [])
              if item.get("id") == record.get("_import_batch_id")
          ),
          None,
      )
      if batch is not None:
        batch.setdefault("added_headers", []).append("Usecase")

    self._save_data(data, date_str)
    return True, f"Usecase {usecase_number} usage recorded. {remaining} remaining."

  def record_stock_in(self, date_str, index, quantity_added):
    """Add received quantity to current stock and retain a timestamped receipt."""
    data = self._load_data(date_str)
    if not 0 <= index < len(data["records"]):
      return False, "The selected inventory item no longer exists."

    record = data["records"][index]
    stock_key = next(
        (
            key
            for key in record
            if key.casefold() in ("current stock", "stock")
        ),
        None,
    )
    if stock_key is None:
      return False, "This inventory item has no 'Current Stock' value."
    try:
      quantity = Decimal(str(quantity_added).strip().replace(",", ""))
      stock = Decimal(
          str(record.get(stock_key) or 0).strip().replace(",", "")
      )
    except (InvalidOperation, AttributeError):
      return False, "Stock and added quantity must be numeric."
    if not quantity.is_finite() or quantity <= 0:
      return False, "Quantity added must be a positive number."
    if not stock.is_finite() or stock < 0:
      return False, "Current Stock must be a non-negative number."
    if (
        "_units" not in record
        and stock == stock.to_integral_value()
        and quantity == quantity.to_integral_value()
    ):
      record["_units"] = []
      success, message = self._append_stock_units(
          record,
          stock,
          record.get("Last Receipt Date") or date_str,
      )
      if not success:
        return False, message
    if "_units" in record:
      if quantity != quantity.to_integral_value():
        return False, "Unit-level stock tracking only supports whole-number receipts."
      unit_success, unit_message = self._append_stock_units(
          record, quantity, date_str
      )
      if not unit_success:
        return False, unit_message

    total = stock + quantity
    total_value = (
        int(total)
        if total == total.to_integral_value()
        else float(total)
    )
    record[stock_key] = total_value
    record["_remaining_stock"] = total_value
    self._append_stock_in_entry(record, quantity, date_str)
    record["Last Receipt Date"] = date_str or datetime.now().strftime(
        "%Y-%m-%d"
    )
    synced, message = self._sync_derived_inventory_fields(
        record, ["Current Stock"]
    )
    if not synced:
      return False, message
    if "Stock In" not in data["headers"]:
      data["headers"].append("Stock In")
    self._save_data(data, date_str)
    return True, f"Stock in recorded: {quantity} added."

  def import_excel(self, filepath, date_str=None, mode="merge"):
    if mode not in ("merge", "replace"):
      return False, "Import mode must be 'merge' or 'replace'."
    extension = os.path.splitext(filepath)[1].lower()
    if extension not in (".xlsx", ".xlsm"):
      return False, "Choose an .xlsx or .xlsm file. Legacy .xls files are not supported."

    workbook = None
    try:
      workbook = load_workbook(filepath, read_only=True, data_only=True)
      worksheet = workbook.active
      rows = worksheet.iter_rows(values_only=True)
      raw_headers = next(rows, None)
      if raw_headers is None:
        return False, "The selected worksheet is empty."

      data = self._load_data(date_str)
      headers = data["headers"]

      accepted_headers = {
          header.casefold(): header for header in INVENTORY_HEADERS
      }
      columns = []
      matched_headers = set()
      for index, value in enumerate(raw_headers):
        if value is None:
          continue
        source_header = str(value).strip().casefold()
        canonical_header = accepted_headers.get(source_header)
        if canonical_header is None or canonical_header in matched_headers:
          continue
        matched_headers.add(canonical_header)
        columns.append((index, canonical_header))

      if not columns:
        return (
            False,
            "No supported inventory columns found. "
            "At least one column must match the inventory template.",
        )

      date_value = date_str or datetime.now().strftime("%Y-%m-%d")
      try:
        default_date = datetime.strptime(date_value, "%Y-%m-%d").strftime(
            "%a, %d %b %Y"
        )
      except ValueError:
        default_date = datetime.now().strftime("%a, %d %b %Y")

      batch_id = uuid.uuid4().hex
      imported_records = []
      for row_number, row in enumerate(rows, start=2):
        if not any(
            index < len(row) and row[index] is not None and str(row[index]).strip()
            for index, _ in columns
        ):
          continue

        record = {header: "" for header in headers}
        now = datetime.now()
        record["Date & Day"] = default_date
        record["Time"] = now.strftime("%H:%M:%S")
        for index, header in columns:
          value = row[index] if index < len(row) else None
          if value is None or (isinstance(value, str) and not value.strip()):
            if header in self.protected_headers:
              continue
            value = ""
          if (
              value not in (None, "")
              and header.casefold() in INVENTORY_DATE_FIELDS
          ):
            parsed_date = parse_inventory_date(value)
            if parsed_date is None:
              return (
                  False,
                  f"Invalid date in Excel row {row_number}, column "
                  f"'{header}': {value!r}. Use a recognizable calendar date.",
              )
            value = parsed_date.strftime("%Y-%m-%d")
          if isinstance(value, datetime):
            value = value.isoformat(sep=" ")
          elif hasattr(value, "isoformat"):
            value = value.isoformat()
          record[header] = value
        current_stock_key = next(
            (key for key in record if key.casefold() == "current stock"),
            None,
        )
        if current_stock_key and record.get(current_stock_key) not in (None, ""):
          try:
            imported_stock = Decimal(
                str(record[current_stock_key]).strip().replace(",", "")
            )
          except (InvalidOperation, AttributeError):
            imported_stock = Decimal(0)
          if imported_stock.is_finite() and imported_stock > 0:
            self._append_stock_in_entry(
                record, imported_stock, date_value
            )
            if record.get("Last Receipt Date") in (None, ""):
              record["Last Receipt Date"] = date_value
        record["_import_batch_id"] = batch_id
        imported_records.append(record)

      if not imported_records:
        return False, "No data rows found in the selected worksheet."

      if mode == "replace":
        data["records"] = imported_records
        data["import_batches"] = []
      else:
        data["records"].extend(imported_records)
      for serial_number, record in enumerate(data["records"], start=1):
        record["Sr No"] = serial_number
      data = self._ensure_inventory_schema(data)
      data.setdefault("import_batches", []).append(
          {
              "id": batch_id,
              "source": os.path.basename(filepath),
              "added_headers": [],
          }
      )
      self._save_data(data, date_str)
      try:
        self._clear_undo_history(date_str)
      except OSError as error:
        return (
            False,
            f"Import was saved, but its undo boundary could not be written: {error}",
        )
      action = "Merged" if mode == "merge" else "Replaced inventory with"
      return (
          True,
          f"{action} {len(imported_records)} rows from '{worksheet.title}'.",
      )
    except (OSError, ValueError, InvalidFileException, BadZipFile, ParseError) as error:
      return False, f"Unable to read Excel file: {error}"
    finally:
      if workbook is not None:
        workbook.close()

  def export_excel(self, date_str=None, design="Simple", end_date=None):
    if not date_str:
      date_str = datetime.now().strftime("%Y-%m-%d")
    range_export = end_date is not None
    if range_export:
      visible_records = self.get_live_records_between(date_str, end_date)
      headers = self.get_live_headers_between(date_str, end_date)
      start_value = parse_inventory_date(date_str)
      end_value = parse_inventory_date(end_date)
      if start_value is None or end_value is None or start_value > end_value:
        return False, "Choose a valid start date on or before the end date."
      report_label = (
          f"{start_value.strftime('%Y-%m-%d')}_to_"
          f"{end_value.strftime('%Y-%m-%d')}"
      )
    else:
      visible_records = self.get_live_records(date_str)
      headers = self.get_live_headers(date_str)
      parsed_date = parse_inventory_date(date_str)
      report_label = (
          parsed_date.strftime("%Y-%m-%d")
          if parsed_date is not None
          else datetime.now().strftime("%Y-%m-%d")
      )
    records = [record for _, _, record in visible_records]
    if not records:
      return False, f"No records found for {report_label}."

    export_path = os.path.join(
        self.export_dir, f"Inventory_{report_label}.xlsx"
    )
    if range_export:
      headers = ["Record Date"] + headers

    wb = Workbook()
    ws = wb.active
    ws.title = "Inventory Log"[:31]

    ws.append(headers)
    for (record_date, _, r) in visible_records:
      row = [
          record_date if h == "Record Date" else r.get(h, "")
          for h in headers
      ]
      ws.append(row)

    designs = {
        "Simple": {
            "header_fill": None,
            "header_font": Font(bold=True),
            "body_font": Font(),
            "alternate_fill": None,
            "border_color": None,
            "row_height": 22,
        },
        "Classic Blue": {
            "header_fill": "1F4E78",
            "header_font": Font(bold=True, color="FFFFFF"),
            "body_font": Font(color="1F2328"),
            "alternate_fill": "EAF1F8",
            "border_color": "C7D5E2",
            "row_height": 26,
        },
        "Inventory Green": {
            "header_fill": "2F6B57",
            "header_font": Font(bold=True, color="FFFFFF"),
            "body_font": Font(color="24352F"),
            "alternate_fill": "EAF3EE",
            "border_color": "C7D8CE",
            "row_height": 26,
        },
        "Compact Gray": {
            "header_fill": "D9E0E5",
            "header_font": Font(bold=True, color="263746"),
            "body_font": Font(color="263746", size=9),
            "alternate_fill": "F1F3F5",
            "border_color": "D8DEE4",
            "row_height": 20,
        },
    }
    selected_design = designs.get(design)
    if selected_design is None:
      return False, f"Unknown Excel design: {design}."

    border = (
        Border(
            bottom=Side(
                style="thin", color=selected_design["border_color"]
            )
        )
        if selected_design["border_color"]
        else Border()
    )
    for row in ws.iter_rows():
      for cell in row:
        cell.font = (
            selected_design["header_font"]
            if cell.row == 1
            else selected_design["body_font"]
        )
        cell.border = border
        if cell.row == 1 and selected_design["header_fill"]:
          cell.fill = PatternFill(
              fill_type="solid", fgColor=selected_design["header_fill"]
          )
        elif (
            cell.row > 1
            and selected_design["alternate_fill"]
            and cell.row % 2 == 0
        ):
          cell.fill = PatternFill(
              fill_type="solid",
              fgColor=selected_design["alternate_fill"],
          )
        cell.alignment = Alignment(
            horizontal="center",
            vertical="center",
            wrap_text=True,
        )
      ws.row_dimensions[row[0].row].height = selected_design["row_height"]

    for column_index, header in enumerate(headers, start=1):
      values = [
          ws.cell(row=row_index, column=column_index).value
          for row_index in range(1, ws.max_row + 1)
      ]
      content_width = max(
          (len(str(value)) for value in values if value is not None),
          default=len(str(header)),
      )
      ws.column_dimensions[
          ws.cell(row=1, column=column_index).column_letter
      ].width = min(max(content_width + 2, len(str(header)) + 2), 40)

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    wb.save(export_path)
    return True, f"Exported using {design} design to {export_path}"

# --- EDIT DIALOG MODAL ---
class InventoryCalendarDialog(ctk.CTkToplevel):

  def __init__(self, parent, initial_value, on_select, on_close=None):
    super().__init__(parent.winfo_toplevel())
    self.anchor_widget = parent
    self.title("Select date")
    self.resizable(False, False)
    self.configure(fg_color="#FFFFFF")
    self.on_select = on_select
    self.on_close = on_close
    self.protocol("WM_DELETE_WINDOW", self.close)
    initial_date = parse_inventory_date(initial_value) or datetime.now().date()
    self.year = initial_date.year
    self.month = initial_date.month
    self.grab_set()
    self.transient(parent.winfo_toplevel())
    self.content = ctk.CTkFrame(self, fg_color="transparent")
    self.content.pack(fill="both", expand=True, padx=12, pady=12)
    self.render_month()

  def render_month(self):
    for child in self.content.winfo_children():
      child.destroy()
    navigation = ctk.CTkFrame(self.content, fg_color="transparent")
    navigation.pack(fill="x", pady=(0, 8))
    ctk.CTkButton(
        navigation,
        text="<",
        width=34,
        command=self.previous_month,
    ).pack(side="left", padx=(0, 8))
    ctk.CTkLabel(
        navigation,
        text=f"{calendar.month_name[self.month]} {self.year}",
        font=("Inter", 13, "bold"),
    ).pack(side="left", expand=True)
    ctk.CTkButton(
        navigation,
        text=">",
        width=34,
        command=self.next_month,
    ).pack(side="right")

    week_frame = ctk.CTkFrame(self.content, fg_color="transparent")
    week_frame.pack()
    for weekday, name in enumerate(("Mo", "Tu", "We", "Th", "Fr", "Sa", "Su")):
      ctk.CTkLabel(
          week_frame,
          text=name,
          width=36,
          font=("Inter", 10, "bold"),
      ).grid(row=0, column=weekday, padx=1, pady=2)
    for row_number, week in enumerate(
        calendar.monthcalendar(self.year, self.month), start=1
    ):
      for weekday, day in enumerate(week):
        if day == 0:
          continue
        ctk.CTkButton(
            week_frame,
            text=str(day),
            width=36,
            height=32,
            fg_color="#0969DA" if (
                self.year == datetime.now().year
                and self.month == datetime.now().month
                and day == datetime.now().day
            ) else "#F6F8FA",
            hover_color="#D0D7DE",
            text_color="#1F2328",
            command=lambda selected_day=day: self.select_day(selected_day),
        ).grid(row=row_number, column=weekday, padx=1, pady=1)
    ctk.CTkButton(
        self.content,
        text="Today",
        height=30,
        command=lambda: self.select_day(
            datetime.now().day,
            datetime.now().year,
            datetime.now().month,
        ),
    ).pack(fill="x", pady=(8, 0))
    self.update_idletasks()
    popup_width = self.winfo_width()
    popup_height = self.winfo_height()
    anchor = self.anchor_widget
    x = anchor.winfo_rootx()
    y = anchor.winfo_rooty() + anchor.winfo_height()
    screen_width = anchor.winfo_screenwidth()
    screen_height = anchor.winfo_screenheight()
    if y + popup_height > screen_height:
      y = anchor.winfo_rooty() - popup_height
    x = max(0, min(x, screen_width - popup_width))
    y = max(0, min(y, screen_height - popup_height))
    self.geometry(f"+{x}+{y}")

  def previous_month(self):
    if self.month == 1:
      self.month = 12
      self.year -= 1
    else:
      self.month -= 1
    self.render_month()

  def next_month(self):
    if self.month == 12:
      self.month = 1
      self.year += 1
    else:
      self.month += 1
    self.render_month()

  def select_day(self, day, year=None, month=None):
    selected = datetime(
        year or self.year,
        month or self.month,
        day,
    ).strftime("%Y-%m-%d")
    self.on_select(selected)
    if self.on_close:
      self.on_close()
    self.destroy()

  def close(self):
    if self.on_close:
      self.on_close()
    self.destroy()


def parse_inventory_date(value):
  if not value:
    return None
  if isinstance(value, datetime):
    return value.date()
  text = str(value).strip()
  try:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
  except ValueError:
    pass
  date_formats = (
      "%Y-%m-%d",
      "%Y/%m/%d",
      "%Y.%m.%d",
      "%d-%m-%Y",
      "%m-%d-%Y",
      "%d/%m/%Y",
      "%m/%d/%Y",
      "%d.%m.%Y",
      "%d-%b-%Y",
      "%d-%B-%Y",
      "%Y-%b-%d",
      "%Y-%B-%d",
      "%d %b %Y",
      "%d %B %Y",
      "%Y %b %d",
      "%Y %B %d",
      "%b %d, %Y",
      "%B %d, %Y",
      "%b %d %Y",
      "%B %d %Y",
  )
  for date_format in date_formats:
    try:
      return datetime.strptime(text, date_format).date()
    except ValueError:
      continue
  return None


class InventoryFieldInput(ctk.CTkFrame):

  def __init__(
      self,
      parent,
      header,
      value="",
      choices=None,
      width=None,
      height=34,
      placeholder_text="",
      numeric=None,
  ):
    super().__init__(
        parent,
        fg_color="transparent",
        width=width or 200,
        height=height,
    )
    self.header = header
    normalized = header.casefold()
    self.numeric = (
        normalized in NUMERIC_INVENTORY_FIELDS
        if numeric is None
        else numeric
    )
    self.date_field = (
        normalized in INVENTORY_DATE_FIELDS
        or "date" in normalized
        or "expiry" in normalized
    )
    self.input_widget = None
    self.calendar_open = False
    self.calendar_dialog = None
    self.calendar_button = None
    self.on_change = None
    self.uom_autocomplete = normalized == "uom"
    self.uom_suggestion_window = None
    self.uom_suggestion_frame = None
    self.uom_suggestions = []
    self.uom_selection_index = 0
    self._step = Decimal("0.01") if normalized == "unit cost" else Decimal(1)

    if self.numeric:
      self.input_widget = ctk.CTkEntry(
          self,
          height=height,
          width=width or 140,
          placeholder_text=placeholder_text,
          justify="center",
      )
      self.input_widget.pack(side="left", fill="both", expand=True)
      arrows = ctk.CTkFrame(self, fg_color="transparent")
      arrows.pack(side="right", fill="y", padx=(2, 0))
      ctk.CTkButton(
          arrows,
          text="▲",
          width=25,
          height=max(14, height // 2),
          corner_radius=3,
          command=lambda: self.adjust(1),
      ).pack(fill="both", expand=True, pady=(0, 1))
      ctk.CTkButton(
          arrows,
          text="▼",
          width=25,
          height=max(14, height // 2),
          corner_radius=3,
          command=lambda: self.adjust(-1),
      ).pack(fill="both", expand=True, pady=(1, 0))
    elif self.uom_autocomplete:
      self.input_widget = ctk.CTkEntry(
          self,
          height=height,
          width=width or 140,
          placeholder_text=placeholder_text,
          justify="center",
      )
      self.input_widget.pack(side="left", fill="both", expand=True)
      ctk.CTkButton(
          self,
          text="▾",
          width=28,
          height=height,
          fg_color="#F8FAFC",
          hover_color="#EAF1F7",
          border_width=1,
          border_color="#D0D7DE",
          text_color="#29465D",
          command=self.show_uom_suggestions,
      ).pack(side="right", padx=(3, 0))
      self.input_widget.bind("<KeyRelease>", self.filter_uom_options)
      self.input_widget.bind("<KeyPress-Escape>", self.hide_uom_suggestions)
    elif not self.date_field:
      self.input_widget = ctk.CTkComboBox(
          self,
          values=choices or [],
          height=height,
          width=width or 140,
          state="normal",
          justify="center",
      )
      self.input_widget.pack(fill="x", expand=True)
    else:
      self.input_widget = ctk.CTkEntry(
          self,
          height=height,
          width=width or 140,
          placeholder_text=placeholder_text,
          justify="center",
      )
      self.input_widget.pack(side="left", fill="both", expand=True)
      if self.date_field:
        self.calendar_button = ctk.CTkButton(
            self,
            text="Date",
            width=36,
            height=height,
            command=self.open_calendar,
        )
        self.calendar_button.pack(side="right", padx=(3, 0))
    self.set_value(value)

  def filter_uom_options(self, event=None):
    if not getattr(self, "uom_autocomplete", False):
      return
    if event and event.keysym in {
        "Return", "Tab", "ISO_Left_Tab", "Escape", "Up", "Down",
        "Left", "Right", "Shift_L", "Shift_R", "Control_L", "Control_R",
    }:
      return

    typed_value = self.input_widget.get().strip().casefold()
    if not typed_value:
      self.hide_uom_suggestions()
      return
    matches = get_uom_recommendations(typed_value)
    if matches:
      self.show_uom_suggestions(matches)
    else:
      self.hide_uom_suggestions()

  def show_uom_suggestions(self, options=None):
    if not getattr(self, "uom_autocomplete", False):
      return
    typed_value = self.input_widget.get().strip().casefold()
    suggestions = (
        list(options)
        if options is not None
        else get_uom_recommendations(typed_value)
        if typed_value
        else UOM_OPTIONS
    )
    if not suggestions:
      self.hide_uom_suggestions()
      return
    self.create_uom_suggestion_window()
    previous_selection = (
        self.uom_suggestions[self.uom_selection_index]
        if self.uom_suggestions
        and self.uom_selection_index < len(self.uom_suggestions)
        else None
    )
    self.uom_suggestions = suggestions
    if previous_selection in suggestions:
      self.uom_selection_index = suggestions.index(previous_selection)
    else:
      typed_value = self.input_widget.get().strip().casefold()
      self.uom_selection_index = next(
          (
              index
              for index, unit in enumerate(suggestions)
              if unit.casefold() == typed_value
          ),
          0,
      )
    for child in self.uom_suggestion_frame.winfo_children():
      child.destroy()
    for index, unit in enumerate(suggestions):
      ctk.CTkButton(
          self.uom_suggestion_frame,
          text=unit,
          height=28,
          corner_radius=4,
          fg_color=(
              "#DCEBFA" if index == self.uom_selection_index else "transparent"
          ),
          hover_color="#EAF1F7",
          text_color="#1F2328",
          anchor="center",
          command=lambda selected=unit: self.select_uom_suggestion(selected),
      ).pack(fill="x", padx=3, pady=1)

    self.update_idletasks()
    self.uom_suggestion_window.update_idletasks()
    visible_rows = min(len(suggestions), 7)
    popup_height = visible_rows * 30 + 8
    popup_width = max(self.winfo_width(), 140)
    popup_x = self.winfo_rootx()
    popup_y = self.winfo_rooty() + self.winfo_height()
    screen_width = self.winfo_screenwidth()
    popup_x = min(popup_x, max(0, screen_width - popup_width))
    self.uom_suggestion_window.geometry(
        f"{popup_width}x{popup_height}+{popup_x}+{popup_y}"
    )
    self.uom_suggestion_window.deiconify()
    self.uom_suggestion_window.lift()
    self.input_widget.focus_set()

  def create_uom_suggestion_window(self):
    if self.uom_suggestion_window is not None:
      return
    self.uom_suggestion_window = ctk.CTkToplevel(self.winfo_toplevel())
    self.uom_suggestion_window.withdraw()
    self.uom_suggestion_window.overrideredirect(True)
    self.uom_suggestion_window.attributes("-topmost", True)
    self.uom_suggestion_frame = ctk.CTkScrollableFrame(
        self.uom_suggestion_window,
        width=200,
        height=180,
        fg_color="#FFFFFF",
        border_width=1,
        border_color="#D0D7DE",
        corner_radius=4,
    )
    self.uom_suggestion_frame.pack(fill="both", expand=True)

  def select_uom_suggestion(self, unit):
    self.set_value(unit)
    self.hide_uom_suggestions()
    self.input_widget.focus_set()

  def hide_uom_suggestions(self, _event=None):
    if self.uom_suggestion_window is not None:
      self.uom_suggestion_window.withdraw()

  @property
  def dropdown_is_open(self):
    if self.uom_autocomplete:
      return self.uom_suggestions_open
    if isinstance(self.input_widget, ctk.CTkComboBox):
      return bool(
          self.input_widget._close_on_next_click
          or self.input_widget._dropdown_menu.winfo_ismapped()
      )
    return False

  def move_dropdown_selection(self, direction):
    if not self.dropdown_is_open:
      return False
    step = -1 if direction == "up" else 1
    if self.uom_autocomplete:
      self.uom_selection_index = min(
          max(self.uom_selection_index + step, 0),
          len(self.uom_suggestions) - 1,
      )
      selected_unit = self.uom_suggestions[self.uom_selection_index]
      self.input_widget.configure(
          fg_color="#FFFFFF",
          border_color="#0969DA",
      )
      for index, button in enumerate(
          self.uom_suggestion_frame.winfo_children()
      ):
        button.configure(
            fg_color=(
                "#DCEBFA" if index == self.uom_selection_index else "transparent"
            )
        )
      self.set_value(selected_unit)
      self.input_widget.after_idle(
          lambda: self.input_widget.focus_set()
      )
      self.uom_suggestion_frame._parent_canvas.yview_moveto(
          self.uom_selection_index / max(len(self.uom_suggestions), 1)
      )
      self.input_widget._uom_preview_value = selected_unit
      return True

    values = list(self.input_widget.cget("values"))
    if not values:
      return False
    current = self.input_widget.get()
    try:
      current_index = values.index(current)
    except ValueError:
      current_index = -1 if step > 0 else len(values)
    next_index = min(max(current_index + step, 0), len(values) - 1)
    self.input_widget.set(values[next_index])
    self.input_widget._dropdown_menu.activate(next_index)
    self.input_widget.focus_set()
    return True

  def accept_dropdown_selection(self):
    if self.uom_autocomplete and self.uom_suggestions_open:
      if self.uom_suggestions:
        self.select_uom_suggestion(
            self.uom_suggestions[self.uom_selection_index]
        )
      return True
    if isinstance(self.input_widget, ctk.CTkComboBox) and self.dropdown_is_open:
      self.input_widget._dropdown_menu.unpost()
      self.input_widget._close_on_next_click = False
      return True
    return False

  @property
  def uom_suggestions_open(self):
    return (
        self.uom_suggestion_window is not None
        and self.uom_suggestion_window.state() != "withdrawn"
    )

  def destroy(self):
    if self.uom_suggestion_window is not None:
      self.uom_suggestion_window.destroy()
      self.uom_suggestion_window = None
    super().destroy()

  def set_value(self, value):
    if isinstance(self.input_widget, ctk.CTkComboBox):
      self.input_widget.set("" if value is None else str(value))
      return
    self.input_widget.delete(0, "end")
    if value not in (None, ""):
      self.input_widget.insert(0, str(value))

  def get(self):
    return self.input_widget.get()

  def insert(self, index, value):
    if isinstance(self.input_widget, ctk.CTkComboBox):
      self.input_widget.set(str(value))
      return
    self.input_widget.insert(index, value)

  def delete(self, first, last=None):
    if isinstance(self.input_widget, ctk.CTkComboBox):
      self.input_widget.set("")
      return
    self.input_widget.delete(first, last)

  def select_range(self, start, end):
    if hasattr(self.input_widget, "select_range"):
      self.input_widget.select_range(start, end)

  def focus_set(self):
    self.input_widget.focus_set()

  def bind(self, sequence=None, func=None, add=None):
    if add is None:
      return self.input_widget.bind(sequence, func)
    return self.input_widget.bind(sequence, func, add)

  def adjust(self, direction):
    try:
      value = Decimal(self.get().strip().replace(",", "") or "0")
      if not value.is_finite():
        value = Decimal(0)
    except (InvalidOperation, AttributeError):
      value = Decimal(0)
    value = max(Decimal(0), value + self._step * direction)
    if value == value.to_integral_value():
      display_value = str(int(value))
    else:
      display_value = format(value.normalize(), "f")
    self.set_value(display_value)
    self.input_widget.focus_set()

  def open_calendar(self):
    self.calendar_open = True
    self.calendar_dialog = InventoryCalendarDialog(
        self.calendar_button or self,
        self.get(),
        self.select_date,
        lambda: setattr(self, "calendar_open", False),
    )

  def select_date(self, value):
    self.set_value(value)
    if self.on_change:
      self.on_change()


class RecordUsageDialog(ctk.CTkToplevel):

  def __init__(
      self,
      parent,
      item_name,
      current_stock,
      on_save_callback,
      available_units,
      recipients=None,
  ):
    super().__init__(parent)
    self.title("Record Usage")
    self.geometry("560x590")
    self.minsize(480, 420)
    self.configure(fg_color="#F6F8FA")
    self.grab_set()
    self.on_save_callback = on_save_callback
    self.unit_vars = {}

    ctk.CTkLabel(
        self,
        text="Record Component Usage",
        font=("Inter", 16, "bold"),
        text_color="#1F2328",
    ).pack(pady=(20, 4))
    ctk.CTkLabel(
        self,
        text=f"{item_name}\nCurrent stock: {current_stock} — select each unit being issued",
        font=("Inter", 12),
        text_color="#57606A",
        wraplength=500,
    ).pack(pady=(0, 10))

    form = ctk.CTkFrame(self, fg_color="#FFFFFF")
    form.pack(fill="both", expand=True, padx=20, pady=8)

    unit_heading = ctk.CTkFrame(form, fg_color="transparent")
    unit_heading.pack(fill="x", padx=12, pady=(10, 3))
    ctk.CTkLabel(
        unit_heading, text="Units to issue", anchor="w", text_color="#57606A"
    ).pack(side="left")
    self.selection_label = ctk.CTkLabel(
        unit_heading, text="0 selected", text_color="#57606A"
    )
    self.selection_label.pack(side="right")

    unit_list = ctk.CTkScrollableFrame(form, height=260, fg_color="#F6F8FA")
    unit_list.pack(fill="both", expand=True, padx=12, pady=(0, 8))
    if not available_units:
      ctk.CTkLabel(
          unit_list,
          text="No in-stock unit IDs are available.",
          text_color="#CF222E",
      ).pack(pady=20)
    for unit in available_units:
      unit_id = str(unit.get("Unit ID", ""))
      variable = ctk.BooleanVar(value=False)
      self.unit_vars[unit_id] = variable
      label = unit_id
      location = str(unit.get("Storage Location", "") or "")
      if location:
        label += f"  ·  {location}"
      if unit.get("Received Date"):
        label += f"  ·  received {unit['Received Date']}"
      ctk.CTkCheckBox(
          unit_list,
          text=label,
          variable=variable,
          command=self.update_selection_count,
          text_color="#1F2328",
      ).pack(fill="x", padx=6, pady=3)

    ctk.CTkLabel(
        form, text="Given to", anchor="w", text_color="#57606A"
    ).pack(fill="x", padx=12, pady=(4, 2))
    self.customer_entry = InventoryFieldInput(
        form,
        "Given to",
        choices=recipients or [],
        placeholder_text="Recipient name",
    )
    self.customer_entry.pack(fill="x", padx=12, pady=(0, 10))

    buttons = ctk.CTkFrame(self, fg_color="transparent")
    buttons.pack(fill="x", padx=20, pady=(8, 18))
    ctk.CTkButton(
        buttons,
        text="Cancel",
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        command=self.destroy,
    ).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ctk.CTkButton(
        buttons,
        text="Save Usage",
        fg_color="#1A7F37",
        hover_color="#2DA44E",
        text_color="#FFFFFF",
        command=self.save,
    ).pack(side="right", fill="x", expand=True, padx=(6, 0))

  def update_selection_count(self):
    selected_count = sum(variable.get() for variable in self.unit_vars.values())
    self.selection_label.configure(text=f"{selected_count} selected")

  def save(self):
    selected_unit_ids = [
        unit_id
        for unit_id, variable in self.unit_vars.items()
        if variable.get()
    ]
    if self.on_save_callback(
        selected_unit_ids, self.customer_entry.get()
    ):
      self.destroy()


class UnitDetailsDialog(ctk.CTkToplevel):

  def __init__(self, parent, item_name, units, on_save_callback):
    super().__init__(parent)
    self.parent_window = parent.winfo_toplevel()
    self.title(f"Unit Details — {item_name}")
    self.geometry("1120x560")
    self.minsize(760, 400)
    self.configure(fg_color="#F6F8FA")
    self.iconbitmap(get_asset_path("material_tracker.ico"))
    if hasattr(self.parent_window, "window_icon"):
      self.iconphoto(True, self.parent_window.window_icon)
    self.item_name = item_name
    self.units = [dict(unit) for unit in units]
    self.on_save_callback = on_save_callback
    self.editor = None
    self.active_edit = None
    self.columns = list(STOCK_UNIT_FIELDS)

    ctk.CTkLabel(
        self,
        text=f"Unit Details — {item_name}",
        font=("Inter", 16, "bold"),
        text_color="#1F2328",
    ).pack(anchor="w", padx=18, pady=(15, 8))

    table_frame = ctk.CTkFrame(self, fg_color="#FFFFFF")
    table_frame.pack(fill="both", expand=True, padx=18, pady=(0, 8))
    self.tree = ttk.Treeview(
        table_frame,
        columns=self.columns,
        show="headings",
        selectmode="browse",
    )
    vertical = ttk.Scrollbar(
        table_frame, orient="vertical", command=self.tree.yview
    )
    horizontal = ttk.Scrollbar(
        table_frame, orient="horizontal", command=self.tree.xview
    )
    self.tree.configure(
        yscrollcommand=vertical.set,
        xscrollcommand=horizontal.set,
    )
    self.tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    table_frame.grid_rowconfigure(0, weight=1)
    table_frame.grid_columnconfigure(0, weight=1)
    for column in self.columns:
      self.tree.heading(column, text=column)
      self.tree.column(column, width=150, minwidth=100, anchor="center")
    self.refresh_rows()
    self.tree.bind("<Double-1>", self.begin_edit)

    ctk.CTkLabel(
        self,
        text="Double-click a cell to edit it. In-stock unit count must match Current Stock.",
        text_color="#57606A",
        anchor="w",
    ).pack(fill="x", padx=18, pady=(0, 6))
    buttons = ctk.CTkFrame(self, fg_color="transparent")
    buttons.pack(fill="x", padx=18, pady=(0, 14))
    ctk.CTkButton(
        buttons,
        text="Export to Excel",
        fg_color="#34735E",
        hover_color="#285D4B",
        text_color="#FFFFFF",
        command=self.export_to_excel,
    ).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ctk.CTkButton(
        buttons,
        text="Cancel",
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        command=self.destroy,
    ).pack(side="left", fill="x", expand=True, padx=6)
    ctk.CTkButton(
        buttons,
        text="Save Unit Details",
        fg_color="#0969DA",
        hover_color="#054DA7",
        text_color="#FFFFFF",
        command=self.save,
    ).pack(side="right", fill="x", expand=True, padx=(6, 0))
    self.transient(self.parent_window)
    self.lift()
    self.focus_force()

  def export_to_excel(self):
    self.commit_edit()
    safe_item_name = re.sub(
        r"[^A-Za-z0-9._-]+", "_", self.item_name
    ).strip("._-") or "Item"
    filepath = filedialog.asksaveasfilename(
        parent=self,
        title="Export Unit Details",
        defaultextension=".xlsx",
        initialfile=(
            f"Unit_Details_{safe_item_name}_"
            f"{datetime.now().strftime('%Y-%m-%d')}.xlsx"
        ),
        filetypes=(("Excel Workbook", "*.xlsx"),),
    )
    if not filepath:
      return

    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Unit Details"
    worksheet.append(list(self.columns))
    for unit in self.units:
      worksheet.append([unit.get(column, "") for column in self.columns])
    for cell in worksheet[1]:
      cell.font = Font(bold=True, color="FFFFFF")
      cell.fill = PatternFill(fill_type="solid", fgColor="203B55")
      cell.alignment = Alignment(horizontal="center", vertical="center")
    for column_index, header in enumerate(self.columns, start=1):
      column_letter = worksheet.cell(
          row=1, column=column_index
      ).column_letter
      content_width = max(
          (len(str(worksheet.cell(row, column_index).value or ""))
           for row in range(1, worksheet.max_row + 1)),
          default=len(header),
      )
      worksheet.column_dimensions[column_letter].width = min(
          max(content_width + 2, len(header) + 2), 32
      )
    worksheet.freeze_panes = "A2"
    worksheet.auto_filter.ref = worksheet.dimensions
    try:
      workbook.save(filepath)
    except OSError as error:
      messagebox.showerror(
          "Export Failed",
          f"Could not save the Excel file:\n{error}",
          parent=self,
      )
      return
    messagebox.showinfo(
        "Export Complete",
        f"Exported {len(self.units)} unit records to:\n{filepath}",
        parent=self,
    )

  def refresh_rows(self):
    for row_id in self.tree.get_children():
      self.tree.delete(row_id)
    for index, unit in enumerate(self.units):
      self.tree.insert(
          "",
          "end",
          iid=str(index),
          values=[unit.get(column, "") for column in self.columns],
      )

  def begin_edit(self, event):
    row_id = self.tree.identify_row(event.y)
    column_id = self.tree.identify_column(event.x)
    if not row_id or not column_id:
      return
    column_index = int(column_id[1:]) - 1
    if not 0 <= column_index < len(self.columns):
      return
    self.commit_edit()
    bounds = self.tree.bbox(row_id, column_id)
    if not bounds:
      return
    x, y, width, height = bounds
    header = self.columns[column_index]
    values = self.tree.item(row_id, "values")
    value = str(values[column_index])
    widget_scale = ctk.ScalingTracker.get_widget_scaling(self.tree)
    choices = ("In Stock", "Issued") if header == "Status" else []
    editor = InventoryFieldInput(
        self.tree,
        header,
        value=value,
        choices=choices,
        width=round(width / widget_scale),
        height=round(height / widget_scale),
        numeric=False,
    )
    editor.place(x=round(x / widget_scale), y=round(y / widget_scale))
    self.editor = editor
    self.active_edit = (row_id, column_index)
    editor.input_widget.focus_set()
    editor.input_widget.bind("<Return>", self.commit_edit)
    editor.input_widget.bind("<Escape>", self.cancel_edit)

  def commit_edit(self, _event=None):
    if self.editor is None or self.active_edit is None:
      return "break"
    row_id, column_index = self.active_edit
    value = self.editor.get()
    self.units[int(row_id)][self.columns[column_index]] = value
    self.editor.destroy()
    self.editor = None
    self.active_edit = None
    self.refresh_rows()
    return "break"

  def cancel_edit(self, _event=None):
    if self.editor is not None:
      self.editor.destroy()
    self.editor = None
    self.active_edit = None
    return "break"

  def save(self):
    self.commit_edit()
    if self.on_save_callback(self.units):
      self.destroy()


class StockInDialog(ctk.CTkToplevel):

  def __init__(self, parent, on_save_callback):
    super().__init__(parent)
    self.title("Record Stock In")
    self.geometry("360x190")
    self.resizable(False, False)
    self.configure(fg_color="#F6F8FA")
    self.grab_set()
    self.on_save_callback = on_save_callback

    ctk.CTkLabel(
        self,
        text="Quantity received",
        font=("Inter", 14, "bold"),
        text_color="#1F2328",
    ).pack(anchor="w", padx=20, pady=(22, 6))
    self.quantity_entry = InventoryFieldInput(
        self, "Quantity received", numeric=True
    )
    self.quantity_entry.pack(fill="x", padx=20, pady=(0, 12))
    buttons = ctk.CTkFrame(self, fg_color="transparent")
    buttons.pack(fill="x", padx=20, pady=(4, 18))
    ctk.CTkButton(
        buttons,
        text="Cancel",
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        command=self.destroy,
    ).pack(side="left", fill="x", expand=True, padx=(0, 5))
    ctk.CTkButton(
        buttons,
        text="Save",
        fg_color="#FFFFFF",
        hover_color="#EAF1F7",
        border_width=1,
        border_color="#D0D7DE",
        text_color="#1F2328",
        command=self.save,
    ).pack(side="right", fill="x", expand=True, padx=(5, 0))

  def save(self):
    if self.on_save_callback(self.quantity_entry.get()):
      self.destroy()


class EditRecordDialog(ctk.CTkToplevel):

  def __init__(self, parent, headers, record_data, on_save_callback):
    super().__init__(parent)
    self.title("Edit Record")
    self.geometry("420x520")
    self.resizable(False, False)
    self.configure(fg_color="#F6F8FA")
    self.grab_set()

    self.on_save_callback = on_save_callback
    self.entries = {}

    ctk.CTkLabel(
        self,
        text="Edit Entry",
        font=("Inter", 16, "bold"),
        text_color="#1F2328",
    ).pack(pady=(20, 10))

    scroll = ctk.CTkScrollableFrame(
        self, fg_color="#FFFFFF", border_width=1, border_color="#D0D7DE"
    )
    scroll.pack(fill="both", expand=True, padx=20, pady=10)

    for col in headers:
      lbl = ctk.CTkLabel(
          scroll,
          text=col,
          anchor="w",
          font=("Inter", 11, "bold"),
          text_color="#57606A",
      )
      lbl.pack(fill="x", pady=(8, 2))

      entry = ctk.CTkEntry(
          scroll,
          fg_color="#F6F8FA",
          border_color="#D0D7DE",
          text_color="#1F2328",
          height=35,
          justify="center",
      )
      entry.insert(0, str(record_data.get(col, "")))
      entry.pack(fill="x", pady=(0, 6))
      self.entries[col] = entry

    btn_frame = ctk.CTkFrame(self, fg_color="transparent")
    btn_frame.pack(fill="x", padx=20, pady=20)

    ctk.CTkButton(
        btn_frame,
        text="Cancel",
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        height=36,
        command=self.destroy,
    ).pack(side="left", fill="x", expand=True, padx=(0, 6))

    ctk.CTkButton(
        btn_frame,
        text="Save Changes",
        fg_color="#1A7F37",
        hover_color="#2DA44E",
        text_color="#FFFFFF",
        height=36,
        command=self.save,
    ).pack(side="right", fill="x", expand=True, padx=(6, 0))

  def save(self):
    updated_data = {col: entry.get() for col, entry in self.entries.items()}
    self.on_save_callback(updated_data)
    self.destroy()


class ColumnVisibilityDialog(ctk.CTkToplevel):

  def __init__(self, parent, headers, selected_headers, on_save_callback):
    super().__init__(parent)
    self.title("Choose Live Columns")
    self.geometry("380x620")
    self.minsize(340, 420)
    self.configure(fg_color="#F6F8FA")
    self.grab_set()
    self.on_save_callback = on_save_callback
    self.variables = {}

    ctk.CTkLabel(
        self,
        text="Choose columns for the live table",
        font=("Inter", 16, "bold"),
        text_color="#1F2328",
    ).pack(anchor="w", padx=18, pady=(18, 8))

    scroll = ctk.CTkScrollableFrame(
        self, fg_color="#FFFFFF", border_width=1, border_color="#D0D7DE"
    )
    scroll.pack(fill="both", expand=True, padx=18, pady=8)
    for header in headers:
      if header.casefold() in ("date & day", "time"):
        continue
      variable = ctk.BooleanVar(value=header in selected_headers)
      self.variables[header] = variable
      ctk.CTkCheckBox(
          scroll,
          text=header,
          variable=variable,
          font=("Inter", 11),
          text_color="#1F2328",
          checkbox_width=18,
          checkbox_height=18,
      ).pack(anchor="w", padx=10, pady=5)

    presets = ctk.CTkFrame(self, fg_color="transparent")
    presets.pack(fill="x", padx=18, pady=(0, 4))
    ctk.CTkButton(
        presets,
        text="Show All",
        height=30,
        fg_color="#FFFFFF",
        hover_color="#EAF1F7",
        border_width=1,
        border_color="#D0D7DE",
        text_color="#1F2328",
        command=self.select_all,
    ).pack(side="left", fill="x", expand=True, padx=(0, 4))
    ctk.CTkButton(
        presets,
        text="Show Default",
        height=30,
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        command=self.select_default,
    ).pack(side="right", fill="x", expand=True, padx=(4, 0))

    actions = ctk.CTkFrame(self, fg_color="transparent")
    actions.pack(fill="x", padx=18, pady=(8, 16))
    ctk.CTkButton(
        actions,
        text="Cancel",
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        command=self.destroy,
    ).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ctk.CTkButton(
        actions,
        text="Apply",
        fg_color="#0969DA",
        hover_color="#054DA7",
        text_color="#FFFFFF",
        command=self.save,
    ).pack(side="right", fill="x", expand=True, padx=(6, 0))

  def save(self):
    selected = {
        header for header, variable in self.variables.items() if variable.get()
    }
    self.on_save_callback(selected)
    self.destroy()

  def select_all(self):
    for variable in self.variables.values():
      variable.set(True)

  def select_default(self):
    for header, variable in self.variables.items():
      variable.set(header in DEFAULT_VISIBLE_HEADERS)


class InventoryEntryDialog(ctk.CTkToplevel):

  def __init__(
      self,
      parent,
      headers,
      record_data,
      on_save_callback,
      column_values=None,
  ):
    super().__init__(parent)
    self.title("Add Inventory Item")
    self.geometry("820x700")
    self.minsize(680, 540)
    self.configure(fg_color="#F6F8FA")
    self.grab_set()
    self.entries = {}
    self.on_save_callback = on_save_callback
    self.column_values = column_values or {}

    ctk.CTkLabel(
        self,
        text="Add Inventory Item",
        font=("Inter", 18, "bold"),
        text_color="#1F2328",
    ).pack(anchor="w", padx=20, pady=(18, 2))
    ctk.CTkLabel(
        self,
        text="Fill in the fields you have; you can edit any value later.",
        font=("Inter", 11),
        text_color="#57606A",
    ).pack(anchor="w", padx=20, pady=(0, 10))

    scroll = ctk.CTkScrollableFrame(
        self, fg_color="#FFFFFF", border_width=1, border_color="#D0D7DE"
    )
    scroll.pack(fill="both", expand=True, padx=20, pady=8)
    scroll.grid_columnconfigure(0, weight=1)
    scroll.grid_columnconfigure(1, weight=1)
    hidden_fields = {"date & day", "time"}
    for index, header in enumerate(headers):
      if (
          header.casefold() in hidden_fields | {"stock in"}
          or header.startswith("_")
          or header.casefold() == "usecase"
          or re.fullmatch(r"usecase\s+\d+", header, re.IGNORECASE)
      ):
        continue
      row, column = divmod(len(self.entries), 2)
      field = ctk.CTkFrame(scroll, fg_color="transparent")
      field.grid(
          row=row,
          column=column,
          sticky="ew",
          padx=10,
          pady=(8, 4),
      )
      ctk.CTkLabel(
          field,
          text=header,
          anchor="w",
          font=("Inter", 11, "bold"),
          text_color="#57606A",
      ).pack(fill="x", pady=(0, 3))
      entry = InventoryFieldInput(
          field,
          header,
          value=record_data.get(header, ""),
          choices=self.column_values.get(header, []),
          height=34,
          numeric=is_numeric_column(
              header, self.column_values.get(header, [])
          ),
          placeholder_text=(
              "Auto-calculated"
              if header in ("Available Stock", "Inventory Value")
              else ""
          ),
      )
      entry.pack(fill="x")
      self.entries[header] = entry

    buttons = ctk.CTkFrame(self, fg_color="transparent")
    buttons.pack(fill="x", padx=20, pady=(8, 16))
    ctk.CTkButton(
        buttons,
        text="Cancel",
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        command=self.destroy,
    ).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ctk.CTkButton(
        buttons,
        text="Add Item",
        fg_color="#1A7F37",
        hover_color="#2DA44E",
        text_color="#FFFFFF",
        command=self.save,
    ).pack(side="right", fill="x", expand=True, padx=(6, 0))
    self.bind("<Control-Return>", lambda _event: self.save())
    self.bind("<Control-KP_Enter>", lambda _event: self.save())
    part_number_entry = self.entries.get("Part Number")
    if part_number_entry:
      part_number_entry.focus_set()

  def save(self):
    values = {header: entry.get().strip() for header, entry in self.entries.items()}
    if self.on_save_callback(values):
      self.destroy()


class ExcelDesignDialog(ctk.CTkToplevel):

  DESIGNS = (
      ("Simple", "Plain white cells, centered text, and sized columns."),
      ("Classic Blue", "Blue header, light banding, and clear table borders."),
      ("Inventory Green", "Green header and soft green alternating rows."),
      ("Compact Gray", "Compact gray styling for dense inventory sheets."),
  )

  def __init__(self, parent, on_export_callback):
    super().__init__(parent)
    self.title("Choose Excel Design")
    self.geometry("480x440")
    self.resizable(False, False)
    self.configure(fg_color="#F6F8FA")
    self.grab_set()
    self.on_export_callback = on_export_callback
    self.design_var = ctk.StringVar(value="Simple")

    ctk.CTkLabel(
        self,
        text="Choose an Excel design",
        font=("Inter", 18, "bold"),
        text_color="#1F2328",
    ).pack(anchor="w", padx=22, pady=(20, 4))
    ctk.CTkLabel(
        self,
        text="Your exported inventory data stays the same.",
        font=("Inter", 11),
        text_color="#57606A",
    ).pack(anchor="w", padx=22, pady=(0, 12))

    for name, description in self.DESIGNS:
      card = ctk.CTkFrame(
          self,
          fg_color="#FFFFFF",
          corner_radius=8,
          border_width=1,
          border_color="#D0D7DE",
      )
      card.pack(fill="x", padx=20, pady=4)
      radio = ctk.CTkRadioButton(
          card,
          text=name,
          variable=self.design_var,
          value=name,
          font=("Inter", 12, "bold"),
          text_color="#1F2328",
          radiobutton_width=18,
          radiobutton_height=18,
      )
      radio.pack(anchor="w", padx=12, pady=(8, 0))
      ctk.CTkLabel(
          card,
          text=description,
          font=("Inter", 10),
          text_color="#57606A",
          anchor="w",
      ).pack(fill="x", padx=40, pady=(0, 8))

    buttons = ctk.CTkFrame(self, fg_color="transparent")
    buttons.pack(fill="x", padx=20, pady=(12, 18))
    ctk.CTkButton(
        buttons,
        text="Cancel",
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        command=self.destroy,
    ).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ctk.CTkButton(
        buttons,
        text="Export XLSX",
        fg_color="#0969DA",
        hover_color="#054DA7",
        text_color="#FFFFFF",
        command=self.export,
    ).pack(side="right", fill="x", expand=True, padx=(6, 0))

  def export(self):
    if self.on_export_callback(self.design_var.get()):
      self.destroy()


class BackupRestoreDialog(ctk.CTkToplevel):

  def __init__(self, parent, date_str, backups, on_restore_callback):
    super().__init__(parent)
    self.title("Inventory Backups")
    self.geometry("620x330")
    self.resizable(False, False)
    self.configure(fg_color="#F6F8FA")
    self.grab_set()
    self.backups = backups
    self.on_restore_callback = on_restore_callback

    ctk.CTkLabel(
        self,
        text=f"Saved backups for {date_str}",
        font=("Inter", 17, "bold"),
        text_color="#1F2328",
    ).pack(anchor="w", padx=20, pady=(20, 4))
    ctk.CTkLabel(
        self,
        text="Choose a backup to restore. Current live data will be backed up first.",
        font=("Inter", 11),
        text_color="#57606A",
        wraplength=570,
    ).pack(anchor="w", padx=20, pady=(0, 12))

    if backups:
      display_names = [os.path.basename(path) for path in backups]
      self.backup_var = ctk.StringVar(value=display_names[0])
      self.backup_dropdown = ctk.CTkOptionMenu(
          self,
          values=display_names,
          variable=self.backup_var,
          height=36,
          fg_color="#FFFFFF",
          button_color="#EAF1F7",
          button_hover_color="#DCE9F2",
          dropdown_fg_color="#FFFFFF",
          text_color="#1F2328",
          anchor="w",
      )
      self.backup_dropdown.pack(fill="x", padx=20, pady=(4, 12))
    else:
      self.backup_var = None
      ctk.CTkLabel(
          self,
          text="No backups are available for this date yet.",
          fg_color="#FFFFFF",
          corner_radius=8,
          text_color="#57606A",
          height=54,
      ).pack(fill="x", padx=20, pady=(4, 12))

    buttons = ctk.CTkFrame(self, fg_color="transparent")
    buttons.pack(fill="x", padx=20, pady=(8, 18))
    ctk.CTkButton(
        buttons,
        text="Close",
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        text_color="#1F2328",
        command=self.destroy,
    ).pack(side="left", fill="x", expand=True, padx=(0, 6))
    self.restore_button = ctk.CTkButton(
        buttons,
        text="Restore Selected Backup",
        fg_color="#0969DA",
        hover_color="#054DA7",
        text_color="#FFFFFF",
        state="normal" if backups else "disabled",
        command=self.restore,
    )
    self.restore_button.pack(side="right", fill="x", expand=True, padx=(6, 0))

  def restore(self):
    if not self.backups or self.backup_var is None:
      return
    selected_name = self.backup_var.get()
    selected_path = next(
        (
            path
            for path in self.backups
            if os.path.basename(path) == selected_name
        ),
        None,
    )
    if selected_path and self.on_restore_callback(selected_path):
      self.destroy()


# --- FRONTEND: Application GUI ---
class LoginWindow(ctk.CTkToplevel):

  def __init__(self, parent, auth_manager=None):
    super().__init__(parent)
    self.auth_manager = auth_manager or AuthManager()
    self.data_encryption = DataEncryptionManager("material_records")
    self.authenticated = False
    self.authenticated_username = ""
    self.recovery_username = ""
    self.title("Material Tracker — Sign In")
    window_height = 610 if self.auth_manager.has_account else 700
    self.geometry(f"470x{window_height}")
    self.resizable(False, False)
    self.configure(fg_color="#F3F6FA")
    self.iconbitmap(get_asset_path("material_tracker.ico"))
    self.window_icon = PhotoImage(
        master=self,
        file=get_asset_path("material_tracker_logo.png"),
    )
    self.iconphoto(True, self.window_icon)
    self.protocol("WM_DELETE_WINDOW", self.close_login)

    self.card = ctk.CTkFrame(
        self,
        fg_color="#FFFFFF",
        corner_radius=12,
        border_width=1,
        border_color="#C7D4E0",
    )
    self.card.pack(fill="both", expand=True, padx=30, pady=24)
    ctk.CTkLabel(
        self.card,
        image=ctk.CTkImage(
            light_image=Image.open(
                get_asset_path("material_tracker_logo.png")
            ),
            size=(72, 72),
        ),
        text="",
    ).pack(pady=(22, 4))
    self.heading = ctk.CTkLabel(
        self.card,
        text="Material Tracker",
        font=("Inter", 21, "bold"),
        text_color="#203B55",
    )
    self.heading.pack(pady=(0, 2))
    self.subtitle = ctk.CTkLabel(
        self.card,
        text="",
        font=("Inter", 11),
        text_color="#526779",
    )
    self.subtitle.pack(pady=(0, 14))
    self.form = ctk.CTkFrame(self.card, fg_color="transparent")
    self.form.pack(fill="x", padx=20, pady=(0, 6))
    self.status_label = ctk.CTkLabel(
        self.card,
        text="",
        font=("Inter", 10),
        text_color="#B42332",
        wraplength=360,
    )
    self.status_label.pack(fill="x", padx=24, pady=(3, 15))
    self.username_entry = None
    self.password_entry = None
    self.render_initial_screen()
    self.deiconify()

  def clear_form(self):
    for child in self.form.winfo_children():
      child.destroy()
    self.status_label.configure(text="")

  def add_field(self, label, placeholder="", secret=False):
    ctk.CTkLabel(
        self.form,
        text=label,
        font=("Inter", 10, "bold"),
        text_color="#344B56",
        anchor="w",
    ).pack(fill="x", pady=(7, 3))
    entry = ctk.CTkEntry(
        self.form,
        height=36,
        placeholder_text=placeholder,
        show="*" if secret else "",
        fg_color="#F8FAFC",
        border_color="#B9C9D5",
        text_color="#203B55",
    )
    entry.pack(fill="x")
    return entry

  def add_action(
      self, text, command, secondary=False, width=140, height=36
  ):
    button = ctk.CTkButton(
        self.form,
        text=text,
        width=width,
        height=height,
        fg_color="#E2EAF0" if secondary else "#315A78",
        hover_color="#CFDDE7" if secondary else "#254762",
        text_color="#203B55" if secondary else "#FFFFFF",
        command=command,
    )
    button.pack(fill="x", pady=(12, 0))
    return button

  def render_initial_screen(self):
    self.clear_form()
    if self.auth_manager.has_account:
      self.heading.configure(text="Welcome back")
      self.subtitle.configure(text="Sign in to continue to your inventory.")
      self.username_entry = self.add_field("Username")
      self.password_entry = self.add_field("Password", secret=True)
      self.password_entry.bind("<Return>", lambda _event: self.sign_in())
      self.add_action("Sign In", self.sign_in)
      self.add_action("Forgot Password", self.open_recovery, secondary=True)
      self.username_entry.focus_set()
      return

    self.heading.configure(text="Set up your account")
    self.subtitle.configure(
        text="Create your local sign-in and recovery details."
    )
    self.username_entry = self.add_field("Username")
    self.password_entry = self.add_field(
        "Password", "At least 8 characters", secret=True
    )
    self.confirm_password_entry = self.add_field(
        "Confirm password", secret=True
    )
    self.recovery_question_entry = self.add_field(
        "Recovery question", "Enter a question only you can answer"
    )
    self.recovery_answer_entry = self.add_field(
        "Recovery answer", secret=True
    )
    self.add_action(
        "Create Account and Continue",
        self.create_account,
        width=360,
        height=48,
    )
    self.username_entry.focus_set()

  def sign_in(self):
    username = self.username_entry.get()
    password = self.password_entry.get()
    try:
      accepted = self.auth_manager.authenticate(
          username, password
      )
    except (OSError, ValueError, json.JSONDecodeError) as error:
      self.status_label.configure(
          text=f"Unable to read the login file: {error}",
          text_color="#B42332",
      )
      return
    if not accepted:
      self.status_label.configure(
          text="Username or password is incorrect.",
          text_color="#B42332",
      )
      self.password_entry.delete(0, "end")
      self.password_entry.focus_set()
      return
    try:
      if self.data_encryption.is_initialized:
        self.data_encryption.unlock(password)
      else:
        recovery_answer = simpledialog.askstring(
            "Protect Existing Inventory",
            (
                "Your inventory JSON files are not encrypted yet. "
                "Enter your recovery answer once to encrypt existing records "
                "and enable recovery if you reset the password. If you forget "
                "both your password and recovery answer, the data cannot be "
                "recovered."
            ),
            show="*",
            parent=self,
        )
        if recovery_answer is None:
          return
        if not self.auth_manager.verify_recovery_answer(
            username, recovery_answer
        ):
          self.status_label.configure(
              text="The recovery answer is incorrect; inventory was not encrypted.",
              text_color="#B42332",
          )
          return
        self.data_encryption.initialize(password, recovery_answer)
      self.data_encryption.encrypt_existing_json_files()
    except (OSError, ValueError, json.JSONDecodeError) as error:
      self.status_label.configure(
          text=f"Unable to unlock or encrypt inventory JSON: {error}",
          text_color="#B42332",
      )
      return
    self.authenticated = True
    self.authenticated_username = self.auth_manager._normalize_username(
        username
    )
    self.withdraw()
    self.quit()

  def create_account(self):
    try:
      created, message = self.auth_manager.create_account(
          self.username_entry.get(),
          self.password_entry.get(),
          self.confirm_password_entry.get(),
          self.recovery_question_entry.get(),
          self.recovery_answer_entry.get(),
      )
    except (OSError, ValueError) as error:
      self.status_label.configure(
          text=f"Unable to save the hidden login file: {error}",
          text_color="#B42332",
      )
      return
    if not created:
      self.status_label.configure(text=message, text_color="#B42332")
      return
    password = self.password_entry.get()
    recovery_answer = self.recovery_answer_entry.get()
    try:
      self.data_encryption.initialize(password, recovery_answer)
      self.data_encryption.encrypt_existing_json_files()
    except (OSError, ValueError, json.JSONDecodeError) as error:
      self.status_label.configure(
          text=f"Account created, but inventory encryption failed: {error}",
          text_color="#B42332",
      )
      return
    self.authenticated = True
    self.authenticated_username = self.auth_manager._normalize_username(
        self.username_entry.get()
    )
    self.withdraw()
    self.quit()

  def close_login(self):
    self.authenticated = False
    self.withdraw()
    self.master.quit()

  def open_recovery(self):
    username = self.username_entry.get().strip()
    if not username:
      self.status_label.configure(
          text="Enter your username first.",
          text_color="#B42332",
      )
      self.username_entry.focus_set()
      return
    try:
      question = self.auth_manager.get_recovery_question(username)
    except (OSError, ValueError, json.JSONDecodeError) as error:
      self.status_label.configure(
          text=f"Unable to read the login file: {error}",
          text_color="#B42332",
      )
      return
    if question is None:
      self.status_label.configure(
          text="No account matches that username.",
          text_color="#B42332",
      )
      return
    self.recovery_username = username
    self.clear_form()
    self.heading.configure(text="Reset password")
    self.subtitle.configure(text="Answer your recovery question to continue.")
    ctk.CTkLabel(
        self.form,
        text=question,
        font=("Inter", 11, "bold"),
        text_color="#203B55",
        wraplength=350,
    ).pack(fill="x", pady=(8, 5))
    self.recovery_answer_entry = self.add_field(
        "Recovery answer", secret=True
    )
    self.new_password_entry = self.add_field(
        "New password", "At least 8 characters", secret=True
    )
    self.new_confirm_password_entry = self.add_field(
        "Confirm new password", secret=True
    )
    self.add_action("Reset Password", self.reset_password)
    self.add_action("Back to Sign In", self.render_initial_screen, secondary=True)
    self.recovery_answer_entry.focus_set()

  def reset_password(self):
    try:
      reset, message = self.auth_manager.reset_password(
          self.recovery_username,
          self.recovery_answer_entry.get(),
          self.new_password_entry.get(),
          self.new_confirm_password_entry.get(),
          data_encryption=self.data_encryption,
      )
    except (OSError, ValueError, json.JSONDecodeError) as error:
      self.status_label.configure(
          text=f"Unable to update the hidden login file: {error}",
          text_color="#B42332",
      )
      return
    if not reset:
      self.status_label.configure(text=message, text_color="#B42332")
      return
    self.render_initial_screen()
    self.status_label.configure(
        text="Password updated. Sign in with your new password.",
        text_color="#34735E",
    )
    self.username_entry.insert(0, self.recovery_username)
    self.password_entry.focus_set()


class App(ctk.CTkToplevel):

  def __init__(
      self,
      parent,
      auth_manager=None,
      data_encryption=None,
      authenticated_username="",
  ):
    if os.name == "nt":
      ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
          "MaterialTracker.Inventory"
      )
    super().__init__(parent)
    self.auth_manager = auth_manager
    self.authenticated_username = authenticated_username
    self.storage = StorageManager(
        data_encryption,
        auth_manager,
        authenticated_username,
    )
    self.selected_date = datetime.now().strftime("%Y-%m-%d")
    self.active_day = self.selected_date
    self.range_start_date = self.selected_date
    self.range_end_date = self.selected_date
    self.range_mode = False
    self.storage.initialize_daily_snapshot(self.selected_date)
    self.storage.normalize_usecases(self.selected_date)

    self.title("Material Tracker")
    self.geometry("1280x760")
    self.minsize(1080, 640)
    self.configure(fg_color="#F3F6FA")
    self.iconbitmap(get_asset_path("material_tracker.ico"))
    self.window_icon = PhotoImage(
        master=self,
        file=get_asset_path("material_tracker_logo.png"),
    )
    self.iconphoto(True, self.window_icon)
    self.protocol("WM_DELETE_WINDOW", self.close_application)

    self.visible_record_locations = {}
    self.displayed_headers = []
    self.visible_columns = set(DEFAULT_VISIBLE_HEADERS)
    self.inline_editor = None

    # Top Header Bar
    self.top_bar = ctk.CTkFrame(
        self,
        fg_color="#18344D",
        corner_radius=0,
        border_width=0,
    )
    self.top_bar.pack(fill="x", side="top")

    self.logo_image = ctk.CTkImage(
        light_image=Image.open(get_asset_path("material_tracker_logo.png")),
        size=(36, 36),
    )
    self.brand_logo_label = ctk.CTkLabel(
        self.top_bar,
        image=self.logo_image,
        text="",
    )
    self.brand_logo_label.pack(side="left", padx=(16, 4), pady=4)

    ctk.CTkLabel(
        self.top_bar,
        text="MATERIAL TRACKER",
        font=("Inter", 15, "bold"),
        text_color="#FFFFFF",
    ).pack(side="left", padx=(4, 12), pady=(10, 7))

    self.date_picker_btn = ctk.CTkButton(
        self.top_bar,
        text=f"Record date  {self.selected_date}  ▾",
        height=32,
        width=190,
        fg_color="#F3F6FA",
        hover_color="#D8E3EC",
        border_width=1,
        border_color="#B9C9D5",
        text_color="#203B55",
        command=self.choose_selected_date,
    )
    self.date_picker_btn.pack(side="left", padx=(0, 12), pady=(8, 6))

    self.status_badge = ctk.CTkLabel(
        self.top_bar,
        text="●  LIVE JSON STORAGE",
        font=("Inter", 10, "bold"),
        text_color="#A9D6C1",
    )
    self.status_badge.pack(side="right", padx=20, pady=(10, 7))

    self.toolbar_actions = ctk.CTkFrame(
        self.top_bar,
        fg_color="#142B40",
        corner_radius=0,
        border_width=1,
        border_color="#304F68",
    )
    self.toolbar_actions.pack(fill="x", side="bottom")

    self.import_btn = ctk.CTkButton(
        self.toolbar_actions,
        text="Import Excel",
        width=110,
        height=32,
        fg_color="#FFFFFF",
        hover_color="#D8E3EC",
        border_width=1,
        border_color="#B9C9D5",
        text_color="#203B55",
        command=self.import_excel,
    )
    self.import_btn.pack(side="left", padx=(12, 4), pady=6)

    self.undo_btn = ctk.CTkButton(
        self.toolbar_actions,
        text="Undo Last Action",
        width=135,
        height=32,
        fg_color="#FFFFFF",
        hover_color="#D8E3EC",
        border_width=1,
        border_color="#B9C9D5",
        text_color="#203B55",
        command=self.undo_last_action,
    )
    self.undo_btn.pack(side="left", padx=4, pady=6)

    self.clear_data_btn = ctk.CTkButton(
        self.toolbar_actions,
        text="Clear Live Data",
        width=125,
        height=32,
        fg_color="#B42332",
        hover_color="#8F1D2C",
        border_width=1,
        border_color="#B42332",
        text_color="#FFFFFF",
        command=self.clear_live_data,
    )
    self.clear_data_btn.pack(side="left", padx=4, pady=6)

    self.delete_json_btn = ctk.CTkButton(
        self.toolbar_actions,
        text="Delete JSON",
        width=95,
        height=32,
        fg_color="#B42332",
        hover_color="#8F1D2C",
        border_width=1,
        border_color="#B42332",
        text_color="#FFFFFF",
        command=self.delete_selected_json,
    )
    self.delete_json_btn.pack(side="left", padx=4, pady=6)

    self.backups_btn = ctk.CTkButton(
        self.toolbar_actions,
        text="Backups",
        width=85,
        height=32,
        fg_color="#FFFFFF",
        hover_color="#D8E3EC",
        border_width=1,
        border_color="#B9C9D5",
        text_color="#203B55",
        command=self.open_backups,
    )
    self.backups_btn.pack(side="left", padx=4, pady=6)

    self.export_btn = ctk.CTkButton(
        self.toolbar_actions,
        text="Export XLSX",
        width=105,
        height=32,
        fg_color="#315A78",
        hover_color="#254762",
        border_width=1,
        border_color="#315A78",
        text_color="#FFFFFF",
        command=self.export_excel,
    )
    self.export_btn.pack(side="left", padx=4, pady=6)

    self.page_tabs = ctk.CTkTabview(
        self,
        fg_color="#F3F6FA",
        segmented_button_fg_color="#E5ECF2",
        segmented_button_selected_color="#2D6288",
        segmented_button_selected_hover_color="#244F6E",
        segmented_button_unselected_color="#E5ECF2",
        segmented_button_unselected_hover_color="#D8E2EB",
        text_color="#203B55",
    )
    self.page_tabs.pack(fill="both", expand=True, padx=14, pady=(10, 14))
    self.dashboard_tab = self.page_tabs.add("Dashboard")
    self.inventory_tab = self.page_tabs.add("Inventory Sheet")
    self.pie_metric_var = ctk.StringVar(value="Availability")
    self.create_dashboard()

    # Main Layout
    self.main_container = ctk.CTkFrame(
        self.inventory_tab, fg_color="transparent"
    )
    self.main_container.pack(fill="both", expand=True, padx=14, pady=14)

    self.main_container.grid_columnconfigure(0, weight=1)
    self.main_container.grid_columnconfigure(1, weight=3)
    self.main_container.grid_rowconfigure(0, weight=1)

    # --- LEFT PANEL ---
    self.left_panel = ctk.CTkFrame(
        self.main_container,
        fg_color="#FFFFFF",
        corner_radius=10,
        border_width=1,
        border_color="#DCE4EC",
    )

    ctk.CTkLabel(
        self.left_panel,
        text="Manage Columns",
        font=("Inter", 15, "bold"),
        text_color="#1F2328",
    ).pack(anchor="w", padx=15, pady=(15, 5))

    col_frame = ctk.CTkFrame(
        self.left_panel,
        fg_color="#F5F8FB",
        corner_radius=8,
        border_width=1,
        border_color="#DCE4EC",
    )
    col_frame.pack(fill="x", padx=12, pady=8)

    # Delete Column
    ctk.CTkLabel(
        col_frame,
        text="Delete Column",
        font=("Inter", 11, "bold"),
        text_color="#57606A",
    ).pack(anchor="w", padx=10, pady=(4, 2))
    del_row = ctk.CTkFrame(col_frame, fg_color="transparent")
    del_row.pack(fill="x", padx=10, pady=(0, 8))

    self.col_dropdown = ctk.CTkOptionMenu(
        del_row,
        values=["None"],
        height=32,
        fg_color="#FFFFFF",
        button_color="#EAEEF2",
        button_hover_color="#D0D7DE",
        dropdown_fg_color="#FFFFFF",
        text_color="#1F2328",
    )
    self.col_dropdown.pack(side="left", fill="x", expand=True, padx=(0, 4))

    ctk.CTkButton(
        del_row,
        text="- Delete",
        width=65,
        height=32,
        fg_color="#FFEBE9",
        hover_color="#FFCECA",
        border_width=1,
        border_color="#FD8C73",
        text_color="#CF222E",
        command=self.delete_column,
    ).pack(side="right")

    # --- RIGHT PANEL ---
    self.right_panel = ctk.CTkFrame(
        self.main_container,
        fg_color="#FFFFFF",
        corner_radius=10,
        border_width=1,
        border_color="#DCE4EC",
    )
    self.right_panel.grid(row=0, column=0, columnspan=2, sticky="nsew")

    header_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
    header_frame.pack(fill="x", padx=18, pady=(16, 12))

    self.log_view_title = ctk.CTkLabel(
        header_frame,
        text=f"Live Inventory + {self.selected_date} Log",
        font=("Inter", 16, "bold"),
        text_color="#203B55",
    )
    self.log_view_title.pack(side="left", padx=(0, 12))

    self.range_frame = ctk.CTkFrame(
        self.right_panel,
        fg_color="#F5F8FB",
        corner_radius=8,
    )
    self.range_frame.pack(fill="x", padx=15, pady=(0, 8))
    ctk.CTkLabel(
        self.range_frame,
        text="Record range:",
        font=("Inter", 10, "bold"),
        text_color="#526779",
    ).pack(side="left", padx=(9, 6))
    self.range_start_btn = ctk.CTkButton(
        self.range_frame,
        text=f"From {self.range_start_date}",
        width=145,
        height=28,
        fg_color="#FFFFFF",
        hover_color="#EAF1F7",
        border_width=1,
        border_color="#D5DDE1",
        text_color="#1F2328",
        command=self.choose_range_start,
    )
    self.range_start_btn.pack(side="left", padx=(0, 5))
    self.range_end_btn = ctk.CTkButton(
        self.range_frame,
        text=f"To {self.range_end_date}",
        width=145,
        height=28,
        fg_color="#FFFFFF",
        hover_color="#EAF1F7",
        border_width=1,
        border_color="#D0D7DE",
        text_color="#1F2328",
        command=self.choose_range_end,
    )
    self.range_end_btn.pack(side="left", padx=(0, 5))
    ctk.CTkButton(
        self.range_frame,
        text="Apply",
        width=95,
        height=28,
        fg_color="#315A78",
        hover_color="#254762",
        text_color="#FFFFFF",
        command=self.apply_date_range,
    ).pack(side="left", padx=(0, 5))
    ctk.CTkButton(
        self.range_frame,
        text="Single Date",
        width=90,
        height=28,
        fg_color="#E2EAF0",
        hover_color="#CFDDE7",
        text_color="#18344D",
        command=self.show_single_date,
    ).pack(side="left")

    self.choose_columns_btn = ctk.CTkButton(
        header_frame,
        text="Show/Hide Columns",
        width=132,
        height=32,
        fg_color="#EAEEF2",
        hover_color="#D0D7DE",
        border_width=1,
        border_color="#D0D7DE",
        text_color="#1F2328",
        command=self.choose_live_columns,
    )
    self.choose_columns_btn.pack(side="right")

    actions_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
    actions_frame.pack(fill="x", padx=15, pady=(0, 10))

    column_delete_frame = ctk.CTkFrame(
        actions_frame, fg_color="transparent"
    )
    column_delete_frame.pack(side="left", fill="x", expand=True)
    ctk.CTkLabel(
        column_delete_frame,
        text="Delete column:",
        font=("Inter", 10),
        text_color="#57606A",
    ).pack(side="left", padx=(0, 5))
    self.col_dropdown = ctk.CTkOptionMenu(
        column_delete_frame,
        values=["No custom cols"],
        height=30,
        width=145,
        fg_color="#FFFFFF",
        button_color="#EAEEF2",
        button_hover_color="#D0D7DE",
        dropdown_fg_color="#FFFFFF",
        text_color="#1F2328",
    )
    self.col_dropdown.pack(side="left", padx=(0, 4))
    self.delete_column_btn = ctk.CTkButton(
        column_delete_frame,
        text="Delete Column",
        width=100,
        height=30,
        fg_color="#B42332",
        hover_color="#8F1D2C",
        border_width=1,
        border_color="#B42332",
        text_color="#FFFFFF",
        command=self.delete_column,
    )
    self.delete_column_btn.pack(side="left")

    self.add_row_btn = ctk.CTkButton(
        actions_frame,
        text="+ Add Inventory Item",
        width=142,
        height=30,
        fg_color="#416F60",
        hover_color="#345C4F",
        text_color="#FFFFFF",
        command=self.add_table_row,
    )
    self.add_row_btn.pack(side="right", padx=(4, 0))

    self.add_column_btn = ctk.CTkButton(
        actions_frame,
        text="+ Add Column",
        width=100,
        height=30,
        fg_color="#E2EAF0",
        hover_color="#CFDDE7",
        border_width=1,
        border_color="#C4D2DE",
        text_color="#203B55",
        command=self.add_column,
    )
    self.add_column_btn.pack(side="right", padx=(4, 0))

    self.del_btn = ctk.CTkButton(
        actions_frame,
        text="Delete Row",
        width=90,
        height=30,
        fg_color="#B42332",
        hover_color="#8F1D2C",
        border_width=1,
        border_color="#B42332",
        text_color="#FFFFFF",
        command=self.delete_selected,
    )
    self.del_btn.pack(side="right", padx=(4, 0))

    self.usage_btn = ctk.CTkButton(
        actions_frame,
        text="Record Usage",
        width=100,
        height=30,
        fg_color="#416F60",
        hover_color="#345C4F",
        text_color="#FFFFFF",
        command=self.record_usage_selected,
    )
    self.usage_btn.pack(side="right", padx=(4, 0))

    self.stock_in_btn = ctk.CTkButton(
        actions_frame,
        text="Record Stock In",
        width=112,
        height=30,
        fg_color="#315A78",
        hover_color="#254762",
        text_color="#FFFFFF",
        command=self.record_stock_in_selected,
    )
    self.stock_in_btn.pack(side="right", padx=(4, 0))

    self.counter_badge = ctk.CTkLabel(
        actions_frame,
        text="0 items",
        font=("Inter", 11),
        text_color="#57606A",
        fg_color="#F6F8FA",
        corner_radius=12,
        padx=10,
        pady=2,
    )
    self.counter_badge.pack(side="right", padx=(0, 8))

    self.status_label = ctk.CTkLabel(
        self.right_panel,
        text="",
        font=("Inter", 11),
        wraplength=900,
        anchor="w",
    )
    self.status_label.pack(fill="x", padx=16, pady=(0, 6))

    self.table_container = ctk.CTkFrame(
        self.right_panel, fg_color="transparent"
    )
    self.table_container.pack(fill="both", expand=True, padx=18, pady=(0, 18))

    # Styled Treeview
    style = ttk.Style()
    style.theme_use("default")
    style.configure(
        "Inventory.Treeview",
        background="#FFFFFF",
        foreground="#203B55",
        fieldbackground="#FFFFFF",
        rowheight=35,
        borderwidth=1,
        relief="flat",
        font=("Inter", 10),
    )
    style.configure(
        "Inventory.Treeview.Heading",
        background="#18344D",
        foreground="#FFFFFF",
        font=("Inter", 10, "bold"),
        relief="flat",
        borderwidth=0,
        padding=(10, 9),
    )
    style.map(
        "Inventory.Treeview",
        background=[("selected", "#2D6288")],
        foreground=[("selected", "#FFFFFF")],
    )
    style.map(
        "Inventory.Treeview.Heading",
        background=[("active", "#2D6288")],
    )

    self.tree = None
    self.update_date_dropdown()
    self.rebuild_ui()
    self.after(60000, self.check_day_rollover)

  def create_dashboard(self):
    self.dashboard_tab.grid_columnconfigure(0, weight=1)
    self.dashboard_tab.grid_rowconfigure(0, weight=1)

    self.dashboard_scroll = ctk.CTkScrollableFrame(
        self.dashboard_tab,
        fg_color="transparent",
        scrollbar_button_color="#CBD5D8",
        scrollbar_button_hover_color="#B7C6CA",
    )
    self.dashboard_scroll.grid(row=0, column=0, sticky="nsew")
    self.dashboard_scroll.grid_columnconfigure(tuple(range(6)), weight=1)

    heading = ctk.CTkFrame(
        self.dashboard_scroll,
        fg_color="#18344D",
        corner_radius=10,
        border_width=1,
        border_color="#18344D",
    )
    heading.grid(
        row=0, column=0, columnspan=6, sticky="ew", padx=4, pady=(4, 12)
    )
    ctk.CTkLabel(
        heading,
        text="Inventory Dashboard",
        font=("Inter", 23, "bold"),
        text_color="#FFFFFF",
    ).pack(anchor="w", padx=18, pady=(14, 2))
    self.dashboard_date_label = ctk.CTkLabel(
        heading,
        text=f"Overview for {self.selected_date}",
        font=("Inter", 11),
        text_color="#D5E1EA",
    )
    self.dashboard_date_label.pack(anchor="w", padx=18, pady=(0, 14))

    self.dashboard_metric_labels = {}
    metrics = (
        ("items", "Inventory items", "#315A78", "#EDF3F8"),
        ("stock", "Units in stock", "#34735E", "#EDF5F1"),
        ("available", "Available units", "#237A88", "#EDF6F7"),
        ("reserved", "Reserved units", "#665C93", "#F2F0F8"),
        ("low", "At / below reorder", "#A96732", "#F8F2EC"),
        ("value", "Inventory value", "#46678F", "#EEF2F8"),
    )
    for column, (key, title, color, card_color) in enumerate(metrics):
      card = ctk.CTkFrame(
          self.dashboard_scroll,
          fg_color=card_color,
          corner_radius=10,
          border_width=1,
          border_color="#DCE4EC",
      )
      card.grid(row=1, column=column, sticky="nsew", padx=4, pady=(0, 12))
      ctk.CTkFrame(
          card,
          height=4,
          fg_color=color,
          corner_radius=2,
      ).pack(fill="x", padx=12, pady=(10, 0))
      ctk.CTkLabel(
          card,
          text=title.upper(),
          font=("Inter", 9, "bold"),
          text_color="#57606A",
      ).pack(anchor="w", padx=14, pady=(13, 4))
      metric = ctk.CTkLabel(
          card,
          text="0",
          font=("Inter", 23, "bold"),
          text_color=color,
      )
      metric.pack(anchor="w", padx=14, pady=(0, 13))
      self.dashboard_metric_labels[key] = metric

    self.dashboard_charts = ctk.CTkFrame(
        self.dashboard_scroll,
        fg_color="transparent",
    )
    self.dashboard_charts.grid(
        row=2, column=0, columnspan=6, sticky="nsew", padx=4, pady=(0, 12)
    )
    self.dashboard_charts.grid_columnconfigure((0, 1, 2), weight=1)
    self.category_chart_frame = ctk.CTkFrame(
        self.dashboard_charts,
        fg_color="#FFFFFF",
        corner_radius=10,
        border_width=1,
        border_color="#DCE4EC",
    )
    self.category_chart_frame.grid(
        row=0, column=0, sticky="nsew", padx=(0, 6)
    )
    self.balance_chart_frame = ctk.CTkFrame(
        self.dashboard_charts,
        fg_color="#FFFFFF",
        corner_radius=10,
        border_width=1,
        border_color="#DCE4EC",
    )
    self.balance_chart_frame.grid(
        row=0, column=1, sticky="nsew", padx=6
    )
    self.low_stock_frame = ctk.CTkFrame(
        self.dashboard_charts,
        fg_color="#FFFFFF",
        corner_radius=10,
        border_width=1,
        border_color="#DCE4EC",
    )
    self.low_stock_frame.grid(
        row=0, column=2, sticky="nsew", padx=(6, 0)
    )

  def close_application(self):
    self.withdraw()
    self.master.quit()

  def refresh_dashboard(self):
    if self.range_mode:
      dated_records = self.storage.get_live_records_between(
          self.range_start_date, self.range_end_date
      )
      period_label = (
          f"{self.range_start_date} to {self.range_end_date}"
      )
    else:
      dated_records = self.storage.get_live_records(self.selected_date)
      period_label = self.selected_date
    records = [record for _, _, record in dated_records]
    self.dashboard_date_label.configure(
        text=f"Overview for {period_label}  ·  {len(records)} dated records"
    )

    total_stock = Decimal(0)
    total_available = Decimal(0)
    total_reserved = Decimal(0)
    total_value = Decimal(0)
    low_stock_items = []
    category_stock = {}
    category_value = {}
    reorder_status = {"At/Below Reorder": 0, "Above Reorder": 0}
    for record in records:
      try:
        current = Decimal(
            str(record.get("Current Stock") or 0).replace(",", "")
        )
        reserved = Decimal(
            str(record.get("Reserved for Production") or 0).replace(",", "")
        )
        available = max(Decimal(0), current - reserved)
        reorder = Decimal(
            str(record.get("Reorder Level") or 0).replace(",", "")
        )
        unit_cost = Decimal(
            str(record.get("Unit Cost") or 0).replace(",", "")
        )
        value = current * unit_cost
        if all(number.is_finite() for number in (current, reserved, available, reorder, value)):
          total_stock += current
          total_available += available
          total_reserved += max(Decimal(0), current - available)
          total_value += value
          if reorder > 0 and available <= reorder:
            item_name = (
                record.get("Component Description")
                or record.get("Part Number")
                or "Unnamed item"
            )
            low_stock_items.append((str(item_name), available, reorder))
            reorder_status["At/Below Reorder"] += 1
          elif reorder > 0:
            reorder_status["Above Reorder"] += 1
          category = str(record.get("Category") or "Uncategorized").strip()
          category_stock[category] = category_stock.get(category, Decimal(0)) + current
          category_value[category] = (
              category_value.get(category, Decimal(0)) + value
          )
      except (InvalidOperation, AttributeError):
        continue

    self.dashboard_metric_labels["items"].configure(text=str(len(records)))
    self.dashboard_metric_labels["stock"].configure(
        text=format(total_stock.normalize(), "f")
        if total_stock
        else "0"
    )
    self.dashboard_metric_labels["available"].configure(
        text=format(total_available.normalize(), "f")
        if total_available
        else "0"
    )
    self.dashboard_metric_labels["reserved"].configure(
        text=format(total_reserved.normalize(), "f")
        if total_reserved
        else "0"
    )
    self.dashboard_metric_labels["low"].configure(
        text=str(len(low_stock_items))
    )
    self.dashboard_metric_labels["value"].configure(
        text=f"{total_value:,.2f}"
    )
    self.render_dashboard_charts(
        category_stock,
        category_value,
        low_stock_items,
        total_stock,
        total_available,
        total_reserved,
        total_value,
        reorder_status,
    )

  def render_dashboard_charts(
      self,
      category_stock,
      category_value,
      low_stock_items,
      total_stock,
      total_available,
      total_reserved,
      total_value,
      reorder_status,
  ):
    for widget in self.category_chart_frame.winfo_children():
      widget.destroy()
    for widget in self.balance_chart_frame.winfo_children():
      widget.destroy()
    for widget in self.low_stock_frame.winfo_children():
      widget.destroy()

    ctk.CTkLabel(
        self.category_chart_frame,
        text="Stock by Category",
        font=("Inter", 14, "bold"),
        text_color="#344B56",
    ).pack(anchor="w", padx=16, pady=(15, 10))
    sorted_categories = sorted(
        category_stock.items(), key=lambda item: item[1], reverse=True
    )[:8]
    if not sorted_categories:
      ctk.CTkLabel(
          self.category_chart_frame,
          text="Import or add inventory to see category totals.",
          font=("Inter", 11),
          text_color="#57606A",
      ).pack(anchor="w", padx=16, pady=(6, 18))
    else:
      max_stock = max(amount for _, amount in sorted_categories) or Decimal(1)
      chart_colors = ("#315A78", "#34735E", "#237A88", "#7969A6", "#A96732")
      for category_index, (category, amount) in enumerate(sorted_categories):
        line = ctk.CTkFrame(self.category_chart_frame, fg_color="transparent")
        line.pack(fill="x", padx=16, pady=5)
        line.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            line,
            text=category,
            width=110,
            anchor="w",
            font=("Inter", 10),
            text_color="#1F2328",
        ).grid(row=0, column=0, sticky="w", padx=(0, 10))
        bar_track = ctk.CTkFrame(
            line,
            height=16,
            fg_color="#E5ECF1",
            corner_radius=8,
        )
        bar_track.grid(row=0, column=1, sticky="ew")
        ratio = float(amount / max_stock)
        ctk.CTkFrame(
            bar_track,
            width=6,
            height=16,
            fg_color=chart_colors[category_index % len(chart_colors)],
            corner_radius=8,
        ).place(x=0, y=0, relwidth=max(0.025, ratio), relheight=1)
        ctk.CTkLabel(
            line,
            text=format(amount.normalize(), "f") if amount else "0",
            width=70,
            anchor="e",
            font=("Inter", 10, "bold"),
            text_color="#344B56",
        ).grid(row=0, column=2, sticky="e", padx=(8, 0))

    pie_header = ctk.CTkFrame(
        self.balance_chart_frame, fg_color="transparent"
    )
    pie_header.pack(fill="x", padx=16, pady=(12, 8))
    ctk.CTkLabel(
        pie_header,
        text="Pie Chart",
        font=("Inter", 14, "bold"),
        text_color="#344B56",
    ).pack(side="left")
    pie_options = (
        "Availability",
        "Stock by Category",
        "Value by Category",
        "Reorder Status",
    )
    self.pie_metric_var.set(
        self.pie_metric_var.get()
        if self.pie_metric_var.get() in pie_options
        else "Availability"
    )
    ctk.CTkOptionMenu(
        pie_header,
        variable=self.pie_metric_var,
        values=pie_options,
        width=150,
        height=28,
        font=("Inter", 10),
        command=lambda _value: self.refresh_dashboard(),
    ).pack(side="right")
    pie_row = ctk.CTkFrame(self.balance_chart_frame, fg_color="transparent")
    pie_row.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    pie = Canvas(
        pie_row,
        width=190,
        height=190,
        bg="#FFFFFF",
        highlightthickness=0,
        bd=0,
    )
    pie.pack(side="left", padx=(0, 6))
    if self.pie_metric_var.get() == "Availability":
      pie_values = [
          ("Available", total_available, "#315A78"),
          ("Reserved", total_reserved, "#78A69A"),
      ]
      center_value = total_stock
      center_label = "total units"
    elif self.pie_metric_var.get() == "Stock by Category":
      palette = ("#315A78", "#34735E", "#237A88", "#7969A6", "#A96732")
      categories = sorted(
          category_stock.items(), key=lambda item: item[1], reverse=True
      )
      pie_values = [
          (category, amount, palette[index % len(palette)])
          for index, (category, amount) in enumerate(categories[:5])
      ]
      other_stock = sum(
          (amount for _, amount in categories[5:]), Decimal(0)
      )
      if other_stock:
        pie_values.append(("Other", other_stock, "#AAB7C4"))
      center_value = total_stock
      center_label = "total units"
    elif self.pie_metric_var.get() == "Value by Category":
      palette = ("#315A78", "#34735E", "#237A88", "#7969A6", "#A96732")
      categories = sorted(
          category_value.items(), key=lambda item: item[1], reverse=True
      )
      pie_values = [
          (category, amount, palette[index % len(palette)])
          for index, (category, amount) in enumerate(categories[:5])
      ]
      other_value = sum(
          (amount for _, amount in categories[5:]), Decimal(0)
      )
      if other_value:
        pie_values.append(("Other", other_value, "#AAB7C4"))
      center_value = total_value
      center_label = "inventory value"
    else:
      pie_values = [
          ("At/Below Reorder", Decimal(reorder_status["At/Below Reorder"]), "#C65D48"),
          ("Above Reorder", Decimal(reorder_status["Above Reorder"]), "#34735E"),
      ]
      center_value = Decimal(sum(reorder_status.values()))
      center_label = "items tracked"
    pie_total = sum((amount for _, amount, _ in pie_values), Decimal(0))
    if pie_total > 0:
      start_angle = 90
      for _label, amount, color in pie_values:
        extent = 360 * float(amount / pie_total)
        pie.create_arc(
            15, 12, 175, 172,
            start=start_angle,
            extent=extent,
            style="pieslice",
            fill=color,
            outline="#FFFFFF",
            width=2,
        )
        start_angle += extent
      pie.create_oval(58, 55, 132, 129, fill="#FFFFFF", outline="#FFFFFF")
      pie.create_text(
          95,
          84,
          text=f"{center_value:,.2f}" if center_value != center_value.to_integral_value() else f"{center_value:,.0f}",
          fill="#344B56",
          font=("Inter", 12, "bold"),
      )
      pie.create_text(
          95,
          103,
          text=center_label,
          fill="#687982",
          font=("Inter", 7),
      )
    else:
      pie.create_text(
          95, 92, text="No stock", fill="#687982", font=("Inter", 10)
      )
    legend = ctk.CTkFrame(pie_row, fg_color="transparent")
    legend.pack(side="left", fill="y", expand=True, padx=(4, 0))
    for label, amount, color in pie_values:
      line = ctk.CTkFrame(legend, fg_color="transparent")
      line.pack(fill="x", pady=5)
      ctk.CTkFrame(
          line, width=10, height=10, fg_color=color, corner_radius=3
      ).pack(side="left", padx=(0, 7))
      ctk.CTkLabel(
          line,
          text=f"{label}\n{amount:,.2f}" if amount != amount.to_integral_value() else f"{label}\n{amount:,.0f}",
          justify="left",
          anchor="w",
          font=("Inter", 10),
          text_color="#344B56",
      ).pack(side="left")

    ctk.CTkLabel(
        self.low_stock_frame,
        text="Reorder Attention",
        font=("Inter", 14, "bold"),
        text_color="#344B56",
    ).pack(anchor="w", padx=16, pady=(15, 10))
    if not low_stock_items:
      ctk.CTkLabel(
          self.low_stock_frame,
          text="No items are at or below their reorder level.",
          font=("Inter", 11),
          text_color="#1A7F37",
      ).pack(anchor="w", padx=16, pady=(6, 18))
      return
    for item_name, available, reorder in sorted(
        low_stock_items, key=lambda item: item[1]
    )[:8]:
      row = ctk.CTkFrame(
          self.low_stock_frame,
          fg_color="#F6F2EE",
          corner_radius=4,
      )
      row.pack(fill="x", padx=14, pady=3)
      ctk.CTkLabel(
          row,
          text=item_name,
          font=("Inter", 10, "bold"),
          text_color="#594B41",
          anchor="w",
      ).pack(side="left", fill="x", expand=True, padx=10, pady=7)
      ctk.CTkLabel(
          row,
          text=(
              f"{format(available.normalize(), 'f')} available  /  "
              f"reorder at {format(reorder.normalize(), 'f')}"
          ),
          font=("Inter", 9),
          text_color="#80624B",
      ).pack(side="right", padx=10, pady=7)

  def update_date_dropdown(self):
    self.date_picker_btn.configure(text=f"Date: {self.selected_date}")
    self.range_start_btn.configure(text=f"From {self.range_start_date}")
    self.range_end_btn.configure(text=f"To {self.range_end_date}")

  def choose_selected_date(self):
    InventoryCalendarDialog(
        self.date_picker_btn,
        self.selected_date,
        self.on_date_changed,
    )

  def choose_range_start(self):
    InventoryCalendarDialog(
        self.range_start_btn,
        self.range_start_date,
        self.set_range_start,
    )

  def choose_range_end(self):
    InventoryCalendarDialog(
        self.range_end_btn,
        self.range_end_date,
        self.set_range_end,
    )

  def set_range_start(self, selected_date):
    self.range_start_date = selected_date
    self.update_date_dropdown()

  def set_range_end(self, selected_date):
    self.range_end_date = selected_date
    self.update_date_dropdown()

  def apply_date_range(self):
    start_date = parse_inventory_date(self.range_start_date)
    end_date = parse_inventory_date(self.range_end_date)
    if start_date is None or end_date is None:
      self.status_label.configure(
          text="Choose valid start and end dates.",
          text_color="#CF222E",
      )
      return
    if start_date > end_date:
      self.status_label.configure(
          text="The start date must be on or before the end date.",
          text_color="#CF222E",
      )
      return

    self.range_mode = True
    self.selected_date = self.range_end_date
    self.update_date_dropdown()
    self.log_view_title.configure(
        text=f"Inventory Records: {self.range_start_date} to {self.range_end_date}"
    )
    self.rebuild_ui()

  def show_single_date(self):
    self.range_mode = False
    self.log_view_title.configure(
        text=f"Live Inventory + {self.selected_date} Log"
    )
    self.rebuild_ui()

  def on_date_changed(self, new_date):
    self.selected_date = new_date
    self.range_start_date = new_date
    self.range_end_date = new_date
    self.range_mode = False
    self.storage.initialize_daily_snapshot(new_date)
    self.storage.normalize_usecases(new_date)
    self.update_date_dropdown()
    self.log_view_title.configure(
        text=f"Live Inventory + {self.selected_date} Log"
    )
    self.rebuild_ui()

  def check_day_rollover(self):
    today = datetime.now().strftime("%Y-%m-%d")
    if today != self.active_day:
      self.storage.initialize_daily_snapshot(today)
      should_switch_to_today = self.selected_date == self.active_day
      self.active_day = today
      if should_switch_to_today:
        self.selected_date = today
        self.range_start_date = today
        self.range_end_date = today
        self.range_mode = False
        self.update_date_dropdown()
        self.log_view_title.configure(
            text=f"Live Inventory + {self.selected_date} Log"
        )
        self.rebuild_ui()
        self.status_label.configure(
            text=f"Started today's inventory log for {today}.",
            text_color="#1A7F37",
        )
    self.after(60000, self.check_day_rollover)

  def rebuild_ui(self):
    deletable = self.storage.get_deletable_headers(self.selected_date)
    self.update_undo_button()

    if deletable:
      self.col_dropdown.configure(values=deletable)
      self.col_dropdown.set(deletable[0])
    else:
      self.col_dropdown.configure(values=["No custom cols"])
      self.col_dropdown.set("No custom cols")

    self.rebuild_live_table()

  def rebuild_live_table(self):
    self.cancel_inline_edit()
    for widget in self.table_container.winfo_children():
      widget.destroy()

    all_headers = (
        self.storage.get_live_headers_between(
            self.range_start_date, self.range_end_date
        )
        if self.range_mode
        else self.storage.get_live_headers(self.selected_date)
    )
    if self.visible_columns == set(DEFAULT_VISIBLE_HEADERS):
      table_headers = [
          header
          for header in DEFAULT_VISIBLE_HEADERS
          if header in all_headers
      ]
    else:
      table_headers = [
          header
          for header in all_headers
          if header in self.visible_columns
          and header.casefold() not in ("date & day", "time")
      ]
    if self.range_mode:
      table_headers.insert(0, "Record Date")
    self.displayed_headers = table_headers
    self.tree = ttk.Treeview(
        self.table_container,
        columns=table_headers,
        show="tree headings",
        style="Inventory.Treeview",
    )
    self.tree.tag_configure("alternate", background="#F1F5F9")
    self.tree.tag_configure(
        "low_stock",
        foreground="#735A46",
        background="#F7F2EC",
    )
    live_records = self.get_display_records()
    cell_font = tkfont.Font(self.tree, font=("Inter", 10))
    heading_font = tkfont.Font(self.tree, font=("Inter", 10, "bold"))
    self.tree.heading("#0", text="#", anchor="center")
    self.tree.column(
        "#0",
        width=48,
        minwidth=48,
        stretch=False,
        anchor="center",
    )
    for h in table_headers:
      self.tree.heading(h, text=h, anchor="center")
      widest_cell = max(
          (
              cell_font.measure(line)
              for record_date, _, record in live_records
              for line in str(
                  self.format_live_value(
                      h,
                      record_date if h == "Record Date" else record.get(h, ""),
                  )
                  or ""
              ).splitlines()
          ),
          default=0,
      )
      content_width = max(
          heading_font.measure(h) + 28,
          widest_cell + 24,
      )
      max_width = {
          "component description": 280,
          "storage location": 190,
          "record date": 125,
          "usecase": 380,
          "stock in": 300,
      }.get(h.casefold(), 220)
      width = min(max(content_width, 88), max_width)
      if h.casefold() == "uom":
        width = max(86, min(width, 120))
      self.tree.column(
          h,
          width=width,
          minwidth=min(width, 110),
          stretch=False,
          anchor="center",
      )

    self.tree.bind("<Button-1>", self.begin_inline_edit)
    self.tree.bind("<<TreeviewSelect>>", lambda _event: self.update_undo_button())
    self.tree.bind("<Delete>", lambda e: self.delete_selected())

    scrollbar = ttk.Scrollbar(
        self.table_container, orient="vertical", command=self.tree.yview
    )
    horizontal_scrollbar = ttk.Scrollbar(
        self.table_container, orient="horizontal", command=self.tree.xview
    )
    self.tree.configure(
        yscrollcommand=scrollbar.set,
        xscrollcommand=horizontal_scrollbar.set,
    )
    scrollbar.pack(side="right", fill="y")
    horizontal_scrollbar.pack(side="bottom", fill="x")
    self.tree.pack(fill="both", expand=True)

    self.refresh_live_table()

  def refresh_live_table(self):
    selected_location = self.get_selected_location()
    self.cancel_inline_edit()
    for item in self.tree.get_children():
      self.tree.delete(item)

    records = self.get_display_records()
    self.visible_record_locations.clear()

    for position, (date_value, index, r) in enumerate(records):
      row_values = [
          date_value
          if h == "Record Date"
          else self.format_live_value(h, r.get(h, ""))
          for h in self.displayed_headers
      ]
      item_id = f"record_{position}"
      row_tags = ["alternate"] if position % 2 else []
      try:
        available = Decimal(
            str(r.get("Available Stock") or 0).replace(",", "")
        )
        reorder = Decimal(
            str(r.get("Reorder Level") or 0).replace(",", "")
        )
        if reorder > 0 and available <= reorder:
          row_tags.append("low_stock")
      except (InvalidOperation, AttributeError):
        pass
      self.tree.insert(
          "",
          "end",
          iid=item_id,
          text=str(position + 1),
          values=row_values,
          tags=tuple(row_tags),
      )
      self.visible_record_locations[item_id] = (date_value, index)

    if selected_location:
      selected_row = next(
          (
              item_id
              for item_id, location in self.visible_record_locations.items()
              if location == selected_location
          ),
          None,
      )
      if selected_row:
        self.tree.selection_set(selected_row)

    self.counter_badge.configure(text=f"{len(records)} records logged")
    self.update_undo_button()
    self.refresh_dashboard()

  def get_display_records(self):
    if self.range_mode:
      return self.storage.get_live_records_between(
          self.range_start_date, self.range_end_date
      )
    return self.storage.get_live_records(self.selected_date)

  def get_undo_date(self):
    location = self.get_selected_location() if self.range_mode else None
    return location[0] if location else self.selected_date

  def update_undo_button(self):
    undo_date = self.get_undo_date()
    self.undo_btn.configure(
        state="normal" if self.storage.has_undo(undo_date) else "disabled"
    )

  def format_live_value(self, header, value):
    """Hide movement timestamps in the grid while preserving the saved values."""
    if value in (None, ""):
      return value
    if header.casefold() == "stock in":
      return "\n".join(
          line.split(" | ", 1)[0] for line in str(value).splitlines()
      )
    if header.casefold() == "usecase":
      return "\n".join(
          " | ".join(
              part.strip()
              for part in line.split(" | ")
              if not part.strip().casefold().startswith(("date:", "time:"))
          )
          for line in str(value).splitlines()
      )
    return value

  def choose_live_columns(self):
    headers = (
        self.storage.get_live_headers_between(
            self.range_start_date, self.range_end_date
        )
        if self.range_mode
        else self.storage.get_live_headers(self.selected_date)
    )
    ColumnVisibilityDialog(
        self,
        headers,
        self.visible_columns,
        self.apply_live_columns,
    )

  def apply_live_columns(self, selected_headers):
    if not selected_headers:
      selected_headers = set(DEFAULT_VISIBLE_HEADERS)
      self.status_label.configure(
          text="At least one live column must remain visible; restored the default columns.",
          text_color="#57606A",
      )
    self.visible_columns = selected_headers
    self.rebuild_live_table()

  def get_selected_location(self):
    selected_item = self.tree.selection()
    if not selected_item:
      return None
    return self.visible_record_locations.get(selected_item[0])

  def cancel_inline_edit(self):
    if self.inline_editor is not None:
      editor = self.inline_editor
      self.inline_editor = None
      editor.destroy()

  def begin_inline_edit(self, event):
    row_id = self.tree.identify_row(event.y)
    column_id = self.tree.identify_column(event.x)
    if not row_id:
      return

    self.tree.selection_set(row_id)
    self.tree.focus(row_id)
    if not column_id:
      return "break"

    column_index = int(column_id[1:]) - 1
    if not 0 <= column_index < len(self.displayed_headers):
      return "break"

    header = self.displayed_headers[column_index]
    if header.casefold() in ("stock in", "usecase", "record date"):
      self.status_label.configure(
          text=(
              "Date labels and movement history are read-only. Use the "
              "calendar or stock movement actions to change them."
          ),
          text_color="#57606A",
      )
      return "break"
    if header.casefold() == "current stock":
      self.cancel_inline_edit()
      self.open_stock_unit_details(row_id)
      return "break"

    self.begin_cell_edit(row_id, column_index)
    return "break"

  def begin_cell_edit(self, row_id, column_index):
    self.cancel_inline_edit()
    self.tree.selection_set(row_id)
    self.tree.focus(row_id)
    self.tree.see(row_id)
    self.scroll_column_into_view(column_index)
    self.tree.update_idletasks()
    bounds = self.tree.bbox(row_id, f"#{column_index + 1}")
    if not bounds:
      return

    x, y, width, height = bounds
    header = self.displayed_headers[column_index]
    date_value, record_index = self.visible_record_locations[row_id]
    records = self.storage.get_all_records(date_value)
    if not 0 <= record_index < len(records):
      return
    current_value = str(records[record_index].get(header, "") or "")
    column_values = self.storage.get_column_values(header, date_value)
    numeric = is_numeric_column(header, column_values)
    widget_scale = self.top_bar._get_widget_scaling()
    editor = InventoryFieldInput(
        self.tree,
        header,
        value=current_value,
        choices=column_values,
        width=round(width / widget_scale),
        height=round(height / widget_scale),
        numeric=numeric,
    )
    editor.place(
        x=round(x / widget_scale),
        y=round(y / widget_scale),
    )
    self.inline_editor = editor

    def commit_edit(_event=None, navigation=None):
      if self.inline_editor is not editor:
        return
      value = editor.get()
      next_cell = (
          self.get_adjacent_editable_cell(
              row_id, column_index, navigation
          )
          if navigation
          else None
      )
      if navigation and next_cell is None:
        return
      self.inline_editor = None
      editor.destroy()
      location = self.visible_record_locations.get(row_id)
      if location is None:
        return

      date_value, record_index = location
      can_navigate = value == current_value
      if value != current_value:
        if self.storage.update_record(
            record_index, {header: value}, date_value
        ):
          can_navigate = True
          self.refresh_live_table()
          self.status_label.configure(
              text=f"Updated {header}.", text_color="#1A7F37"
          )
        else:
          self.status_label.configure(
              text=(
                  "Update rejected. Numeric fields must be non-negative; "
                  "tracked Current Stock cannot be reduced directly—use "
                  "Record Usage to select the unit IDs being issued."
              ),
              text_color="#CF222E",
          )
      if navigation and can_navigate:
        self.after_idle(
            lambda target=next_cell: self.begin_cell_edit(*target)
        )

    editor.on_change = commit_edit

    def cancel_edit(_event=None):
      if self.inline_editor is editor:
        self.cancel_inline_edit()

    def commit_after_focus_change(_event=None):
      def commit_when_ready():
        if self.inline_editor is not editor:
          return
        if editor.calendar_open:
          self.after(100, commit_when_ready)
          return
        focused_widget = self.focus_get()
        if focused_widget is not None and str(focused_widget).startswith(
            str(editor)
        ):
          return
        if editor.dropdown_is_open:
          return
        commit_edit()

      self.after(150, commit_when_ready)

    def commit_or_accept_dropdown(event=None):
      if editor.dropdown_is_open:
        editor.accept_dropdown_selection()
      commit_edit(event)

    def handle_vertical_arrow(event, direction):
      if editor.move_dropdown_selection(direction):
        return "break"
      commit_edit(event, navigation=direction)
      return "break"

    editor.bind("<Return>", commit_or_accept_dropdown)
    editor.bind(
        "<Tab>",
        lambda event: (commit_edit(event, navigation="tab-forward"), "break")[1],
    )
    editor.bind(
        "<Shift-Tab>",
        lambda event: (commit_edit(event, navigation="tab-backward"), "break")[1],
    )
    editor.bind(
        "<Left>",
        lambda event: (commit_edit(event, navigation="left"), "break")[1],
    )
    editor.bind(
        "<Right>",
        lambda event: (commit_edit(event, navigation="right"), "break")[1],
    )
    editor.bind(
        "<Up>",
        lambda event: handle_vertical_arrow(event, "up"),
    )
    editor.bind(
        "<Down>",
        lambda event: handle_vertical_arrow(event, "down"),
    )
    editor.bind("<FocusOut>", commit_after_focus_change)
    editor.bind("<Escape>", cancel_edit)
    editor.focus_set()

  def scroll_column_into_view(self, column_index):
    if not self.displayed_headers:
      return
    total_width = self.tree.column("#0", "width")
    target_width = None
    for index, header in enumerate(self.displayed_headers):
      width = self.tree.column(header, "width")
      if index == column_index:
        target_width = width
        break
      total_width += width
    if target_width is None:
      return
    total_width += sum(
        self.tree.column(header, "width")
        for header in self.displayed_headers[column_index:]
    )
    viewport_width = self.tree.winfo_width()
    if total_width <= viewport_width:
      return

    first_fraction, last_fraction = self.tree.xview()
    current_left = first_fraction * total_width
    current_right = last_fraction * total_width
    target_left = sum(
        self.tree.column(header, "width")
        for header in self.displayed_headers[:column_index]
    ) + self.tree.column("#0", "width")
    target_right = target_left + target_width
    desired_left = current_left
    if target_left < current_left:
      desired_left = target_left
    elif target_right > current_right:
      desired_left = target_right - viewport_width
    if desired_left != current_left:
      self.tree.xview_moveto(
          max(0, min(1, desired_left / total_width))
      )

  def get_adjacent_editable_cell(self, row_id, column_index, direction):
    rows = list(self.tree.get_children())
    if not rows or row_id not in rows or not self.displayed_headers:
      return None
    row_index = rows.index(row_id)
    column_count = len(self.displayed_headers)
    non_editable = {"record date", "stock in", "usecase"}
    if direction in ("tab-forward", "tab-backward"):
      step = 1 if direction == "tab-forward" else -1
      total_cells = len(rows) * column_count
      position = row_index * column_count + column_index
      for offset in range(1, total_cells):
        candidate = (position + step * offset) % total_cells
        candidate_row, candidate_column = divmod(candidate, column_count)
        if self.displayed_headers[candidate_column].casefold() not in non_editable:
          return rows[candidate_row], candidate_column
      return None

    row_step, column_step = {
        "left": (0, -1),
        "right": (0, 1),
        "up": (-1, 0),
        "down": (1, 0),
    }.get(direction, (0, 0))
    candidate_row = row_index + row_step
    candidate_column = column_index + column_step
    while (
        0 <= candidate_row < len(rows)
        and 0 <= candidate_column < column_count
    ):
      if self.displayed_headers[candidate_column].casefold() not in non_editable:
        return rows[candidate_row], candidate_column
      candidate_row += row_step
      candidate_column += column_step
    return None

  def add_table_row(self):
    success, message = self.storage.save_row({}, self.selected_date)
    self.status_label.configure(
        text=message,
        text_color="#1A7F37" if success else "#CF222E",
    )
    if not success:
      return
    self.update_date_dropdown()
    self.rebuild_ui()
    rows = self.tree.get_children()
    if not rows:
      return
    first_editable = next(
        (
            index
            for index, header in enumerate(self.displayed_headers)
            if header.casefold() not in (
                "record date",
                "sr no",
                "stock in",
                "usecase",
            )
        ),
        None,
    )
    if first_editable is not None:
      self.tree.selection_set(rows[-1])
      self.begin_cell_edit(rows[-1], first_editable)

  def add_column(self):
    dialog = ctk.CTkInputDialog(
        text="Enter a name for the new column:",
        title="Add Column",
    )
    col_name = dialog.get_input()
    if col_name is None:
      return
    success, msg = self.storage.add_column(col_name, self.selected_date)
    if success:
      self.visible_columns.add(col_name)
      self.rebuild_ui()
      self.status_label.configure(text=msg, text_color="#1A7F37")
    else:
      self.status_label.configure(text=msg, text_color="#CF222E")

  def delete_column(self):
    selected_col = self.col_dropdown.get()
    if selected_col == "No custom cols":
      self.status_label.configure(
          text="No deletable columns.", text_color="#CF222E"
      )
      return

    success, msg = self.storage.delete_column(selected_col, self.selected_date)
    if success:
      self.rebuild_ui()
      self.status_label.configure(text=msg, text_color="#1A7F37")
    else:
      self.status_label.configure(text=msg, text_color="#CF222E")

  def delete_selected(self):
    location = self.get_selected_location()
    if location is None:
      self.status_label.configure(
          text="Select a row in table to remove.", text_color="#CF222E"
      )
      return

    date_value, index = location
    if self.storage.delete_record(index, date_value):
      self.refresh_live_table()
      self.status_label.configure(text="Record removed.", text_color="#1A7F37")

  def open_stock_unit_details(self, row_id):
    location = self.visible_record_locations.get(row_id)
    if location is None:
      return
    date_value, index = location
    success, units_or_message = self.storage.get_stock_units(date_value, index)
    if not success:
      self.status_label.configure(
          text=units_or_message, text_color="#CF222E"
      )
      return
    self.update_undo_button()
    record = self.storage.get_all_records(date_value)[index]
    item_name = next(
        (
            str(record.get(header))
            for header in ("Component Description", "Part Number")
            if record.get(header) not in (None, "")
        ),
        "Selected item",
    )

    def save_units(units):
      saved, message = self.storage.save_stock_units(
          date_value, index, units
      )
      self.status_label.configure(
          text=message,
          text_color="#1A7F37" if saved else "#CF222E",
      )
      if saved:
        self.rebuild_ui()
      return saved

    UnitDetailsDialog(self, item_name, units_or_message, save_units)

  def record_usage_selected(self):
    location = self.get_selected_location()
    if location is None:
      self.status_label.configure(
          text="Select a component row to record usage.",
          text_color="#CF222E",
      )
      return

    date_value, index = location
    record = self.storage.get_all_records(date_value)[index]

    item_name = next(
        (
            str(record.get(header))
            for header in ("Component Description", "Part Number")
            if record.get(header) not in (None, "")
        ),
        "Selected item",
    )
    current_stock = self.storage.get_remaining_stock(record)
    unit_success, units_or_message = self.storage.get_stock_units(
        date_value, index
    )
    if not unit_success:
      self.status_label.configure(
          text=units_or_message, text_color="#CF222E"
      )
      return
    self.update_undo_button()
    available_units = [
        unit
        for unit in units_or_message
        if unit.get("Status") == "In Stock"
    ]

    def save_usage(unit_ids, recipient):
      quantity = str(len(unit_ids))
      success, message = self.storage.record_usage(
          date_value, index, quantity, recipient, unit_ids
      )
      self.status_label.configure(
          text=message,
          text_color="#1A7F37" if success else "#CF222E",
      )
      if success:
        self.rebuild_ui()
      return success

    RecordUsageDialog(
        self,
        item_name,
        current_stock,
        save_usage,
        available_units,
        self.storage.get_usage_recipients(date_value),
    )

  def record_stock_in_selected(self):
    location = self.get_selected_location()
    if location is None:
      self.status_label.configure(
          text="Select a component row to record stock in.",
          text_color="#CF222E",
      )
      return

    date_value, index = location
    def save_stock_in(quantity):
      success, message = self.storage.record_stock_in(
          date_value, index, quantity
      )
      self.status_label.configure(
          text=message,
          text_color="#1A7F37" if success else "#CF222E",
      )
      if success:
        self.rebuild_ui()
      return success

    StockInDialog(self, save_stock_in)

  def export_excel(self):
    ExcelDesignDialog(self, self.export_excel_design)

  def export_excel_design(self, design):
    success, msg = self.storage.export_excel(
        self.range_start_date if self.range_mode else self.selected_date,
        design=design,
        end_date=self.range_end_date if self.range_mode else None,
    )
    color = "#1A7F37" if success else "#CF222E"
    self.status_label.configure(text=msg, text_color=color)
    return success

  def import_excel(self):
    filepath = filedialog.askopenfilename(
        parent=self,
        title="Import Excel workbook",
        filetypes=(
            ("Excel workbooks", "*.xlsx *.xlsm"),
            ("All files", "*.*"),
        ),
    )
    if not filepath:
      return

    existing_records = self.storage.get_all_records(self.selected_date)
    import_mode = "merge"
    if existing_records:
      choice = messagebox.askyesnocancel(
          "Import Excel Workbook",
          (
              f"There are already {len(existing_records)} inventory rows for "
              f"{self.selected_date}.\n\n"
              "Yes: Merge the new rows below the existing rows.\n"
              "No: Replace all existing rows with the new workbook.\n"
              "Cancel: Keep the current inventory unchanged."
          ),
          parent=self,
      )
      if choice is None:
        return
      import_mode = "merge" if choice else "replace"

    success, msg = self.storage.import_excel(
        filepath, self.selected_date, mode=import_mode
    )
    if success:
      self.update_date_dropdown()
      self.rebuild_ui()
    color = "#1A7F37" if success else "#CF222E"
    self.status_label.configure(text=msg, text_color=color)

  def undo_last_action(self):
    undo_date = self.get_undo_date()
    success, msg = self.storage.undo_last_action(undo_date)
    if success:
      self.update_date_dropdown()
      self.rebuild_ui()
    color = "#1A7F37" if success else "#CF222E"
    self.status_label.configure(text=msg, text_color=color)

  def clear_live_data(self):
    confirmed = messagebox.askyesno(
        "Clear Live Data",
        (
          f"This will save a backup of {self.selected_date}'s JSON, "
          "then empty the active inventory while keeping its JSON file. "
          "The backup will not be removed. Data for other dates will not "
          "be affected.\n\nContinue?"
      ),
      parent=self,
    )
    if not confirmed:
      return

    success, msg = self.storage.clear_date_data(self.selected_date)
    if success:
      self.update_date_dropdown()
      self.rebuild_ui()
    color = "#1A7F37" if success else "#CF222E"
    self.status_label.configure(text=msg, text_color=color)

  def delete_selected_json(self):
    confirmed = messagebox.askyesno(
        "Delete JSON File",
        (
            f"This will permanently delete the active JSON file for "
            f"{self.selected_date}. Existing backups will be kept, but the "
            "active file cannot be restored using Undo.\n\nDelete this JSON?"
        ),
        icon="warning",
        parent=self,
    )
    if not confirmed:
      return

    password = simpledialog.askstring(
        "Confirm JSON Deletion",
        "Enter your app password to create an encrypted backup and delete this JSON file.",
        show="*",
        parent=self,
    )
    if password is None:
      return
    try:
      success, message = self.storage.delete_date_json(
          self.selected_date, password
      )
    except (OSError, ValueError, json.JSONDecodeError) as error:
      success = False
      message = f"Unable to verify the app password: {error}"
    if success:
      self.update_date_dropdown()
      self.rebuild_ui()
    self.status_label.configure(
        text=message,
        text_color="#1A7F37" if success else "#CF222E",
    )

  def open_backups(self):
    backups = self.storage.get_backups(self.selected_date)
    BackupRestoreDialog(
        self,
        self.selected_date,
        backups,
        self.restore_selected_backup,
    )

  def restore_selected_backup(self, backup_path):
    if not messagebox.askyesno(
        "Restore Inventory Backup",
        (
            f"Restore {os.path.basename(backup_path)} to "
            f"{self.selected_date}? Existing live data will be backed up first."
        ),
        parent=self,
    ):
      return False

    success, message = self.storage.restore_backup(
        self.selected_date, backup_path
    )
    if success:
      self.update_date_dropdown()
      self.rebuild_ui()
    self.status_label.configure(
        text=message,
        text_color="#1A7F37" if success else "#CF222E",
    )
    return success

if __name__ == "__main__":
  ctk.set_appearance_mode("Light")
  if os.name == "nt":
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
        "MaterialTracker.Inventory"
    )
  # Keep the shared Tcl interpreter alive until process exit; CustomTkinter
  # may still have deferred callbacks when its windows are closed.
  auth_root = tk.Tk()
  auth_root.withdraw()
  login = LoginWindow(auth_root)
  auth_root.mainloop()
  if login.authenticated:
    app = App(
        auth_root,
        login.auth_manager,
        login.data_encryption,
        login.authenticated_username,
    )
    auth_root.mainloop()