"""
pike.py — учебная реализация алгоритма шифрования «PIKE»
(ECB, 64-битные блоки, 128-битный ключ, 32 раунда).

Реализовано:
- pike_encrypt_block / pike_decrypt_block — шифрование/дешифрование одного 64-битного блока
- ECB + PKCS#7 для произвольной длины данных
- Ввод ключа в HEX (16 байт = 32 hex-символа), вывод шифртекста в hex
- Графический интерфейс на tkinter/ttk с 3 полями:
  1) исходный текст -> 2) шифртекст (hex) -> 3) расшифрованный текст
"""

from __future__ import annotations

from typing import Tuple

# --- Константы алгоритма ---
DELTA = 0x9E3779B9  # константа PIKE (используется в каждом раунде)
BLOCK_SIZE = 8      # 64 бита
KEY_SIZE = 16       # 128 бит

# Ключ по умолчанию (ASCII "PIKE" повторён 4 раза = 16 байт)
DEFAULT_KEY_BYTES = (b"PIKE" * 4)
DEFAULT_KEY_HEX = DEFAULT_KEY_BYTES.hex().upper()


# --- Вспомогательные функции для u32/байтов ---
def _u32(x: int) -> int:
    """Ограничение до 32 бит (по модулю 2^32)."""
    return x & 0xFFFFFFFF


def _split_u32_be(block8: bytes) -> Tuple[int, int]:
    """Разбить 8 байт на две 32-битные части (Big-Endian)."""
    if len(block8) != BLOCK_SIZE:
        raise ValueError("block8 должен быть ровно 8 байт (64 бита).")
    left = int.from_bytes(block8[0:4], "big")
    right = int.from_bytes(block8[4:8], "big")
    return left, right


def _join_u32_be(left: int, right: int) -> bytes:
    """Собрать две 32-битные части в 8 байт (Big-Endian)."""
    return _u32(left).to_bytes(4, "big") + _u32(right).to_bytes(4, "big")


def _key_u32_be(key16: bytes) -> Tuple[int, int, int, int]:
    """Разбить ключ 16 байт на 4 32-битных подключа (Big-Endian)."""
    if len(key16) != KEY_SIZE:
        raise ValueError("key16 должен быть ровно 16 байт (128 бит).")
    return (
        int.from_bytes(key16[0:4], "big"),
        int.from_bytes(key16[4:8], "big"),
        int.from_bytes(key16[8:12], "big"),
        int.from_bytes(key16[12:16], "big"),
    )


# --- PKCS#7 ---
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Некорректная длина данных для PKCS#7 unpad.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Некорректный PKCS#7 padding (длина).")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Некорректный PKCS#7 padding (содержимое).")
    return data[:-pad_len]


# --- Блочное шифрование/дешифрование ---
def pike_encrypt_block(block8: bytes, key16: bytes, rounds: int = 32) -> bytes:
    """
    Шифрование одного 64-битного блока.
    """
    left, right = _split_u32_be(block8)
    k0, k1, k2, k3 = _key_u32_be(key16)

    s = 0
    for _ in range(rounds):
        s = _u32(s + DELTA)
        left = _u32(left + (((right << 4) + k0) ^ (right + s) ^ ((right >> 5) + k1)))
        right = _u32(right + (((left << 4) + k2) ^ (left + s) ^ ((left >> 5) + k3)))

    return _join_u32_be(left, right)


def pike_decrypt_block(block8: bytes, key16: bytes, rounds: int = 32) -> bytes:
    """
    Дешифрование одного 64-битного блока.
    """
    left, right = _split_u32_be(block8)
    k0, k1, k2, k3 = _key_u32_be(key16)

    s = _u32(DELTA * rounds)
    for _ in range(rounds):
        right = _u32(right - (((left << 4) + k2) ^ (left + s) ^ ((left >> 5) + k3)))
        left = _u32(left - (((right << 4) + k0) ^ (right + s) ^ ((right >> 5) + k1)))
        s = _u32(s - DELTA)

    return _join_u32_be(left, right)


def ecb_encrypt(data: bytes, key16: bytes, rounds: int = 32) -> bytes:
    """ECB шифрование произвольных данных (PKCS#7 + блоки по 8 байт)."""
    data = pkcs7_pad(data, BLOCK_SIZE)
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        out += pike_encrypt_block(data[i:i + BLOCK_SIZE], key16, rounds)
    return bytes(out)


def ecb_decrypt(data: bytes, key16: bytes, rounds: int = 32) -> bytes:
    """ECB дешифрование (блоки по 8 байт + снятие PKCS#7)."""
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Длина шифртекста должна быть кратна 8 байтам (64 бита).")
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        out += pike_decrypt_block(data[i:i + BLOCK_SIZE], key16, rounds)
    return pkcs7_unpad(bytes(out), BLOCK_SIZE)


# --- Утилиты ввода/вывода (hex ключ/данные) ---
def _strip_spaces(s: str) -> str:
    return "".join(s.split())


def parse_key(key_input: str) -> bytes:
    """
    Ключ ожидается в hex (32 hex-символа). Если поле пустое — берём ключ по умолчанию.
    """
    k = _strip_spaces(key_input)
    if not k:
        return DEFAULT_KEY_BYTES
    if len(k) != 32:
        raise ValueError("Ключ должен быть в HEX и иметь длину 32 символа (16 байт).")
    try:
        key_bytes = bytes.fromhex(k)
    except ValueError as e:
        raise ValueError("Ключ должен быть в шестнадцатеричном формате (0-9, a-f).") from e
    if len(key_bytes) != KEY_SIZE:
        raise ValueError("Ключ должен быть ровно 16 байт.")
    return key_bytes


def parse_hex_data(hex_text: str) -> bytes:
    h = _strip_spaces(hex_text)
    if not h:
        raise ValueError("Пустые данные.")
    if len(h) % 2 != 0:
        raise ValueError("Hex-строка должна иметь чётную длину.")
    try:
        return bytes.fromhex(h)
    except ValueError as e:
        raise ValueError("Данные должны быть в hex-формате.") from e


def encrypt_text_to_hex(plain_text: str, key_hex: str) -> str:
    key = parse_key(key_hex)
    data = plain_text.encode("utf-8")
    ct = ecb_encrypt(data, key)
    return ct.hex().upper()


def decrypt_hex_to_text(cipher_hex: str, key_hex: str) -> str:
    key = parse_key(key_hex)
    ct = parse_hex_data(cipher_hex)
    pt = ecb_decrypt(ct, key)
    return pt.decode("utf-8", errors="replace")


# --- GUI на tkinter/ttk ---
def launch_gui() -> None:
    import tkinter as tk
    from tkinter import ttk, messagebox
    from tkinter.scrolledtext import ScrolledText

    root = tk.Tk()
    root.title("PIKE (ECB) — шифрование/расшифрование")

    # Верхняя панель: ключ
    key_frame = ttk.Frame(root, padding=10)
    key_frame.grid(row=0, column=0, sticky="ew")
    key_frame.columnconfigure(1, weight=1)

    ttk.Label(key_frame, text="Ключ (HEX, 32 символа; пусто = по умолчанию):").grid(row=0, column=0, sticky="w")
    key_entry = ttk.Entry(key_frame)
    key_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))

    hint = ttk.Label(key_frame, text=f"Ключ по умолчанию: {DEFAULT_KEY_HEX}", foreground="#444")
    hint.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))

    # Основная зона: 3 поля
    main = ttk.Frame(root, padding=(10, 0, 10, 10))
    main.grid(row=1, column=0, sticky="nsew")
    root.rowconfigure(1, weight=1)
    root.columnconfigure(0, weight=1)

    main.columnconfigure(0, weight=1)
    main.columnconfigure(1, weight=1)
    main.columnconfigure(2, weight=1)
    main.rowconfigure(1, weight=1)

    ttk.Label(main, text="1) Открытый текст (ввод):").grid(row=0, column=0, sticky="w")
    ttk.Label(main, text="2) Шифртекст (hex):").grid(row=0, column=1, sticky="w")
    ttk.Label(main, text="3) Расшифрованный текст:").grid(row=0, column=2, sticky="w")

    plain_box = ScrolledText(main, wrap="word", height=12)
    cipher_box = ScrolledText(main, wrap="word", height=12)
    decrypted_box = ScrolledText(main, wrap="word", height=12)

    plain_box.grid(row=1, column=0, sticky="nsew", padx=(0, 8), pady=(6, 0))
    cipher_box.grid(row=1, column=1, sticky="nsew", padx=(0, 8), pady=(6, 0))
    decrypted_box.grid(row=1, column=2, sticky="nsew", pady=(6, 0))

    # Кнопки
    btns = ttk.Frame(root, padding=(10, 0, 10, 10))
    btns.grid(row=2, column=0, sticky="ew")

    def _get_key_bytes() -> bytes:
        return parse_key(key_entry.get())

    def on_encrypt() -> None:
        try:
            key = _get_key_bytes()
            text_in = plain_box.get("1.0", "end").rstrip("\n")
            if not text_in:
                raise ValueError("Введите открытый текст в поле №1.")
            ct_hex = ecb_encrypt(text_in.encode("utf-8"), key).hex().upper()
            cipher_box.delete("1.0", "end")
            cipher_box.insert("1.0", ct_hex)

            # Очищаем поле расшифровки при новом шифровании
            decrypted_box.delete("1.0", "end")

            messagebox.showinfo("Успех", "Шифрование выполнено. Шифртекст записан в поле №2 (hex).")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def on_decrypt() -> None:
        try:
            key = _get_key_bytes()
            hex_in = cipher_box.get("1.0", "end").strip()
            if not _strip_spaces(hex_in):
                raise ValueError("Введите шифртекст (hex) в поле №2.")
            ct = parse_hex_data(hex_in)
            pt = ecb_decrypt(ct, key).decode("utf-8", errors="replace")
            decrypted_box.delete("1.0", "end")
            decrypted_box.insert("1.0", pt)
            messagebox.showinfo("Успех", "Расшифрование выполнено. Результат записан в поле №3.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def on_reset() -> None:
        plain_box.delete("1.0", "end")
        cipher_box.delete("1.0", "end")
        decrypted_box.delete("1.0", "end")

    ttk.Button(btns, text="Шифровать (1→2)", command=on_encrypt).grid(row=0, column=0, sticky="w")
    ttk.Button(btns, text="Расшифровать (2→3)", command=on_decrypt).grid(row=0, column=1, sticky="w", padx=(8, 0))
    ttk.Button(btns, text="Сбросить", command=on_reset).grid(row=0, column=2, sticky="w", padx=(8, 0))
    ttk.Button(btns, text="Выход", command=root.destroy).grid(row=0, column=3, sticky="e", padx=(8, 0))

    root.minsize(1200, 450)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
