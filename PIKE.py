"""
pike.py — учебная реализация поточного шифра «PIKE» (вариант 35)

Алгоритм (по индивидуальному заданию):
- 3 генератора на сдвиговых регистрах слов (32-битные слова):
  G1: 55 слов, отводы 24 и 55
  G2: 57 слов, отводы 7 и 57
  G3: 58 слов, отводы 19 и 58
- Управляющие биты C1,C2,C3 — биты переноса сумматоров OR1,OR2,OR3
  (перенос при сложении двух отводов + carry-in генератора).
- Схема синхронизации: сдвигаются те регистры, у которых Ci совпадает с большинством
  (если все три Ci одинаковы — сдвиг всех трёх).
- Сдвиг выполняется с задержкой 8 циклов (решение о сдвиге применяется через 8 тактов).
- Очередное слово гаммы: XOR самых младших слов (Rg55 ⊕ Rg57 ⊕ Rg58).

Шифрование/расшифрование:
- Поточное гаммирование: ciphertext = plaintext XOR keystream
- Расшифрование идентично (XOR тем же потоком гаммы).
- Для удобства в GUI шифртекст выводится в HEX.

Примечание (учебная инициализация):
- Для заполнения регистров из введённого ключевого материала используется SHA-256 в режиме счётчика.
  Это НЕ является частью криптоалгоритма PIKE по ГОСТ/стандарту и применяется только как способ
  получить детерминированное начальное состояние из пользовательского ключа.

"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, Tuple
import hashlib
import string

WORD_MASK = 0xFFFFFFFF
WORD_BYTES = 4


def _u32(x: int) -> int:
    return x & WORD_MASK


def _strip_spaces(s: str) -> str:
    return "".join(s.split())


def _looks_like_hex(s: str) -> bool:
    if not s or len(s) % 2 != 0:
        return False
    hexdigits = set(string.hexdigits)
    return all(ch in hexdigits for ch in s)


def parse_key_material(key_input: str) -> bytes:
    """
    Ключевой материал:
    - если пусто → ключ по умолчанию
    - если похоже на hex → bytes.fromhex(...)
    - иначе → UTF-8 bytes
    """
    key_input = _strip_spaces(key_input)
    if not key_input:
        return (b"PIKE" * 4)  # 16 байт, по умолчанию
    if _looks_like_hex(key_input):
        return bytes.fromhex(key_input)
    return key_input.encode("utf-8")


def expand_key_to_u32_words(key_material: bytes, n_words: int) -> list[int]:
    """
    Детерминированно расширяет key_material до n_words 32-битных слов.
    Используется SHA-256(key || counter).
    """
    out: list[int] = []
    counter = 0
    while len(out) < n_words:
        h = hashlib.sha256(key_material + counter.to_bytes(4, "big")).digest()
        for i in range(0, len(h), 4):
            out.append(int.from_bytes(h[i:i + 4], "big"))
            if len(out) >= n_words:
                break
        counter += 1
    return out


@dataclass
class PikeGenerator:
    """
    Генератор на регистре сдвига слов длиной r и отводом tap.
    Сумматор (ORi) складывает слова Rgtap и Rgr + carry_in,
    перенос (carry_out) используется как управляющий бит Ci.
    """
    r: int
    tap: int  # 1..r
    reg: Deque[int]
    carry: int = 0  # carry_in (0/1)

    def __post_init__(self) -> None:
        if not (1 <= self.tap <= self.r):
            raise ValueError("tap должен быть в диапазоне 1..r")
        if len(self.reg) != self.r:
            raise ValueError("Длина регистра должна быть ровно r слов")
        self.carry &= 1

    def comb_sum_and_carry(self) -> Tuple[int, int]:
        """Комбинаторный расчёт суммы и переноса без изменения состояния."""
        a = self.reg[self.tap - 1]      # Rgtap
        b = self.reg[-1]               # Rgr (самое младшее слово)
        total = a + b + self.carry
        sum_word = total & WORD_MASK
        carry_out = 1 if (total >> 32) else 0
        return sum_word, carry_out

    def control_bit(self) -> int:
        """Текущий управляющий бит Ci = carry_out сумматора."""
        _, c = self.comb_sum_and_carry()
        return c

    def lsw(self) -> int:
        """Самое младшее слово (выход генератора): Rgr."""
        return self.reg[-1]

    def clock(self) -> None:
        """Сдвиг регистра: Rg1 <- sum_word, остальные сдвигаются вправо, обновляется carry."""
        sum_word, carry_out = self.comb_sum_and_carry()
        # Сдвиг вправо: удаляем Rgr и вставляем новое слово в Rg1
        self.reg.pop()
        self.reg.appendleft(sum_word)
        self.carry = carry_out


class PikeStreamCipher:
    """
    Поточный шифр PIKE (вариант 35):
    - 3 генератора
    - majority-clock по Ci
    - задержка 8 циклов
    """

    def __init__(self, key_material: bytes, delay: int = 8):
        self.delay = delay

        # Инициализация регистров (учебная): расширяем ключ до нужного числа слов
        total_words = 55 + 57 + 58
        words = expand_key_to_u32_words(key_material, total_words + 3)

        g1_words = words[0:55]
        g2_words = words[55:55 + 57]
        g3_words = words[55 + 57:55 + 57 + 58]

        # carry берём из ещё 3 слов (LSB)
        c1 = words[-3] & 1
        c2 = words[-2] & 1
        c3 = words[-1] & 1

        self.g1 = PikeGenerator(55, 24, deque((_u32(x) for x in g1_words), maxlen=55), carry=c1)
        self.g2 = PikeGenerator(57, 7, deque((_u32(x) for x in g2_words), maxlen=57), carry=c2)
        self.g3 = PikeGenerator(58, 19, deque((_u32(x) for x in g3_words), maxlen=58), carry=c3)

        # Очередь задержки решений о сдвиге (prefill = сдвиг всех трёх)
        self._shift_queue: Deque[Tuple[bool, bool, bool]] = deque([(True, True, True)] * delay, maxlen=delay)

    @staticmethod
    def _majority(a: int, b: int, c: int) -> int:
        return 1 if (a + b + c) >= 2 else 0

    def _decide_shift_mask(self) -> Tuple[bool, bool, bool]:
        c1 = self.g1.control_bit()
        c2 = self.g2.control_bit()
        c3 = self.g3.control_bit()
        m = self._majority(c1, c2, c3)
        return (c1 == m, c2 == m, c3 == m)

    def next_keystream_word(self) -> int:
        """
        Один такт:
        1) применить решение о сдвиге, принятое delay тактов назад
        2) принять новое решение о сдвиге (по текущим Ci) и положить в очередь
        3) выдать слово гаммы (Rg55 ⊕ Rg57 ⊕ Rg58)
        """
        # 1) применяем задержанное решение
        shift1, shift2, shift3 = self._shift_queue.popleft()
        if shift1:
            self.g1.clock()
        if shift2:
            self.g2.clock()
        if shift3:
            self.g3.clock()

        # 2) новое решение и кладём в очередь
        self._shift_queue.append(self._decide_shift_mask())

        # 3) слово гаммы
        return _u32(self.g1.lsw() ^ self.g2.lsw() ^ self.g3.lsw())

    def keystream_bytes(self, n_bytes: int) -> bytes:
        out = bytearray()
        while len(out) < n_bytes:
            w = self.next_keystream_word()
            out += w.to_bytes(WORD_BYTES, "big")
        return bytes(out[:n_bytes])

    def crypt(self, data: bytes) -> bytes:
        ks = self.keystream_bytes(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))


def encrypt_text_to_hex(plain_text: str, key_input: str) -> str:
    key_material = parse_key_material(key_input)
    cipher = PikeStreamCipher(key_material)
    ct = cipher.crypt(plain_text.encode("utf-8"))
    return ct.hex().upper()


def decrypt_hex_to_text(cipher_hex: str, key_input: str) -> str:
    cipher_hex = _strip_spaces(cipher_hex)
    if not cipher_hex:
        raise ValueError("Пустые данные.")
    if len(cipher_hex) % 2 != 0:
        raise ValueError("Hex-строка должна иметь чётную длину.")
    if not _looks_like_hex(cipher_hex):
        raise ValueError("Данные должны быть в hex-формате (0-9, a-f).")

    key_material = parse_key_material(key_input)
    cipher = PikeStreamCipher(key_material)
    ct = bytes.fromhex(cipher_hex)
    pt = cipher.crypt(ct)
    return pt.decode("utf-8", errors="replace")


# --- GUI на tkinter/ttk (3 поля) ---
def launch_gui() -> None:
    import tkinter as tk
    from tkinter import ttk, messagebox
    from tkinter.scrolledtext import ScrolledText

    root = tk.Tk()
    root.title("PIKE (поточный) — шифрование/расшифрование")

    # Верхняя панель: ключ
    key_frame = ttk.Frame(root, padding=10)
    key_frame.grid(row=0, column=0, sticky="ew")
    key_frame.columnconfigure(1, weight=1)

    ttk.Label(
        key_frame,
        text="Ключ (HEX любой чётной длины ИЛИ текст; пусто = по умолчанию):",
    ).grid(row=0, column=0, sticky="w")
    key_entry = ttk.Entry(key_frame)
    key_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))

    hint = ttk.Label(key_frame, text="По умолчанию: 'PIKE'×4", foreground="#444")
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

    def on_encrypt() -> None:
        try:
            text_in = plain_box.get("1.0", "end").rstrip("\n")
            if not text_in:
                raise ValueError("Введите открытый текст в поле №1.")
            ct_hex = encrypt_text_to_hex(text_in, key_entry.get())
            cipher_box.delete("1.0", "end")
            cipher_box.insert("1.0", ct_hex)

            decrypted_box.delete("1.0", "end")
            messagebox.showinfo("Успех", "Шифрование выполнено. Шифртекст записан в поле №2 (hex).")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def on_decrypt() -> None:
        try:
            hex_in = cipher_box.get("1.0", "end").strip()
            if not _strip_spaces(hex_in):
                raise ValueError("Введите шифртекст (hex) в поле №2.")
            pt = decrypt_hex_to_text(hex_in, key_entry.get())
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
