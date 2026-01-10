
ALPHABET = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
DEFAULT_KEY = PIKE

def extend_key(text, key)
    res = 
    j = 0
    for ch in text
        if ch in ALPHABET
            res += key[j % len(key)]
            j += 1
        else
            res += ch
    return res

def vigenere_encrypt(text, key)
    key = extend_key(text, key)
    result = 
    for t, k in zip(text, key)
        if t in ALPHABET
            ti = ALPHABET.index(t)
            ki = ALPHABET.index(k)
            result += ALPHABET[(ti + ki) % len(ALPHABET)]
        else
            result += t
    return result

def vigenere_decrypt(text, key)
    key = extend_key(text, key)
    result = 
    for t, k in zip(text, key)
        if t in ALPHABET
            ti = ALPHABET.index(t)
            ki = ALPHABET.index(k)
            result += ALPHABET[(ti - ki) % len(ALPHABET)]
        else
            result += t
    return result

def second_layer_encrypt(text)
    res = 
    for i, ch in enumerate(text[-1])
        if ch in ALPHABET
            res += ALPHABET[(ALPHABET.index(ch) + i) % len(ALPHABET)]
        else
            res += ch
    return res

def second_layer_decrypt(text)
    temp = 
    for i, ch in enumerate(text)
        if ch in ALPHABET
            temp += ALPHABET[(ALPHABET.index(ch) - i) % len(ALPHABET)]
        else
            temp += ch
    return temp[-1]

def encrypt(text, key)
    step1 = vigenere_encrypt(text, key)
    step2 = second_layer_encrypt(step1)
    return step2

def decrypt(text, key)
    step1 = second_layer_decrypt(text)
    step2 = vigenere_decrypt(step1, key)
    return step2

def menu()
    print(n=== PIKE+ ===)
    print(1 — Шифровать)
    print(2 — Расшифровать)
    print(0 — Выход)
    choice = input(Выбор )

    if choice == 0
        return False

    key = input(Введите ключ (Enter = PIKE) )
    if not key
        key = DEFAULT_KEY

    text = input(Введите текст )

    if choice == 1
        print(Результат, encrypt(text, key))
    elif choice == 2
        print(Результат, decrypt(text, key))
    else
        print(Неверный выбор)

    return True

if __name__ == __main__
    while menu()
        pass


