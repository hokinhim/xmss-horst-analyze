import os
import hashlib
import hmac
import secrets
import json
from typing import List

class Address:
    def __init__(self):
        # Все поля 32 бита (4 байта)
        self.layer = 0
        self.tree = 0
        self.type = 0
        self.ots = 0
        self.chain = 0
        self.hash = 0
        self.key_and_mask = 0

    def to_bytes(self) -> bytes:
        # Адрес 32 байта (8 полей по 4 байта, здесь только 7 заполнено, добьём нулями)
        parts = [
            self.layer,
            (self.tree >> 24) & 0xFF000000 | (self.tree & 0xFFFFFF),  # tree 64 бит, но для упрощения оставим int
            self.type,
            self.ots,
            self.chain,
            self.hash,
            self.key_and_mask,
            0
        ]
        b = b""
        for part in parts:
            b += part.to_bytes(4, 'big', signed=False)
        return b

    def set_type(self, t: int):
        self.type = t

    def set_ots(self, ots: int):
        self.ots = ots

    def set_chain(self, chain: int):
        self.chain = chain

    def set_hash(self, h: int):
        self.hash = h

    def set_key_and_mask(self, val: int):
        self.key_and_mask = val

class WOTSPlus:
    def __init__(self, n=32, w=16):
        self.n = n  # размер хэша в байтах (обычно 32)
        self.w = w  # параметр Winternitz (обычно 16)
        # вычисляем параметры длины подписи len_1 и len_2 по RFC 8391
        self.len_1 = (8 * n + (w - 1)) // (w.bit_length() - 1)  # количество base_w блоков для сообщения
        self.log_w = (w - 1).bit_length()
        self.len_1 = (8 * n + self.log_w - 1) // self.log_w
        self.len_2 = (self._len_2_calculate())
        self.len = self.len_1 + self.len_2

    def _len_2_calculate(self) -> int:
        # len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1
        import math
        return int((math.floor(math.log(self.len_1 * (self.w - 1), self.w))) + 1)

    def base_w(self, msg: bytes, out_len: int) -> List[int]:
        """Конвертация массива байт в base_w с длиной out_len"""
        total_bits = len(msg) * 8
        bits_per_digit = self.log_w
        msg_bits = int.from_bytes(msg, 'big')
        output = []
        for i in range(out_len):
            shift = total_bits - (i + 1) * bits_per_digit
            if shift < 0:
                output.append(0)
            else:
                val = (msg_bits >> shift) & (self.w - 1)
                output.append(val)
        return output

    def _prf(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def _f(self, key: bytes, data: bytes) -> bytes:
        return hashlib.sha256(key + data).digest()

    def _get_seed(self, sk_seed: bytes, addr: Address) -> bytes:
        # Генерация секретного ключевого элемента с помощью PRF и адреса
        return self._prf(sk_seed, addr.to_bytes())

    def chain(self, seed: bytes, start: int, steps: int, pub_seed: bytes, addr: Address) -> bytes:
        # Последовательное вычисление цепочки хэшей F
        # каждый шаг меняем addr.hash и addr.key_and_mask по стандарту
        out = seed
        for i in range(start, start + steps):
            addr.set_hash(i)
            addr.set_key_and_mask(0)
            key = self._prf(pub_seed, addr.to_bytes())
            addr.set_key_and_mask(1)
            bitmask = self._prf(pub_seed, addr.to_bytes())
            # XOR input с bitmask
            masked = bytes(x ^ y for x, y in zip(out, bitmask))
            out = self._f(key, masked)
        return out

    def wots_gen_pk(self, sk_seed: bytes, pub_seed: bytes, addr: Address) -> List[bytes]:
        pk = []
        for i in range(self.len):
            addr.set_chain(i)
            addr.set_hash(0)
            addr.set_key_and_mask(0)
            sk_element = self._get_seed(sk_seed, addr)
            pk_element = self.chain(sk_element, 0, self.w - 1, pub_seed, addr)
            pk.append(pk_element)
        return pk

    def wots_sign(self, msg: bytes, sk_seed: bytes, pub_seed: bytes, addr: Address) -> List[bytes]:
        # Вычисляем base_w представление сообщения
        msg_base_w = self.base_w(msg, self.len_1)
        csum = 0
        for c in msg_base_w:
            csum += self.w - 1 - c

        csum_len = (self.len_2 * self.log_w + 7) // 8
        csum_bytes = csum.to_bytes(csum_len, 'big')
        csum_base_w = self.base_w(csum_bytes, self.len_2)

        msg_base_w += csum_base_w

        signature = []
        for i, steps in enumerate(msg_base_w):
            addr.set_chain(i)
            addr.set_hash(0)
            addr.set_key_and_mask(0)
            sk_element = self._get_seed(sk_seed, addr)
            sig_element = self.chain(sk_element, 0, steps, pub_seed, addr)
            signature.append(sig_element)
        return signature

    def wots_pk_from_sig(self, sig: List[bytes], msg: bytes, pub_seed: bytes, addr: Address) -> List[bytes]:
        msg_base_w = self.base_w(msg, self.len_1)
        csum = 0
        for c in msg_base_w:
            csum += self.w - 1 - c

        csum_len = (self.len_2 * self.log_w + 7) // 8
        csum_bytes = csum.to_bytes(csum_len, 'big')
        csum_base_w = self.base_w(csum_bytes, self.len_2)

        msg_base_w += csum_base_w

        pk = []
        for i, steps in enumerate(msg_base_w):
            addr.set_chain(i)
            addr.set_hash(0)
            addr.set_key_and_mask(0)
            pk_element = self.chain(sig[i], steps, self.w - 1 - steps, pub_seed, addr)
            pk.append(pk_element)
        return pk

    def pk_compress(self, pk: List[bytes]) -> bytes:
        return hashlib.sha256(b''.join(pk)).digest()


class MerkleTree:
    def __init__(self, leaf_nodes: List[bytes]):
        self.leaves = leaf_nodes
        self.levels = []
        self.build_tree()

    def build_tree(self):
        current_level = self.leaves
        self.levels.append(current_level)
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left
                parent = hashlib.sha256(left + right).digest()
                next_level.append(parent)
            current_level = next_level
            self.levels.append(current_level)

    def get_root(self) -> bytes:
        return self.levels[-1][0] if self.levels else None

    def get_auth_path(self, index: int) -> List[bytes]:
        path = []
        idx = index
        for level in self.levels[:-1]:
            sibling_idx = idx ^ 1
            if sibling_idx < len(level):
                path.append(level[sibling_idx])
            else:
                path.append(level[idx])
            idx >>= 1
        return path


class XMSS:
    def __init__(self, height=4, n=32, private_key_path="private_key.json", public_key_path="public_key.json"):
        self.height = height
        self.n = n
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.wots = WOTSPlus(n=self.n)
        self.max_signatures = 2 ** self.height

        if os.path.exists(self.private_key_path):
            self.load_keys()
            print("Ключи загружены из файла.")
            print(f"Текущий индекс подписи: {self.sk['idx']}")
        else:
            self.generate_keys()
            self.save_keys()
            print("Сгенерированы и сохранены новые ключи.")

    def h(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def prf(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def generate_keys(self):
        sk_seed = secrets.token_bytes(self.n)
        sk_prf = secrets.token_bytes(self.n)
        pub_seed = secrets.token_bytes(self.n)

        leaf_pks = []
        addr = Address()
        addr.set_type(0)  # WOTS+
        for i in range(self.max_signatures):
            addr.set_ots(i)
            pk = self.wots.wots_gen_pk(sk_seed, pub_seed, addr)
            compressed_pk = self.wots.pk_compress(pk)
            leaf_pks.append(compressed_pk)

        tree = MerkleTree(leaf_pks)
        root = tree.get_root()

        self.sk = {
            "SK_SEED": sk_seed,
            "SK_PRF": sk_prf,
            "pub_seed": pub_seed,
            "root": root,
            "idx": 0,
            "tree": tree,
            "auth_path": []
        }
        self.pk = {
            "root": root,
            "pub_seed": pub_seed,
            "height": self.height,
            "n": self.n
        }

    def save_keys(self):
        with open(self.private_key_path, "w") as f:
            json.dump({
                "SK_SEED": self.sk["SK_SEED"].hex(),
                "SK_PRF": self.sk["SK_PRF"].hex(),
                "pub_seed": self.sk["pub_seed"].hex(),
                "root": self.sk["root"].hex(),
                "idx": self.sk["idx"]
            }, f, indent=2)
        with open(self.public_key_path, "w") as f:
            json.dump({
                "root": self.pk["root"].hex(),
                "pub_seed": self.pk["pub_seed"].hex(),
                "height": self.pk["height"],
                "n": self.pk["n"]
            }, f, indent=2)

    def load_keys(self):
        with open(self.private_key_path, "r") as f:
            data = json.load(f)
            self.sk = {
                "SK_SEED": bytes.fromhex(data["SK_SEED"]),
                "SK_PRF": bytes.fromhex(data["SK_PRF"]),
                "pub_seed": bytes.fromhex(data["pub_seed"]),
                "root": bytes.fromhex(data["root"]),
                "idx": data["idx"],
                "tree": None,
                "auth_path": []
            }
        with open(self.public_key_path, "r") as f:
            data = json.load(f)
            self.pk = {
                "root": bytes.fromhex(data["root"]),
                "pub_seed": bytes.fromhex(data["pub_seed"]),
                "height": data["height"],
                "n": data["n"]
            }
        # Восстановим дерево из листов
        leaf_pks = []
        addr = Address()
        addr.set_type(0)
        for i in range(2**self.pk["height"]):
            addr.set_ots(i)
            pk = self.wots.wots_gen_pk(self.sk["SK_SEED"], self.pk["pub_seed"], addr)
            compressed_pk = self.wots.pk_compress(pk)
            leaf_pks.append(compressed_pk)
        self.sk["tree"] = MerkleTree(leaf_pks)

    def sign(self, data: bytes) -> bytes:
        idx = self.sk["idx"]
        if idx >= self.max_signatures:
            raise Exception("Достигнут лимит подписей!")

        idx_bytes = idx.to_bytes(4, "big")
        randomness = self.prf(self.sk["SK_PRF"], idx_bytes)
        msg_hash = self.h(randomness + self.sk["root"] + data)

        addr = Address()
        addr.set_type(0)
        addr.set_ots(idx)

        wots_sig = self.wots.wots_sign(msg_hash, self.sk["SK_SEED"], self.sk["pub_seed"], addr)
        auth_path = self.sk["tree"].get_auth_path(idx)

        sig = idx_bytes + randomness
        for part in wots_sig:
            sig += part
        for node in auth_path:
            sig += node

        self.sk["idx"] += 1
        self.save_keys()
        return sig

    def verify(self, data: bytes, sig: bytes) -> bool:
        idx = int.from_bytes(sig[:4], "big")
        randomness = sig[4:4+self.n]
        msg_hash = self.h(randomness + self.pk["root"] + data)

        addr = Address()
        addr.set_type(0)
        addr.set_ots(idx)

        wots_len = self.wots.len
        wots_sig_bytes = sig[4+self.n:4+self.n + wots_len*self.n]
        auth_path_bytes = sig[4+self.n + wots_len*self.n:]

        wots_sig = [wots_sig_bytes[i*self.n:(i+1)*self.n] for i in range(wots_len)]
        pk_from_sig = self.wots.wots_pk_from_sig(wots_sig, msg_hash, self.pk["pub_seed"], addr)
        leaf = self.wots.pk_compress(pk_from_sig)

        node = leaf
        idx_leaf = idx
        for i in range(self.pk["height"]):
            start = i * self.n
            node_at_level = auth_path_bytes[start:start+self.n]
            if idx_leaf % 2 == 0:
                node = hashlib.sha256(node + node_at_level).digest()
            else:
                node = hashlib.sha256(node_at_level + node).digest()
            idx_leaf >>= 1

        return node == self.pk["root"]

    def sign_file(self, filepath: str):
        with open(filepath, "rb") as f:
            data = f.read()
        sig = self.sign(data)
        with open(filepath + ".sig", "wb") as f:
            f.write(sig)
        print(f"Подпись создана: {filepath}.sig")

    def verify_file(self, filepath: str, sigpath: str):
        with open(filepath, "rb") as f:
            data = f.read()
        with open(sigpath, "rb") as f:
            sig = f.read()
        if self.verify(data, sig):
            print("Подпись действительна.")
        else:
            print("Подпись недействительна.")

def main():
    xmss = XMSS(height=4)  # 16 листьев
    print("\nВыберите действие:")
    print("1 — Подписать файл")
    print("2 — Проверить подпись")
    choice = input("Ваш выбор (1/2): ").strip()

    if choice == '1':
        path = input("Введите путь к файлу для подписи: ").strip()
        xmss.sign_file(path)
    elif choice == '2':
        path = input("Введите путь к файлу: ").strip()
        sig_path = input("Введите путь к файлу подписи (.sig): ").strip()
        xmss.verify_file(path, sig_path)
    else:
        print("Неверный выбор.")

if __name__ == "__main__":
    main()
