import os
import hashlib
from typing import List, Tuple


class HorstSignature:
    """
    Represents a HORST signature, containing k leaf secrets and their authentication paths.
    """

    def __init__(self,
                 indices: List[int],
                 secrets: List[bytes],
                 auth_paths: List[List[bytes]]):
        """
        Initializes the HORST signature object.

        Args:
            indices (List[int]): List of leaf indices selected for this signature.
            secrets (List[bytes]): List of k secret values for the selected leaves.
            auth_paths (List[List[bytes]]): List of authentication paths for each selected leaf.
        """
        self.indices = indices
        self.secrets = secrets
        self.auth_paths = auth_paths


class HorstPublicKey:
    """
    Public key for HORST, namely the root of the Merkle tree.
    """

    def __init__(self, root: bytes):
        """
        Initializes the HORST public key object.

        Args:
            root (bytes): Root hash of the HORST Merkle tree.
        """
        self.root = root


class HorstPrivateKey:
    """
    Private key for HORST, containing all leaf secret values and the Merkle tree.
    """

    def __init__(self,
                 secrets: List[bytes],
                 tree: List[List[bytes]]):
        """
        Initializes the HORST private key object.

        Args:
            secrets (List[bytes]): List of all leaf secret values.
            tree (List[List[bytes]]): Full Merkle tree as list of levels (level 0 = leaves).
        """
        self.secrets = secrets
        self.tree = tree


class Horst:
    """
    HORST one-time signature scheme based on a Merkle hash tree.

    Attributes:
        h (int): Height of the HORST tree.
        k (int): Number of leaves to reveal in the signature.
        t (int): Total number of leaves (2^h).
    """

    def __init__(self, height: int = 16, k: int = 32):
        """
        Initializes the HORST scheme parameters.

        Args:
            height (int): Height of the HORST tree (default 16 => 65536 leaves).
            k (int): Number of leaves to reveal in the signature (default 32).
        """
        self.h = height
        self.k = k
        self.t = 1 << height

    @staticmethod
    def _hash(data: bytes) -> bytes:
        """
        Computes the SHA-256 hash of the input data.

        Args:
            data (bytes): Input data to hash.

        Returns:
            bytes: SHA-256 hash digest.
        """
        return hashlib.sha256(data).digest()

    def _build_tree(self,
                    leaf_hashes: List[bytes]) -> List[List[bytes]]:
        """
        Builds a Merkle tree from the given leaf hashes.

        Args:
            leaf_hashes (List[bytes]): List of hashes for the leaves.

        Returns:
            List[List[bytes]]: Tree levels, where level 0 is leaves and level h is root.
        """
        tree = [leaf_hashes]
        current = leaf_hashes
        for _ in range(self.h):
            next_level = []
            for i in range(0, len(current), 2):
                parent = self._hash(current[i] + current[i + 1])
                next_level.append(parent)
            tree.append(next_level)
            current = next_level
        return tree

    def keygen(self) -> Tuple[HorstPrivateKey, HorstPublicKey]:
        """
        Generates a HORST key pair.

        Returns:
            Tuple[HorstPrivateKey, HorstPublicKey]: Private and public key pair.
        """
        secrets = [os.urandom(32) for _ in range(self.t)]
        leaf_hashes = [self._hash(s) for s in secrets]
        tree = self._build_tree(leaf_hashes)
        pk = HorstPublicKey(root=tree[-1][0])
        sk = HorstPrivateKey(secrets=secrets, tree=tree)
        return sk, pk

    def _expand_indices(self, digest: bytes) -> List[int]:
        """
        Expands a fixed-size message digest into k unique HORST leaf indices using a hash-chain.

        This function appends a 4-byte big-endian counter to the original digest,
        hashes the concatenation, and takes the first 4 bytes of the result (masked
        to the tree size) as an index. It repeats until k unique indices are collected.

        Args:
            digest (bytes): SHA-256 digest of the message to be signed.

        Returns:
            List[int]: List of k unique leaf indices.
        """
        indices = []
        seen = set()
        counter = 0
        while len(indices) < self.k:
            ctr_bytes = counter.to_bytes(4, 'big')
            h = self._hash(digest + ctr_bytes)
            idx = int.from_bytes(h[:4], 'big') & (self.t - 1)
            if idx not in seen:
                seen.add(idx)
                indices.append(idx)
            counter += 1
        return indices

    def sign(self,
             sk: HorstPrivateKey,
             message: bytes) -> HorstSignature:
        """
        Signs a message with the HORST private key.

        Args:
            sk (HorstPrivateKey): HORST private key.
            message (bytes): Message bytes to sign.

        Returns:
            HorstSignature: Generated signature object.
        """
        digest = self._hash(message)
        indices = self._expand_indices(digest)
        secrets = []
        auth_paths = []
        for idx in indices:
            secrets.append(sk.secrets[idx])
            path = []
            node_index = idx
            for level in range(self.h):
                sibling = node_index ^ 1
                path.append(sk.tree[level][sibling])
                node_index //= 2
            auth_paths.append(path)
        return HorstSignature(indices, secrets, auth_paths)

    def verify(self,
               pk: HorstPublicKey,
               message: bytes,
               signature: HorstSignature) -> bool:
        """
        Verifies a HORST signature.

        Args:
            pk (HorstPublicKey): HORST public key.
            message (bytes): Signed message bytes.
            signature (HorstSignature): Signature to verify.

        Returns:
            bool: True if valid, False otherwise.
        """
        digest = self._hash(message)
        expected_indices = self._expand_indices(digest)
        if expected_indices != signature.indices:
            return False
        for idx, secret, path in zip(signature.indices, signature.secrets, signature.auth_paths):
            node_hash = self._hash(secret)
            node_index = idx
            for sibling_hash in path:
                if node_index % 2 == 0:
                    node_hash = self._hash(node_hash + sibling_hash)
                else:
                    node_hash = self._hash(sibling_hash + node_hash)
                node_index //= 2
            if node_hash != pk.root:
                return False
        return True


# if __name__ == "__main__":
#     horst = Horst(height=16, k=32)
#     sk, pk = horst.keygen()
#     msg = b"test test test"
#     sig = horst.sign(sk, msg)
#     valid = horst.verify(pk, msg, sig)
#     print(f"Signature valid: {valid}")
