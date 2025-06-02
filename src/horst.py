import os
import hashlib
import pickle
import argparse
from typing import List, Tuple


class Horst:
    """
    HORST one-time signature scheme with file signing support.

    Attributes:
        h (int): Height of the HORST Merkle tree.
        k (int): Number of leaves to reveal in each signature.
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
        self.t = 1 << height  # Total leaf count = 2^h

    class Signature:
        """
        Represents a HORST signature, containing k leaf secrets and their authentication paths.
        """

        def __init__(self, indices: List[int], secrets: List[bytes], auth_paths: List[List[bytes]]):
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

    class PublicKey:
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

    class PrivateKey:
        """
        Private key for HORST, containing all leaf secret values and the Merkle tree.
        """

        def __init__(self, secrets: List[bytes], tree: List[List[bytes]]):
            """
            Initializes the HORST private key object.

            Args:
                secrets (List[bytes]): List of all leaf secret values.
                tree (List[List[bytes]]): Full Merkle tree as list of levels (level 0 = leaves).
            """
            self.secrets = secrets
            self.tree = tree

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

    def _build_tree(self, leaf_hashes: List[bytes]) -> List[List[bytes]]:
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
            # Pair adjacent nodes to compute each parent hash
            for i in range(0, len(current), 2):
                parent = self._hash(current[i] + current[i + 1])
                next_level.append(parent)
            tree.append(next_level)
            current = next_level
        return tree

    def keygen(self) -> Tuple["Horst.PrivateKey", "Horst.PublicKey"]:
        """
        Generates a HORST key pair.

        Returns:
            Tuple[Horst.PrivateKey, Horst.PublicKey]: Private and public key pair.
        """
        # Generate t random 32-byte secrets (one per leaf)
        secrets = [os.urandom(32) for _ in range(self.t)]
        # Compute leaf hashes = H(secret)
        leaf_hashes = [self._hash(s) for s in secrets]
        # Build full Merkle tree from these leaf hashes
        tree = self._build_tree(leaf_hashes)
        # Public key is the root hash (top of the tree)
        pk = Horst.PublicKey(root=tree[-1][0])
        # Private key stores all secrets and entire tree
        sk = Horst.PrivateKey(secrets=secrets, tree=tree)
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

    def sign(self, sk: "Horst.PrivateKey", message: bytes) -> "Horst.Signature":
        """
        Signs a message with the HORST private key.

        Args:
            sk (Horst.PrivateKey): HORST private key.
            message (bytes): Message bytes to sign.

        Returns:
            Horst.Signature: Generated signature object.
        """
        # Compute digest of the message
        digest = self._hash(message)
        # Determine which k leaves to reveal
        indices = self._expand_indices(digest)

        secrets = []
        auth_paths = []
        for idx in indices:
            # Collect the secret for this leaf
            secrets.append(sk.secrets[idx])
            # Build authentication path from leaf to root
            path = []
            node_index = idx
            for level in range(self.h):
                sibling = node_index ^ 1  # sibling index = flip last bit
                path.append(sk.tree[level][sibling])
                node_index //= 2  # move up to parent
            auth_paths.append(path)

        return Horst.Signature(indices, secrets, auth_paths)

    def verify(self, pk: "Horst.PublicKey", message: bytes, signature: "Horst.Signature") -> bool:
        """
        Verifies a HORST signature.

        Args:
            pk (Horst.PublicKey): HORST public key.
            message (bytes): Signed message bytes.
            signature (Horst.Signature): Signature to verify.

        Returns:
            bool: True if valid, False otherwise.
        """
        # Recompute digest and expected indices
        digest = self._hash(message)
        expected_indices = self._expand_indices(digest)
        # Check that the signature used the correct indices
        if expected_indices != signature.indices:
            return False

        for idx, secret, path in zip(signature.indices, signature.secrets, signature.auth_paths):
            # Start with hash of the provided secret
            node_hash = self._hash(secret)
            node_index = idx
            # Recompute path up to the root
            for sibling_hash in path:
                if node_index % 2 == 0:
                    node_hash = self._hash(node_hash + sibling_hash)
                else:
                    node_hash = self._hash(sibling_hash + node_hash)
                node_index //= 2
            # At the end, node_hash must equal the public root
            if node_hash != pk.root:
                return False

        return True

    def sign_file(self, sk: "Horst.PrivateKey", filepath: str) -> "Horst.Signature":
        """
        Signs the entire contents of a file.

        Args:
            sk (Horst.PrivateKey): HORST private key.
            filepath (str): Path to the file to be signed.

        Returns:
            Horst.Signature: Generated signature over the file's contents.
        """
        with open(filepath, 'rb') as f:
            data = f.read()
        return self.sign(sk, data)

    def verify_file(self, pk: "Horst.PublicKey", filepath: str, signature: "Horst.Signature") -> bool:
        """
        Verifies a signature against the contents of a file.

        Args:
            pk (Horst.PublicKey): HORST public key.
            filepath (str): Path to the file whose signature to verify.
            signature (Horst.Signature): Signature object to verify.

        Returns:
            bool: True if signature is valid for the file, False otherwise.
        """
        with open(filepath, 'rb') as f:
            data = f.read()
        return self.verify(pk, data, signature)

    @staticmethod
    def save_signature_and_key(pk: "Horst.PublicKey",
                               signature: "Horst.Signature",
                               out_path: str) -> None:
        """
        Saves the public key and signature together into a single file using pickle.

        Args:
            pk (Horst.PublicKey): Public key object.
            signature (Horst.Signature): Signature object.
            out_path (str): Path to the file where both will be saved.
        """
        bundle = {
            'public_key': pk,
            'signature': signature
        }
        with open(out_path, 'wb') as f:
            pickle.dump(bundle, f)

    @staticmethod
    def load_signature_and_key(bundle_path: str) -> Tuple["Horst.PublicKey", "Horst.Signature"]:
        """
        Loads the public key and signature from a bundle file.

        Args:
            bundle_path (str): Path to the bundle file containing public key and signature.

        Returns:
            Tuple[Horst.PublicKey, Horst.Signature]: Loaded public key and signature.
        """
        with open(bundle_path, 'rb') as f:
            bundle = pickle.load(f)
        return bundle['public_key'], bundle['signature']

    def verify_file_with_bundle(self, filepath: str, bundle_path: str) -> bool:
        """
        Loads a public key and signature from a bundle and verifies it against a file.

        Args:
            filepath (str): Path to the file whose signature to verify.
            bundle_path (str): Path to the bundle file (contains public key + signature).

        Returns:
            bool: True if the signature matches the file contents, False otherwise.
        """
        pk, signature = Horst.load_signature_and_key(bundle_path)
        return self.verify_file(pk, filepath, signature)


def main():
    parser = argparse.ArgumentParser(description="HORST file signer/verifier")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subparser for "sign" command
    sign_parser = subparsers.add_parser(
        "sign", help="Sign a file and bundle its signature + public key"
    )
    sign_parser.add_argument(
        "file", help="Path to the file to sign"
    )
    sign_parser.add_argument(
        "--out", "-o",
        help="Output bundle path (default: <file>_signed.pkl)",
        default=None
    )

    # Subparser for "verify" command
    verify_parser = subparsers.add_parser(
        "verify", help="Verify a file against a signature+key bundle"
    )
    verify_parser.add_argument(
        "file", help="Path to the file to verify"
    )
    verify_parser.add_argument(
        "bundle", help="Path to the bundle file containing public key + signature"
    )

    args = parser.parse_args()

    horst = Horst()  # Use default height=16, k=32

    if args.command == "sign":
        input_path = args.file
        if not os.path.isfile(input_path):
            print(f"Error: file '{input_path}' does not exist.")
            return

        # Determine output bundle path
        if args.out:
            bundle_path = args.out
        else:
            bundle_path = f"{input_path}_signed.pkl"

        # Generate a fresh key pair
        sk, pk = horst.keygen()

        # Sign the file contents
        signature = horst.sign_file(sk, input_path)

        # Save public key + signature into a single bundle
        Horst.save_signature_and_key(pk, signature, bundle_path)
        print(f"Signed bundle saved to: {bundle_path}")

    elif args.command == "verify":
        input_path = args.file
        bundle_path = args.bundle

        if not os.path.isfile(input_path):
            print(f"Error: file '{input_path}' does not exist.")
            return
        if not os.path.isfile(bundle_path):
            print(f"Error: bundle file '{bundle_path}' does not exist.")
            return

        # Verify using the bundle (loads public key + signature)
        result = horst.verify_file_with_bundle(input_path, bundle_path)
        print(result)  # True или False


if __name__ == "__main__":
    main()
