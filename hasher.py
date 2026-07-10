import hashlib
import base64
import os
import time
from dataclasses import dataclass, field


@dataclass
class HashResult:
    algorithm: str
    hash_value: str
    salt: str
    time_taken: float
    params: dict = field(default_factory=dict)


class PasswordHasher:
    @staticmethod
    def hash_bcrypt(password: str, rounds: int = 12) -> HashResult:
        try:
            import bcrypt
            start = time.perf_counter()
            salt = bcrypt.gensalt(rounds=rounds)
            hashed = bcrypt.hashpw(password.encode(), salt)
            elapsed = time.perf_counter() - start
            return HashResult(
                algorithm="bcrypt",
                hash_value=hashed.decode(),
                salt=salt.decode(),
                time_taken=elapsed,
                params={"rounds": rounds},
            )
        except ImportError:
            raise ImportError("bcrypt is required. Install with: pip install bcrypt")

    @staticmethod
    def hash_argon2(password: str, memory_cost: int = 19456,
                    time_cost: int = 2, parallelism: int = 1) -> HashResult:
        try:
            from argon2 import PasswordHasher as Argon2Hasher
            ph = Argon2Hasher(memory_cost=memory_cost, time_cost=time_cost,
                              parallelism=parallelism)
            start = time.perf_counter()
            hash_value = ph.hash(password)
            elapsed = time.perf_counter() - start
            return HashResult(
                algorithm="argon2",
                hash_value=hash_value,
                salt="argon2-salt-internal",
                time_taken=elapsed,
                params={"memory_cost": memory_cost, "time_cost": time_cost,
                        "parallelism": parallelism},
            )
        except ImportError:
            raise ImportError("argon2-cffi is required. Install with: pip install argon2-cffi")

    @staticmethod
    def hash_pbkdf2(password: str, iterations: int = 600000) -> HashResult:
        salt = os.urandom(16)
        start = time.perf_counter()
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        elapsed = time.perf_counter() - start
        return HashResult(
            algorithm="pbkdf2_sha256",
            hash_value=base64.b64encode(dk).decode(),
            salt=base64.b64encode(salt).decode(),
            time_taken=elapsed,
            params={"iterations": iterations, "dklen": len(dk)},
        )

    def verify(self, algorithm: str, password: str, hash_value: str, salt: str,
               **params) -> bool:
        if algorithm == "bcrypt":
            import bcrypt
            try:
                return bcrypt.checkpw(password.encode(), hash_value.encode())
            except ValueError:
                return False
        elif algorithm == "pbkdf2_sha256":
            iterations = params.get("iterations", 600000)
            salt_bytes = base64.b64decode(salt)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, iterations)
            return base64.b64encode(dk).decode() == hash_value
        elif algorithm == "argon2":
            from argon2 import PasswordHasher as Argon2Hasher
            ph = Argon2Hasher()
            try:
                return ph.verify(hash_value, password)
            except Exception:
                return False
        raise ValueError(f"Unknown algorithm: {algorithm}")

    def benchmark(self, password: str) -> list[dict]:
        results = []
        for algo in ["pbkdf2_sha256", "bcrypt", "argon2"]:
            try:
                if algo == "bcrypt":
                    r = self.hash_bcrypt(password, rounds=10)
                elif algo == "argon2":
                    r = self.hash_argon2(password, memory_cost=1024, time_cost=1)
                else:
                    r = self.hash_pbkdf2(password, iterations=10000)
                results.append({"algorithm": algo, "time_seconds": r.time_taken})
            except ImportError:
                results.append({"algorithm": algo, "error": "not installed"})
        return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Password Hasher")
    parser.add_argument("--password", required=True, help="Password to hash")
    parser.add_argument("--algorithm", choices=["bcrypt", "argon2", "pbkdf2"],
                        default="bcrypt", help="Hashing algorithm")
    args = parser.parse_args()

    hasher = PasswordHasher()
    algo_map = {"bcrypt": hasher.hash_bcrypt, "argon2": hasher.hash_argon2,
                "pbkdf2": hasher.hash_pbkdf2}
    result = algo_map[args.algorithm](args.password)
    print(f"Algorithm: {result.algorithm}")
    print(f"Hash: {result.hash_value}")
    print(f"Salt: {result.salt}")
    print(f"Time: {result.time_taken:.4f}s")
    print(f"Params: {result.params}")


if __name__ == "__main__":
    main()
