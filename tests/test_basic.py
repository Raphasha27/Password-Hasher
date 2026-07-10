import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hasher import PasswordHasher


class TestPasswordHasher(unittest.TestCase):
    def setUp(self):
        self.hasher = PasswordHasher()

    def test_hash_pbkdf2_returns_result(self):
        result = self.hasher.hash_pbkdf2("testpassword123")
        self.assertEqual(result.algorithm, "pbkdf2_sha256")
        self.assertTrue(len(result.hash_value) > 0)
        self.assertTrue(len(result.salt) > 0)
        self.assertGreater(result.time_taken, 0)

    def test_hash_pbkdf2_different_salts(self):
        r1 = self.hasher.hash_pbkdf2("samepass")
        r2 = self.hasher.hash_pbkdf2("samepass")
        self.assertNotEqual(r1.salt, r2.salt)
        self.assertNotEqual(r1.hash_value, r2.hash_value)

    def test_verify_pbkdf2_correct(self):
        result = self.hasher.hash_pbkdf2("mypassword", iterations=10000)
        valid = self.hasher.verify("pbkdf2_sha256", "mypassword",
                                    result.hash_value, result.salt, iterations=10000)
        self.assertTrue(valid)

    def test_verify_pbkdf2_wrong(self):
        result = self.hasher.hash_pbkdf2("correctpw", iterations=10000)
        valid = self.hasher.verify("pbkdf2_sha256", "wrongpw",
                                    result.hash_value, result.salt, iterations=10000)
        self.assertFalse(valid)

    def test_verify_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            self.hasher.verify("unknown_algo", "pw", "hash", "salt")

    def test_benchmark_returns_results(self):
        results = self.hasher.benchmark("benchtest")
        self.assertGreater(len(results), 0)
        algos = [r["algorithm"] for r in results]
        self.assertIn("pbkdf2_sha256", algos)


if __name__ == "__main__":
    unittest.main()
