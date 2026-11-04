"""Axiom inventory must not omit declarations decorated with Lean attributes."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import proof_registry


class RegistryTests(unittest.TestCase):
    def test_attributes_do_not_hide_theorems_from_axiom_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proof = root / 'proofs'
            proof.mkdir()
            (proof / 'ExampleProofs.lean').write_text('''namespace ExampleProofs
theorem plain : True := by trivial
@[simp] theorem same_line : True := by trivial
@[simp]
@[aesop safe] lemma next_line : True := by trivial
end ExampleProofs
''')
            with patch.object(proof_registry, 'ROOT', root), patch.object(proof_registry, 'PROOFS', proof):
                entries = proof_registry.declarations()
            self.assertEqual([e['name'] for e in entries], [
                'ExampleProofs.plain', 'ExampleProofs.same_line', 'ExampleProofs.next_line'])
            self.assertEqual(proof_registry.audit_source(entries).count('#print axioms '), 3)


if __name__ == '__main__':
    unittest.main()
