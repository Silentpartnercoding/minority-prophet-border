import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_neutral_border_never_imports_provider_implementations(self):
        violations = []
        for source_path in sorted((ROOT / "border").glob("*.py")):
            tree = ast.parse(source_path.read_text(), filename=str(source_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                if any(name == "providers" or name.startswith("providers.") for name in names):
                    violations.append(f"{source_path.name}:{node.lineno}")
        self.assertEqual([], violations)

    def test_passive_language_is_limited_to_witness_behavior(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("admission path is\nactive and fail-closed", readme)
        self.assertIn("witness path is observational and non-blocking", readme)
        self.assertIn("exception never converts failed admission into valid authority", readme)

    def test_readme_states_the_contract_directly(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("defines a portable admission record for one exact\nagent action", readme)
        self.assertIn("The provider-independent contract", readme)


if __name__ == "__main__":
    unittest.main()
