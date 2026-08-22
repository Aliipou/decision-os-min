import sys
from pathlib import Path

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "examples"))

from adversarial_novapulse import run_scenario

out = root / ".pytest-basetemp" / "novapulse_live"
out.mkdir(parents=True, exist_ok=True)
r = run_scenario(str(out / "audit.jsonl"))
print("INFRA:", r["question"]["infrastructure_grade_claim"])
print("sealed_execute_without_chain:", r["question"]["can_adversary_execute_without_legit_auth_pep_chain_on_sealed_surface"])
print("ambient_python_bypass:", r["question"]["can_adversary_execute_via_ambient_unsealed_python"])
print("--- cases ---")
for k, v in r["cases"].items():
    print(f"{k}: ok={v['ok']}")
print("--- matrix ---")
for k, v in r["matrix"].items():
    print(f"{v['status']:8} {k}")
