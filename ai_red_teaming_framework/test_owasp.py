from src.owasp_mapper import get_owasp_mapping, get_all_owasp_categories

print("Testing RedLens OWASP mapping")
print("--------------------------------")

for category in [
    "jailbreak",
    "prompt_injection",
    "data_extraction",
    "privacy",
    "misinformation",
    "cybercrime",
]:
    result = get_owasp_mapping(category)
    print(category, "->", result["id"], result["name"])

print("\nAll OWASP categories:")
print("--------------------------------")

for item in get_all_owasp_categories():
    print(item["id"], "-", item["name"])

print("\nOWASP mapping test completed.")