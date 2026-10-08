"""OWASP LLM Top 10 mapping for RedLens."""

from .category_utils import canonical_category

OWASP_MAPPING = {
    "prompt_injection": {
        "id": "LLM01",
        "name": "Prompt Injection",
    },
    "jailbreak": {
        "id": "LLM01",
        "name": "Prompt Injection",
    },
    "cybercrime": {
        "id": "LLM01",
        "name": "Prompt Injection",
    },

    "data_extraction": {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
    },
    "privacy": {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
    },

    "supply_chain": {
        "id": "LLM03",
        "name": "Supply Chain",
    },

    "data_poisoning": {
        "id": "LLM04",
        "name": "Data and Model Poisoning",
    },

    "output_handling": {
        "id": "LLM05",
        "name": "Improper Output Handling",
    },

    "excessive_agency": {
        "id": "LLM06",
        "name": "Excessive Agency",
    },

    "system_prompt_leakage": {
        "id": "LLM07",
        "name": "System Prompt Leakage",
    },

    "vector_embedding": {
        "id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
    },

    "misinformation": {
        "id": "LLM09",
        "name": "Misinformation",
    },

    "unbounded_consumption": {
        "id": "LLM10",
        "name": "Unbounded Consumption",
    },
}


def get_owasp_mapping(category):
    """Return OWASP information for a RedLens category.

    Uses canonical_category() so dataset spelling variants of the same
    category (e.g. "weapon" / "weapons") are treated as one category
    instead of silently fragmenting into separate UNMAPPED buckets.
    This does NOT add any new category->OWASP mappings.
    """
    category = canonical_category(category)

    return OWASP_MAPPING.get(
        category,
        {
            "id": "UNMAPPED",
            "name": "Unmapped",
        },
    )


def get_all_owasp_categories():
    """Return all OWASP LLM Top 10 categories."""
    return [
        {
            "id": f"LLM{i:02d}",
            "name": name,
        }
        for i, name in [
            (1, "Prompt Injection"),
            (2, "Sensitive Information Disclosure"),
            (3, "Supply Chain"),
            (4, "Data and Model Poisoning"),
            (5, "Improper Output Handling"),
            (6, "Excessive Agency"),
            (7, "System Prompt Leakage"),
            (8, "Vector and Embedding Weaknesses"),
            (9, "Misinformation"),
            (10, "Unbounded Consumption"),
        ]
    ]