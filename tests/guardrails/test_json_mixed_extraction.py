from typing import Dict, Optional
import logging

logger = logging.getLogger("test_logger")

def _extract_prompt(data: Dict) -> Optional[str]:
    if not data:
        return None
        
    extracted_strings = []
    
    def _recursive_extract(node):
        if isinstance(node, str):
            extracted_strings.append(node)
        elif isinstance(node, dict):
            for value in node.values():
                _recursive_extract(value)
        elif isinstance(node, list):
            for item in node:
                _recursive_extract(item)
                
    try:
        _recursive_extract(data)
    except Exception as e:
        logger.error(f"Error during recursive prompt extraction (Potential structural payload bypass attempt): {e}")
        pass
    
    if extracted_strings:
        return " \n ".join(extracted_strings)
        
    return None

def test_mixed_type_extraction():
    payload = {
        "model": "gpt-4",
        "temperature": 0.5,
        "max_tokens": 100,
        "stream": False,
        "mixed_array": [10, True, None, {"key": "malicious string hidden here"}, 4.5],
        "messages": [
            {"role": "user", "content": "hello"}
        ]
    }
    
    print(f"Extracting mixed type payload: {payload}")
    extracted = _extract_prompt(payload)
    
    print("\n--- Extracted Prompt ---")
    print(extracted)
    
    if extracted and "malicious string hidden here" in extracted and "0.5" not in extracted and "10" not in extracted:
        print("\n[SUCCESS] Mixed-type parsing gracefully pulled strings and ignored other primitive types.")
    else:
        print("\n[FAILED] Extraction logic did not behave as expected.")

if __name__ == "__main__":
    test_mixed_type_extraction()
