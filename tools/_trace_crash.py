import sys
import os

with open(os.path.join(os.path.dirname(__file__), "_trace.log"), "w", encoding="utf-8") as f:
    f.write("Step 1: Imports starting\n")
    
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "guardian")))

    try:
        from guardrails.input_filter import InputFilter
        f.write("Step 2: InputFilter imported\n")
        f.flush()
        
        from guardrails.ai_firewall import AIPromptFirewall
        f.write("Step 3: AIPromptFirewall imported\n")
        f.flush()
        
        from guardrails.encoding_detector import EncodingDetector
        f.write("Step 4: EncodingDetector imported\n")
        f.flush()
    except Exception as e:
        f.write(f"Import error: {e}\n")
        import traceback
        f.write(traceback.format_exc())
        f.flush()
        sys.exit(1)

    try:
        filter_obj = InputFilter()
        f.write("Step 5: InputFilter created\n")
        f.flush()
        
        fw_obj = AIPromptFirewall()
        f.write("Step 6: AIPromptFirewall created\n")
        f.flush()
    except Exception as e:
        f.write(f"Init error: {e}\n")
        import traceback
        f.write(traceback.format_exc())
        f.flush()
        sys.exit(1)

    f.write("Step 7: Testing hello world\n")
    r1 = filter_obj.check_prompt("hello world")
    f.write(f"InputFilter says: {r1}\n")
    
    r2 = fw_obj.is_malicious("hello world", mode="balanced")
    f.write(f"AIFirewall says: {r2}\n")
    f.write("ALL OK\n")
