import sys
import os

with open(os.path.join(os.path.dirname(__file__), "_trace_fw.log"), "w", encoding="utf-8") as f:
    f.write("Tracing AIPromptFirewall imports...\n")
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "guardian")))
    
    try:
        f.write("1. Importing logging\n")
        f.flush()
        import logging
        
        f.write("2. Importing re\n")
        f.flush()
        import re
        
        f.write("3. Importing collections\n")
        f.flush()
        from collections import OrderedDict
        
        f.write("4. Importing os\n")
        f.flush()
        import os
        
        f.write("5. Importing yaml\n")
        f.flush()
        import yaml
        
        f.write("6. Importing EncodingDetector\n")
        f.flush()
        from guardrails.encoding_detector import EncodingDetector
        
        f.write("7. Importing sentence_transformers\n")
        f.flush()
        from sentence_transformers import SentenceTransformer
        
        f.write("8. Importing sklearn\n")
        f.flush()
        from sklearn.metrics.pairwise import cosine_similarity
        
        f.write("9. Done importing dependencies\n")
        f.flush()
    except Exception as e:
        f.write(f"Import Error: {e}\n")
        f.flush()
