from ibm_watsonx_orchestrate.agent_builder.knowledge_bases.knowledge_base import KnowledgeBase

# MITRE ATT&CK Knowledge Base
mitre_knowledge_base = KnowledgeBase(
   name="mitre_attack_knowledge_base",
   description="Get comprehensive knowledge of MITRE ATT&CK framework, tactics, techniques, and procedures for cybersecurity threat analysis",
   documents=["knowledge_bases/mitre.pdf"],
   vector_index={
      "embeddings_model_name": "ibm/slate-125m-english-rtrvr-v2"
   }
)

# CVE Knowledge Base
cve_knowledge_base = KnowledgeBase(
   name="cve_knowledge_base", 
   description="Access detailed information about Common Vulnerabilities and Exposures (CVE) database for security vulnerability identification and analysis",
   documents=["knowledge_bases/cve.pdf"],
   vector_index={
      "embeddings_model_name": "ibm/slate-125m-english-rtrvr-v2"
   }
)

owasp_top_10_knowledge_base = KnowledgeBase(
   name="owasp_top_10_knowledge_base", 
   description="Access detailed information about Common Vulnerabilities and Exposures (CVE) database for security vulnerability identification and analysis",
   documents=["knowledge_bases/owasptop10.pdf"],
   vector_index={
      "embeddings_model_name": "ibm/slate-125m-english-rtrvr-v2"
   }
)

