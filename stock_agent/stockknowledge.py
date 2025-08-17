# from ibm_watsonx_orchestrate.agent_builder.agents import Agent
# from ibm_watsonx_orchestrate.agent_builder.knowledge_bases.knowledge_base import KnowledgeBase

# # First create the knowledge base
# knowledge_base = KnowledgeBase(
#     name="my_knowledge_base_name",
#     description="Knowledge base description",
#     documents=["orchestrate/Stocks.pdf"]
# )

# # Load existing agent (assuming you have the agent object)
# # If you need to load from file, use appropriate method

# # Method 1: Modify existing agent object
# existing_agent = Agent(
#     name="nicks_stock_agent",  # Same name as existing agent
#     description="Updated agent with knowledge base",
#     instructions="You are a helpful assistant.",
#     knowledge_base=["orchestrate/Stocks.pdf", "orchestrate/stocks.pdf"]  # Add this line
# )

# Method 2: If you have the agent object already loaded
# existing_agent.knowledge_base = ["my_knowledge_base_name"]

from ibm_watsonx_orchestrate.agent_builder.knowledge_bases.knowledge_base import KnowledgeBase

knowledge_base = KnowledgeBase(
   name="knowledge_base_name",
   description="Get the basic knowledge of the stock market, how to invest and get stock",
   documents=["orchestrate/Stocks.pdf", "orchestrate/stocks.pdf"],  # Use relative path if the file is in the same directory
   vector_index={
      "embeddings_model_name": "ibm/slate-125m-english-rtrvr-v2"
   }
)