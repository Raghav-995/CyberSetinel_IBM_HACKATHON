from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
import yfinance as yf

@tool(name='get_income_statement', description="a tool that returns the income statement given stock ticker"
      ,permission=ToolPermission.ADMIN)
def get_income_statement(stock_ticker:str):
    data = yf.Ticker(stock_ticker)
    return data.quarterly_income_stmt