from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
import yfinance as yf

@tool(name='get_stock_info', description="a tool that returns the stock information for given stock ticker"
      ,permission=ToolPermission.ADMIN)
def get_stock_data(stock_ticker:str):
    data = yf.Ticker(stock_ticker)
    return data.info