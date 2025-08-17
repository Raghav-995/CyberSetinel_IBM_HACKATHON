from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
import yfinance as yf

@tool(name='get_stock_price', description="a tool that returns the last stock price given a stock name",permission=ToolPermission.ADMIN)
def stock_price(stock_ticker:str):
    data = yf.Ticker(stock_ticker)
    prices = data.history(period='1mo')
    return prices['Close'].iloc[-1]