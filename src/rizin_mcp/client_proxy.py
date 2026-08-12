import os
import json
import asyncio
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

nv_client = OpenAI(
    base_url="https://nvidia.com",
    api_key=os.environ.get("NVIDIA_API_KEY")
)
MODEL_NAME = "meta/llama-3.1-70b-instruct"

async def run_analysis_proxy():
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "-m", "rizin_mcp.server"]
    )
    
    print("[Proxy] 正在啟動 Rizin MCP Server...")
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as mcp_session:
            await mcp_session.initialize()
            print("[Proxy] MCP 會話初始化成功！")
            
            mcp_tools = await mcp_session.list_tools()
            nv_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.inputSchema
                    }
                } for tool in mcp_tools.tools
            ]
            
            messages = [
                {
                    "role": "system", 
                    "content": "你是一個頂尖的惡意程式分析專家。請善用 Rizin 與 capa 工具分析二進位檔案，逐步探索並找出關鍵威脅指標。"
                },
                {
                    "role": "user", 
                    "content": "請幫我分析當前目錄下的 test_file.bin，先載入它，然後使用 capa 分析其惡意特徵並進行反編譯。"
                }
            ]
            
            while True:
                print(f"\n[Proxy] 傳送對話與工具至 LLM ({MODEL_NAME})...")
                response = nv_client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    tools=nv_tools if nv_tools else None,
                    tool_choice="auto" if nv_tools else None
                )
                
                response_message = response.choices[0].message
                messages.append(response_message)
                
                if not response_message.tool_calls:
                    print("\n[AI 最終分析報告]:")
                    print(response_message.content)
                    break
                    
                for tool_call in response_message.tool_calls:
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)
                    
                    print(f"🤖 [AI 決策] 呼叫工具: {tool_name}")
                    print(f"📦 [參數內容] {tool_args}")
                    
                    server_result = await mcp_session.call_tool(tool_name, arguments=tool_args)
                    result_text = "".join([
                        content_item.text for content_item in server_result.content if hasattr(content_item, 'text')
                    ])
                    
                    print(f"[Proxy] 執行成功 (結果長度: {len(result_text)} 字元)")
                    
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": tool_name,
                        "content": result_text
                    })

def main():
    asyncio.run(run_analysis_proxy())

if __name__ == "__main__":
    main()
