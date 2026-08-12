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
    
    print("[Proxy] Starting Rizin MCP Server...")
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as mcp_session:
            await mcp_session.initialize()
            print("[Proxy] MCP Session initialized successfully!")
            
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
                    "content": "You are a top-tier malware analysis expert. Please effectively use Rizin and capa tools to analyze binary files, systematically explore, and uncover critical threat indicators."
                },
                {
                    "role": "user", 
                    "content": "Please help me analyze test_file.bin in the current directory. Load it first, then use capa to analyze its malicious features and perform decompilation."
                }
            ]
            
            while True:
                print(f"\n[Proxy] Sending conversation and tools to LLM ({MODEL_NAME})...")
                response = nv_client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    tools=nv_tools if nv_tools else None,
                    tool_choice="auto" if nv_tools else None
                )
                
                response_message = response.choices[0].message
                messages.append(response_message)
                
                if not response_message.tool_calls:
                    print("\n[Final AI Analysis Report]:")
                    print(response_message.content)
                    break
                    
                for tool_call in response_message.tool_calls:
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)
                    
                    print(f"🤖 [AI Decision] Calling tool: {tool_name}")
                    print(f"📦 [Argument contents] {tool_args}")
                    
                    server_result = await mcp_session.call_tool(tool_name, arguments=tool_args)
                    result_text = "".join([
                        content_item.text for content_item in server_result.content if hasattr(content_item, 'text')
                    ])
                    
                    print(f"[Proxy] Execution successful (Result length: {len(result_text)} chars)")
                    
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
