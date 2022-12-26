# Ghidra plugin that asks OpenAI Chat GPT (https://chat.openai.com/chat) to explain functions! :)
# @author evyatar9 (https://github.com/evyatar9)
# @category API
# @keybinding Ctrl-Alt-G
# @menupath Tools.GptHidra
# @toolbar

import requests
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface

# Get your API key from https://beta.openai.com/account/api-keys
API_KEY = ''


def explainFunction(c_code):
    response = requests.post(
        "https://api.openai.com/v1/completions",
        headers={"Authorization": "Bearer {}".format(API_KEY)},
        json={"prompt": "Explain this code:\r\n" + c_code, "max_tokens": 2048, "model": "text-davinci-003"},
    )
    return response.json()["choices"][0]["text"]


def getCurrentDecompiledFunction():
    # Reference: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html

    # Create a TaskMonitor object
    monitor = TaskMonitor.DUMMY

    # Create a DecompInterface object
    decompiler = DecompInterface()

    # Set the current program for the decompiler
    decompiler.openProgram(currentProgram)

    # Get the current address and the function containing it
    currentAddress = currentLocation.getAddress()
    functionName = getFunctionContaining(currentAddress)

    # Decompile the function and get the resulting C code
    return decompiler.decompileFunction(functionName, 30, monitor).getDecompiledFunction().getC()

try:
    c_code = getCurrentDecompiledFunction()
    print(explainFunction(c_code))
except Exception as e:
    print(e)