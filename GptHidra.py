# Ghidra plugin that asks OpenAI Chat GPT (https://chat.openai.com/chat) to explain functions (OpenAI's GPT-4).
# @author evyatar9 (https://github.com/evyatar9)
# @category API
# @keybinding Ctrl-Alt-G
# @menupath Tools.GptHidra
# @toolbar

import urllib2
import json
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface

# https://help.openai.com/en/articles/7102672-how-can-i-access-gpt-4
# Get your API key from https://beta.openai.com/account/api-keys
API_KEY = ''

def explainFunction(c_code):
    """
        Calls the OpenAI Chat GPT API to explain the given code.

        Args:
            c_code (str): The code to be explained.

        Returns:
            str: The explanation provided by the API.
    """
    url = 'https://api.openai.com/v1/chat/completions'
    data = {"messages":[ {"role": "user","content":"Explain code:\n" + c_code} ], "model": "gpt-4"}
    data = json.dumps(data)

    req = urllib2.Request(url, data,
                          {'Authorization': 'Bearer ' + API_KEY,
                           'Content-Type': 'application/json'})
    response = json.loads(urllib2.urlopen(req).read())

    if "error" in response:
        raise ValueError(response["error"])
    else:
        return response["choices"][0]["message"]["content"]


def getCurrentDecompiledFunction():
    """
        Returns the C code for the function currently selected in the Ghidra decompiler.

        Returns:
            str: The C code for the selected function.
    """
    # Reference: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html

    # Create a TaskMonitor object
    monitor = TaskMonitor.DUMMY

    # Create a DecompInterface object
    decompiler = DecompInterface()

    # Set the current program for the decompiler
    decompiler.openProgram(currentProgram)

    # Get the current address and the function containing it
    currentAddress = currentLocation.getAddress()
    function = getFunctionContaining(currentAddress)

    if function is None:
        raise ValueError("No function is currently selected.")

    # Decompile the function and get the resulting C code
    try:
        return decompiler.decompileFunction(function, 30, monitor).getDecompiledFunction().getC()
    except Exception as e:
        raise ValueError("Unable to decompile function: " + str(e))

try:
    c_code = getCurrentDecompiledFunction()
    explanation = explainFunction(c_code)
    print(explanation)
	
except ValueError as e:
    print(e)