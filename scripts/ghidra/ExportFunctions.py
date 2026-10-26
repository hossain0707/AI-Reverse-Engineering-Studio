#@category ARES Studio
# Ghidra's Jython script: Export only bounded function names and decompiled fragments.
# This script is intentionally limited in count and output size.
from ghidra.app.decompiler import DecompInterface
import json

args = getScriptArgs()
if not args:
    raise ValueError("Missing export destination")
output = args[0]
program = currentProgram
fm = program.getFunctionManager()
funcs = fm.getFunctions(True)
decomp = DecompInterface()
decomp.openProgram(program)
results = []
try:
    while funcs.hasNext() and len(results) < 60 and not monitor.isCancelled():
        function = funcs.next()
        record = {"name": str(function.getName()), "address": str(function.getEntryPoint()), "decompiled": ""}
        try:
            response = decomp.decompileFunction(function, 8, monitor)
            if response.decompileCompleted():
                content = response.getDecompiledFunction()
                if content is not None:
                    record["decompiled"] = str(content.getC())[:1800]
        except Exception:
            pass
        results.append(record)
finally:
    decomp.dispose()
with open(output, 'w') as handle:
    handle.write(json.dumps(results))
