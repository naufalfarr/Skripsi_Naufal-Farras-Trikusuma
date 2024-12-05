from graphviz import Digraph

# Create a directed graph
flowchart = Digraph(format='png', name="Randomness Analyzer Flowchart")

# Nodes
flowchart.node("Start", "Start")
flowchart.node("LoadCiphertext", "Load Ciphertext List")
flowchart.node("IterateCiphertext", "Iterate through Ciphertext")
flowchart.node("CheckCiphertext", "Is Ciphertext Non-Empty?")
flowchart.node("CleanHex", "Clean & Validate Hex String")
flowchart.node("ConvertToBytes", "Convert Hex String to Bytes")
flowchart.node("AnalyzeRandomness", "Analyze Randomness")
flowchart.node("Entropy", "Calculate Shannon Entropy")
flowchart.node("ChiSquare", "Perform Chi-Square Test")
flowchart.node("PlotDistribution", "Plot Byte Distribution")
flowchart.node("DisplayResults", "Display Results")
flowchart.node("HandleError", "Handle Conversion Error")
flowchart.node("End", "End")

# Edges
flowchart.edge("Start", "LoadCiphertext")
flowchart.edge("LoadCiphertext", "IterateCiphertext")
flowchart.edge("IterateCiphertext", "CheckCiphertext")
flowchart.edge("CheckCiphertext", "CleanHex", label="Yes")
flowchart.edge("CheckCiphertext", "End", label="No")
flowchart.edge("CleanHex", "ConvertToBytes")
flowchart.edge("ConvertToBytes", "AnalyzeRandomness", label="Success")
flowchart.edge("ConvertToBytes", "HandleError", label="Failure")
flowchart.edge("AnalyzeRandomness", "Entropy")
flowchart.edge("AnalyzeRandomness", "ChiSquare")
flowchart.edge("Entropy", "DisplayResults")
flowchart.edge("ChiSquare", "DisplayResults")
flowchart.edge("DisplayResults", "PlotDistribution")
flowchart.edge("PlotDistribution", "IterateCiphertext")
flowchart.edge("HandleError", "IterateCiphertext")
flowchart.edge("IterateCiphertext", "End", label="All Ciphertexts Processed")

# Render flowchart
flowchart_filepath = "/mnt/data/Randomness_Analyzer_Flowchart"
flowchart.render(flowchart_filepath, format="png", cleanup=True)

flowchart_filepath + ".png"
