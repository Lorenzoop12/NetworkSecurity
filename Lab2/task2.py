import pandas as pd

hello = pd.read_csv("hello.csv", sep=";")
print(len(hello))

print(hello.groupby("tls.handshake.ja4").size())

anchor_ja4 = "t13d1516h2_8daaf6152771_9829734ff3cf"
mal = hello[hello["tls.handshake.ja4"] == anchor_ja4].sort_values("frame.time_relative")
print(len(mal))
print(mal[["tcp.stream", "frame.time_relative", "tls.handshake.extensions_server_name"]])

labels = mal["tls.handshake.extensions_server_name"].str.split(".").str[0]
print(labels.tolist())
token = "".join(labels.tolist())

print(f"netsec{{{token}}}")