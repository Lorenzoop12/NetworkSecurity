import pandas as pd

# SYN dell'ancora
df = pd.read_csv("syn.csv", sep=";")
anchor = df[(df["ip.ttl"] == 63) &
            (df["tcp.window_size_value"] == 65535) &
            (df["tcp.options.mss_val"] == 1400) &
            (df["tcp.options.wscale.shift"] == 10)]
print(len(anchor))

# Richieste HTTP
df_http = pd.read_csv("http.csv", sep=";", header=None, names=["tcp.stream", "line"])
df_http[["n", "hex"]] = df_http["line"].str.extract(r"X-Trace:\s*(\d)-([0-9a-f]{6})")

mine = df_http[df_http["tcp.stream"].isin(anchor["tcp.stream"])]
print(len(mine))

mine = mine.sort_values("n")
print(mine[["tcp.stream", "n", "hex"]])

pieces = mine.drop_duplicates("n").sort_values("n")["hex"]
token = "".join(pieces)
print(len(token), token)