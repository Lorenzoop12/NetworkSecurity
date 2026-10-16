import asyncio

HOST, PORT = None, 9001

store: dict[str, str] = {}


def process(line: bytes) -> str:
    if not all(0x20 <= b <= 0x7E for b in line):
        return "ERR"
    text = line.decode("ascii")
    cmd, sep, rest = text.partition(" ")

    if cmd == "PING":
        return "PONG" if not sep else "ERR"

    if cmd == "ECHO":
        return rest

    if cmd == "SET":
        key, sep2, value = rest.partition(" ")
        if not sep or not key or not sep2 or value == "":
            return "ERR"
        store[key] = value
        return "OK"

    if cmd == "GET":
        if not sep or not rest or " " in rest:
            return "ERR"
        return store.get(rest, "NOT_FOUND")

    return "ERR"


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            try:
                raw = await reader.readuntil(b"\n")
            except asyncio.IncompleteReadError:
                break
            except asyncio.LimitOverrunError:
                writer.write(b"ERR\n")
                await writer.drain()
                break
            writer.write(process(raw[:-1]).encode("ascii") + b"\n")
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def main():
    server = await asyncio.start_server(
        handle, HOST, PORT
    )
    print(f"Listening on {server.sockets}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass