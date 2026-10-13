#!/usr/bin/env python3
"""mock-vulnbox svc2 — raw TCP echo service (l4-raw), for non-HTTP flow testing."""
import asyncio
import os


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)  # plain echo
            await writer.drain()
    except ConnectionResetError:
        pass
    finally:
        writer.close()


async def main():
    port = int(os.environ.get("SVC2_PORT", 9002))
    server = await asyncio.start_server(handle, "0.0.0.0", port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
