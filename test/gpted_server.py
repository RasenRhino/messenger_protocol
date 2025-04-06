import asyncio

# Handler for each client connection
async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"[+] New client connected: {addr}")

    try:
        while True:
            data = await reader.read(1024)
            if not data:
                print(f"[-] Client {addr} disconnected")
                break

            message = data.decode().strip()
            print(f"[{addr}] Received: {message}")

            # Echo message back
            response = f"You said: {message}\n"
            writer.write(response.encode())
            await writer.drain()

    except asyncio.CancelledError:
        print(f"[!] Task for {addr} was cancelled")

    finally:
        writer.close()
        await writer.wait_closed()
        print(f"[x] Closed connection for {addr}")

# Start server
async def main():
    server = await asyncio.start_server(
        handle_client, host='0.0.0.0', port=9000
    )
    addr = server.sockets[0].getsockname()
    print(f"🚀 Server listening on {addr}")

    async with server:
        await server.serve_forever()

asyncio.run(main())
