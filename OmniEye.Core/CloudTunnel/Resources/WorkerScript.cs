namespace OmniEye.Core.CloudTunnel.Resources;

public static class WorkerScript
{
    public const string Code = @"// OmniEye Cloudflare Worker (WebSocket -> TCP Sockets Bridge)
// Free deployment at https://dash.cloudflare.com/ (Workers & Pages)
import { connect } from ""cloudflare:sockets"";

function toBytes(data) {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    if (typeof data === ""string"") {
        return new TextEncoder().encode(data);
    }
    if (data && typeof data.arrayBuffer === ""function"") {
        return data.arrayBuffer().then((ab) => new Uint8Array(ab));
    }
    return new Uint8Array();
}

export default {
    async fetch(request) {
        if ((request.headers.get(""Upgrade"") || """").toLowerCase() !== ""websocket"") {
            return new Response(""OmniEye Cloudflare Worker is Running. Send WebSocket to /apiws"", { status: 200 });
        }

        const url = new URL(request.url);
        if (url.pathname !== ""/apiws"") {
            return new Response(""Not found"", { status: 404 });
        }

        const dst = url.searchParams.get(""dst"") || ""149.154.167.220"";
        const port = parseInt(url.searchParams.get(""port"") || ""443"", 10);

        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();

        let socket;
        try {
            socket = connect({ hostname: dst, port: port });
        } catch (e) {
            return new Response(""Connect failed: "" + e.message, { status: 502 });
        }

        const tcpReader = socket.readable.getReader();
        const tcpWriter = socket.writable.getWriter();

        server.addEventListener(""message"", async (event) => {
            try {
                await tcpWriter.write(await toBytes(event.data));
            } catch {
                try { server.close(1011, ""tcp write failed""); } catch {}
            }
        });

        server.addEventListener(""close"", async () => {
            try { await tcpWriter.close(); } catch {}
            try { socket.close(); } catch {}
        });

        (async () => {
            try {
                while (true) {
                    const { value, done } = await tcpReader.read();
                    if (done) break;
                    if (value) server.send(value);
                }
            } catch {
            } finally {
                try { server.close(); } catch {}
                try { tcpReader.releaseLock(); } catch {}
                try { socket.close(); } catch {}
            }
        })();

        return new Response(null, { status: 101, webSocket: client });
    },
};";

    public const string InstructionsRu = @"1. Зарегистрируйтесь на https://dash.cloudflare.com/ (бесплатно).
2. Перейдите в раздел Compute -> Workers & Pages.
3. Нажмите 'Create application' -> 'Create Worker' -> 'Deploy'.
4. Нажмите 'Edit code', замените весь код на код скрипта OmniEye и нажмите 'Deploy'.
5. Скопируйте полученный домен (например: 'xxx-yyy.workers.dev') и вставьте его в настройки OmniEye.";

    public const string InstructionsEn = @"1. Sign up for free at https://dash.cloudflare.com/.
2. Navigate to Compute -> Workers & Pages.
3. Click 'Create application' -> 'Create Worker' -> 'Deploy'.
4. Click 'Edit code', replace all code with OmniEye Worker script and click 'Deploy'.
5. Copy the assigned domain (e.g. 'xxx-yyy.workers.dev') and paste it into OmniEye Cloud Tunnel settings.";
}
