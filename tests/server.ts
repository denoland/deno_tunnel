import { type HeaderInfo, HTTPParser } from "npm:http-parser-js";
import { Buffer } from "node:buffer";

const VERSION = 1;
const CLOSE_GENERIC = 0;
const CLOSE_PROTOCOL = 1;
const CLOSE_UNAUTHORIZED = 2;
const CLOSE_NOT_FOUND = 3;
const CLOSE_MIGRATE = 4;

const endpoint = new Deno.QuicEndpoint({
  hostname: "localhost",
  port: 0,
});

const quicListener = endpoint.listen({
  cert: Deno.readTextFileSync(
    new URL(import.meta.resolve("./localhost.crt")).pathname,
  ),
  key: Deno.readTextFileSync(
    new URL(import.meta.resolve("./localhost.key")).pathname,
  ),
  alpnProtocols: ["🦕🕳️"],
});

const tcpListener = Deno.listen({ port: 0 });

console.log(
  "LISTEN",
  serializeAddr(endpoint.addr),
  serializeAddr(tcpListener.addr),
);

const CONNECTIONS = new Map<
  string,
  Map<
    string,
    {
      conn: Deno.QuicConn;
      control: {
        writer: WritableStreamDefaultWriter;
        reader: ReadableStreamBYOBReader;
        bi: Deno.QuicBidirectionalStream;
      };
    }
  >
>();

(async function () {
  for await (const conn of quicListener) {
    handleQuicConnection(conn);
  }
})();

(async function () {
  for await (const conn of tcpListener) {
    handleTcpConnection(conn);
  }
})();

async function handleTcpConnection(conn: Deno.TcpConn) {
  if (Deno.env.get("PROXY_WITH_HTTP")) {
    const parser = new HTTPParser(HTTPParser.REQUEST);
    let info: HeaderInfo | null = null;
    parser[HTTPParser.kOnHeadersComplete] = (i) => {
      i.headers;
      info = i;
    };

    const chunks = [];
    for await (const chunk of conn.readable.values({ preventCancel: true })) {
      chunks.push(chunk);
      parser.execute(Buffer.from(chunk));
      if (info) break;
    }
    if (!info) return;
    info = info as unknown as HeaderInfo; // ts bug?

    const headers: Record<string, string> = {};
    for (let i = 0; i < info.headers.length; i += 2) {
      const name = info.headers[i].toLowerCase();
      const value = info.headers[i + 1];
      headers[name] = value;
    }

    const routingId = headers.host?.split(".")[0];
    if (!routingId) {
      await conn.writable.getWriter().write(
        new TextEncoder().encode(
          "HTTP/1.1 404 NOT FOUND\r\nConnnection: close\r\n\r\n",
        ),
      );
      return;
    }
    const connections = CONNECTIONS.get(routingId);
    if (!connections) {
      await conn.writable.getWriter().write(
        new TextEncoder().encode(
          "HTTP/1.1 400 BAD REQUEST\r\nConnnection: close\r\n\r\n",
        ),
      );
      return;
    }
    const entry = [...connections][0][1];

    if (headers["x-control"] === "migrate") {
      Deno.unrefTimer(setTimeout(() => {
        entry.conn.close({ closeCode: CLOSE_MIGRATE, reason: "migrate" });
      }, 2000));
      await writeStreamMessage<ControlMessage>(entry.control.writer, {
        headerType: "Migrate",
      });
      await conn.writable.getWriter().write(
        new TextEncoder().encode(
          "HTTP/1.1 204 NO CONTENT\r\nConnnection: close\r\n\r\n",
        ),
      );
      return;
    }

    if (headers["x-control"] === "close") {
      entry.conn.close({ closeCode: CLOSE_GENERIC, reason: "" });
      await conn.writable.getWriter().write(
        new TextEncoder().encode(
          "HTTP/1.1 204 NO CONTENT\r\nConnnection: close\r\n\r\n",
        ),
      );
      return;
    }

    const bi = await entry.conn.createBidirectionalStream();
    const writer = bi.writable.getWriter();

    await writeStreamMessage<StreamHeader>(writer, {
      headerType: "Stream",
      local_addr: serializeAddr(conn.localAddr),
      remote_addr: serializeAddr(conn.remoteAddr),
    });

    const p = bi.readable.pipeTo(conn.writable);

    for (const chunk of chunks) {
      await writer.write(chunk);
    }

    writer.releaseLock();

    await Promise.all([p, conn.readable.pipeTo(bi.writable)]);
  } else {
    const reader = conn.readable.getReader({ mode: "byob" });
    const length = await readUint32LE(reader);
    const { value: view } = await reader.read(new Uint8Array(length), {
      min: length,
    });

    const routingId = new TextDecoder().decode(view);

    const connections = CONNECTIONS.get(routingId);
    if (!connections) {
      return;
    }
    const entry = [...connections][0][1];

    const byte = (await reader.read(new Uint8Array(1), { min: 1 })).value![0];
    if (byte === 1) {
      Deno.unrefTimer(setTimeout(() => {
        entry.conn.close({ closeCode: CLOSE_MIGRATE, reason: "migrate" });
      }, 2000));
      await writeStreamMessage<ControlMessage>(entry.control.writer, {
        headerType: "Migrate",
      });
      return;
    }
    if (byte === 2) {
      entry.conn.close({ closeCode: CLOSE_GENERIC, reason: "" });
      return;
    }

    reader.releaseLock();

    const bi = await entry.conn.createBidirectionalStream();

    const writer = bi.writable.getWriter();
    await writeStreamMessage<StreamHeader>(writer, {
      headerType: "Stream",
      local_addr: serializeAddr(conn.localAddr),
      remote_addr: serializeAddr(conn.remoteAddr),
    });
    writer.releaseLock();

    await Promise.all([
      bi.readable.pipeTo(conn.writable),
      conn.readable.pipeTo(bi.writable),
    ]);
  }
}

async function handleQuicConnection(conn: Deno.QuicConn) {
  const tunnelId = crypto.randomUUID();

  const bi = (await conn.incomingBidirectionalStreams
    .getReader()
    .read()).value!;

  const reader = bi.readable.getReader({ mode: "byob" });
  const version = await readUint32LE(reader);
  if (version !== VERSION) {
    conn.close({ closeCode: CLOSE_PROTOCOL, reason: "invalid version" });
    return;
  }
  const writer = bi.writable.getWriter();
  await writeUint32LE(writer, version);

  const header = await readStreamMessage<StreamHeader>(reader);
  if (header.headerType !== "Control") {
    conn.close({ closeCode: CLOSE_PROTOCOL, reason: "unexpected header" });
    return;
  }

  let routingId;
  const auth = await readStreamMessage<ControlMessage>(reader);
  switch (auth.headerType) {
    case "AuthenticateApp":
      if (auth.org === "unknown" || auth.app === "unknown") {
        conn.close({
          closeCode: CLOSE_NOT_FOUND,
          reason: "unknown org or app",
        });
        return;
      }
      if (auth.token === "invalid") {
        conn.close({ closeCode: CLOSE_UNAUTHORIZED, reason: "invalid token" });
        return;
      }
      routingId = `${auth.org}-${auth.app}`;
      break;
    case "AuthenticateCluster":
      if (auth.token === "invalid") {
        conn.close({ closeCode: CLOSE_UNAUTHORIZED, reason: "invalid token" });
        return;
      }
      routingId = auth.token;
      break;
    default:
      conn.close({ closeCode: CLOSE_PROTOCOL, reason: "unexpected header" });
      return;
  }

  await writeStreamMessage<ControlMessage>(writer, {
    headerType: "Authenticated",
    hostnames: [`${routingId}.localhost`],
    addr: serializeAddr(endpoint.addr),
    env: {},
    metadata: {},
  });

  const control = {
    bi,
    reader,
    writer,
  };

  if (!CONNECTIONS.has(routingId)) {
    CONNECTIONS.set(routingId, new Map());
  }
  const connections = CONNECTIONS.get(routingId)!;
  connections.set(tunnelId, { conn, control });
  conn.closed.then(() => {
    connections.delete(tunnelId);
    if (connections.size === 0) {
      CONNECTIONS.delete(routingId);
    }
  });

  await writeStreamMessage<ControlMessage>(writer, {
    headerType: "Routed",
  });
}

function serializeAddr(addr: Deno.NetAddr) {
  const host = addr.hostname.includes(":")
    ? `[${addr.hostname}]`
    : addr.hostname;

  return `${host}:${addr.port}`;
}

async function readUint32LE(reader: ReadableStreamBYOBReader): Promise<number> {
  const { value: view } = await reader.read(new Uint8Array(4), { min: 4 });
  return new DataView(view!.buffer).getUint32(0, true);
}

async function writeUint32LE(
  writer: WritableStreamDefaultWriter,
  value: number,
) {
  const view = new Uint8Array(4);
  new DataView(view.buffer).setUint32(0, value, true);
  await writer.write(view);
}

type StreamHeader = {
  headerType: "Control";
} | {
  headerType: "Stream";
  local_addr: string;
  remote_addr: string;
} | {
  headerType: "Agent";
};

type ControlMessage = {
  headerType: "AuthenticateApp";
  app: string;
  org: string;
  token: string;
} | {
  headerType: "AuthenticateCluster";
  token: string;
} | {
  headerType: "Authenticated";
  metadata: Record<string, string>;
  addr: string;
  hostnames: string[];
  env: Record<string, string>;
} | {
  headerType: "Routed";
} | {
  headerType: "Migrate";
};

async function readStreamMessage<T extends { headerType: string }>(
  reader: ReadableStreamBYOBReader,
): Promise<T> {
  const length = await readUint32LE(reader);
  const { value: view } = await reader.read(new Uint8Array(length), {
    min: length,
  });

  const data = JSON.parse(new TextDecoder().decode(view));

  // shaped like { HeaderName: Data }

  const items = Object.entries(
    data as { [k: string]: Record<string, unknown> },
  );
  if (items.length !== 1) {
    throw new Error("invalid header");
  }
  items[0][1].headerType = items[0][0];

  console.error("<-", items[0][1]);

  return items[0][1] as T;
}

async function writeStreamMessage<T extends { headerType: string }>(
  writer: WritableStreamDefaultWriter,
  header: T,
) {
  const { headerType, ...headerData } = header;
  const data = { [headerType]: headerData };
  console.error("->", data);
  const view = new TextEncoder().encode(JSON.stringify(data));
  await writeUint32LE(writer, view.length);
  await writer.write(view);
}
