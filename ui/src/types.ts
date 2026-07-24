// Mirrors pkg/api/types.go — keep in sync with the Go wire contract.

export type Protocol =
  | "http"
  | "dns"
  | "redis"
  | "valkey"
  | "postgres"
  | "mysql"
  | "mongodb"
  | "kafka"
  | "amqp"
  | "ws"
  | "tcp"
  | "udp"
  | "icmp";

export interface Endpoint {
  ip: string;
  port: number;
  name?: string;
  namespace?: string;
}

// --- richer per-protocol sub-objects (mirrors pkg/api/types.go, all optional) --

export interface TLSInfo {
  sni?: string;
  alpn?: string;
  version?: string;
  cipher?: string;
}

export interface L4Info {
  srcMac?: string;
  dstMac?: string;
  ipVersion?: number;
  ttl?: number;
  ipFlags?: string;
  clientTcpFlags?: string;
  serverTcpFlags?: string;
  seqStart?: number;
  ackStart?: number;
  window?: number;
  mss?: number;
  retransmits?: number;
  rttMs?: number;
  durationMs?: number;
  clientBytes?: number;
  serverBytes?: number;
  clientPackets?: number;
  serverPackets?: number;
  headerHex?: string;
  tls?: TLSInfo;
}

export interface RawView {
  hex?: string;
  bytes?: number;
  truncated?: boolean;
}

export interface HTTPDetail {
  version?: string;
  query?: Record<string, string>;
  contentType?: string;
  ttfbMs?: number;
}

export interface DNSQuestion {
  name: string;
  type: string;
  class?: string;
}

export interface DNSRecord {
  name: string;
  type: string;
  ttl?: number;
  data: string;
}

export interface DNSDetail {
  id?: number;
  questions?: DNSQuestion[];
  answers?: DNSRecord[];
  authority?: DNSRecord[];
  additional?: DNSRecord[];
  rcode?: string;
  authoritative?: boolean;
  recursionAvailable?: boolean;
}

export interface RedisDetail {
  args?: string[];
  reply?: string;
  replyType?: string;
  dbIndex?: number;
  pipelineDepth?: number;
  attributes?: Record<string, string>;
}

export interface PGColumn {
  name: string;
  typeOid?: number;
  type?: string;
}

export interface PGError {
  severity?: string;
  code?: string;
  message?: string;
  detail?: string;
  hint?: string;
  where?: string;
}

export interface PGDetail {
  statementName?: string;
  portal?: string;
  params?: string[];
  columns?: PGColumn[];
  tag?: string;
  error?: PGError;
  txStatus?: string;
}

export interface MySQLDetail {
  command?: string;
  errorCode?: number;
  errorMessage?: string;
}

export interface MongoDetail {
  command?: string;
  collection?: string;
  database?: string;
  ok?: boolean;
  errmsg?: string;
}

export interface KafkaDetail {
  apiKey?: string;
  apiVersion?: number;
  topic?: string;
  clientId?: string;
  errorCode?: number;
  correlationId?: number;
}

export interface Payload {
  summary?: string;
  headers?: Record<string, string>;
  body?: string;
  size?: number;
  method?: string;
  path?: string;
  host?: string;
  statusCode?: number;
  question?: string;
  answer?: string;
  command?: string;
  query?: string;
  rowCount?: number;
  // AMQP
  exchange?: string;
  routingKey?: string;
  queue?: string;
  deliveryTag?: number;
  class?: string;
  // WebSocket (post-101 frames)
  wsOpcode?: string;
  // L4 flows
  packets?: number;
  bytes?: number;
  flags?: string;
  // richer extras
  contentType?: string;
  truncated?: boolean;
  raw?: RawView;
  http?: HTTPDetail;
  dns?: DNSDetail;
  redis?: RedisDetail;
  postgres?: PGDetail;
  mysql?: MySQLDetail;
  mongo?: MongoDetail;
  kafka?: KafkaDetail;
}

export interface Entry {
  id: string;
  protocol: Protocol;
  timestamp: string;
  elapsedMs: number;
  node: string;
  nodeIp?: string;
  src: Endpoint;
  dst: Endpoint;
  request: Payload;
  response: Payload;
  status: "success" | "warning" | "error" | "";
  statusCode: number;
  l4?: L4Info;
  seq?: number;
  // EXT-3: end-to-end correlation id (traceparent trace-id / x-request-id /
  // x-correlation-id), when the request carried one. Filter via trace.id.
  traceId?: string;
}

export interface Stats {
  totalEntries: number;
  entriesPerSec: number;
  workers: number;
  byProtocol: Record<string, number>;
  byStatus: Record<string, number>;
  broadcastDropped: number;
}

export interface StatsPoint {
  timestamp: string;
  entriesPerSec: number;
  totalEntries: number;
}

// TimelineBucket is one fixed-width slice of GET /api/timeline.
export interface TimelineBucket {
  start: string;
  entries: number;
  errors: number;
  warnings: number;
}

// GroupSummary is one row of GET /api/summary: the buffered traffic
// aggregated over one value of the group-by key (mirrors hub summary.go).
export interface GroupSummary {
  key: string;
  count: number;
  errors: number;
  warnings: number;
  protocols?: string[];
  p50Ms: number;
  p95Ms: number;
  maxMs: number;
  firstSeen: string;
  lastSeen: string;
}

// WorkerInfo is one row of GET /api/workers.
export interface WorkerInfo {
  node: string;
  version?: string;
  connected: boolean;
  connectedAt: string;
  lastSeen: string;
  entries: number;
  dropped: number;
  captureLive: boolean;
  captureTls: boolean;
  capturePaused: boolean;
  ringPackets: number;
  ringDrops: number;
  flowsEvicted: number;
}

export interface Envelope {
  type: "entry" | "entryBatch" | "stats" | "hello" | "filter" | "filterError";
  entry?: Entry;
  // entryBatch: several entries in one frame, oldest first — semantically the
  // same as that many "entry" frames in order (the hub coalesces the live
  // feed and history replay to cut frame count).
  entries?: Entry[];
  stats?: Stats;
  filter?: string;
  error?: string;
}

// --- IFL autocomplete (field catalog) ---------------------------------------
// Mirrors GET /api/fields and GET /api/fields/{field}/values.

export interface FieldValue {
  value: string;
  count: number;
}

export type FieldType = "enum" | "number" | "string" | "freetext";

export interface FieldMeta {
  name: string;
  type: FieldType;
  operators: string[];
  values?: FieldValue[];
}

export interface FieldsResponse {
  fields: FieldMeta[];
}
