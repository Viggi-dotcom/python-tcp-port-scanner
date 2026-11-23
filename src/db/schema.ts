import {
  pgTable,
  serial,
  text,
  integer,
  timestamp,
  boolean,
} from "drizzle-orm/pg-core";

export const labTargets = pgTable("lab_targets", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  host: text("host").notNull(),
  environment: text("environment").notNull(), // e.g. 'Loopback', 'VirtualBox Host-Only (vboxnet0)', 'VirtualBox NAT'
  osProfile: text("os_profile").notNull(),
  defaultPorts: text("default_ports").notNull(),
  description: text("description").notNull(),
  authorized: boolean("authorized").default(true).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const scans = pgTable("scans", {
  id: serial("id").primaryKey(),
  targetHost: text("target_host").notNull(),
  targetLabel: text("target_label").default("Authorized Lab Node").notNull(),
  portRange: text("port_range").notNull(),
  timeoutMs: integer("timeout_ms").default(500).notNull(),
  threads: integer("threads").default(20).notNull(),
  grabBanner: boolean("grab_banner").default(true).notNull(),
  status: text("status").default("completed").notNull(), // 'running' | 'completed' | 'failed'
  openCount: integer("open_count").default(0).notNull(),
  closedCount: integer("closed_count").default(0).notNull(),
  filteredCount: integer("filtered_count").default(0).notNull(),
  totalPortsScanned: integer("total_ports_scanned").default(0).notNull(),
  durationMs: integer("duration_ms").default(0).notNull(),
  cliCommand: text("cli_command").default("").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const portResults = pgTable("port_results", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id")
    .references(() => scans.id, { onDelete: "cascade" })
    .notNull(),
  port: integer("port").notNull(),
  protocol: text("protocol").default("TCP").notNull(),
  state: text("state").notNull(), // 'open' | 'closed' | 'filtered'
  service: text("service").default("unknown").notNull(),
  banner: text("banner"),
  rawHex: text("raw_hex"),
  latencyMs: integer("latency_ms"),
  securityNotes: text("security_notes"),
  riskLevel: text("risk_level").default("info").notNull(), // 'info' | 'low' | 'medium' | 'high'
});

export type LabTarget = typeof labTargets.$inferSelect;
export type NewLabTarget = typeof labTargets.$inferInsert;
export type Scan = typeof scans.$inferSelect;
export type NewScan = typeof scans.$inferInsert;
export type PortResult = typeof portResults.$inferSelect;
export type NewPortResult = typeof portResults.$inferInsert;
