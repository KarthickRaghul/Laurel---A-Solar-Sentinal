import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: text("email").notNull().unique(),
  role: text("role").notNull().default("viewer"), // admin, analyst, viewer
  status: text("status").notNull().default("active"), // active, inactive
  createdAt: timestamp("created_at").defaultNow(),
});

export const devices = pgTable("devices", {
  id: varchar("id").primaryKey(),
  ipAddress: text("ip_address").notNull(),
  deviceType: text("device_type").notNull(),
  manufacturer: text("manufacturer").notNull(),
  firmware: text("firmware").notNull(),
  riskScore: integer("risk_score").notNull(),
  status: text("status").notNull(), // online, offline, warning
  lastScan: timestamp("last_scan"),
});

export const openPorts = pgTable("open_ports", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  deviceId: varchar("device_id").notNull(),
  ipAddress: text("ip_address").notNull(),
  ports: text("ports").notNull(),
  suspicious: boolean("suspicious").notNull(),
  severity: text("severity").notNull(), // low, medium, high, critical
});

export const cves = pgTable("cves", {
  id: varchar("id").primaryKey(),
  description: text("description").notNull(),
  severity: text("severity").notNull(), // low, medium, high, critical
  cvssScore: text("cvss_score").notNull(),
  discoveredAt: timestamp("discovered_at").defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  email: true,
  role: true,
});

export const insertDeviceSchema = createInsertSchema(devices).omit({
  id: true,
});

export const insertOpenPortSchema = createInsertSchema(openPorts).omit({
  id: true,
});

export const insertCveSchema = createInsertSchema(cves).omit({
  id: true,
  discoveredAt: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertDevice = z.infer<typeof insertDeviceSchema>;
export type Device = typeof devices.$inferSelect;
export type InsertOpenPort = z.infer<typeof insertOpenPortSchema>;
export type OpenPort = typeof openPorts.$inferSelect;
export type InsertCve = z.infer<typeof insertCveSchema>;
export type Cve = typeof cves.$inferSelect;
