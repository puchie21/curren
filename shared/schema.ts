import { pgTable, text, serial, integer, timestamp, doublePrecision } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const conversions = pgTable("conversions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  fromAmount: doublePrecision("from_amount").notNull(),
  fromCurrency: text("from_currency").notNull(),
  toAmount: doublePrecision("to_amount").notNull(),
  toCurrency: text("to_currency").notNull(),
  exchangeRate: doublePrecision("exchange_rate").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertConversionSchema = createInsertSchema(conversions).omit({
  id: true,
  userId: true,
  createdAt: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type Conversion = typeof conversions.$inferSelect;
export type InsertConversion = z.infer<typeof insertConversionSchema>;
