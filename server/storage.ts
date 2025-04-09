import { users, conversions, type User, type InsertUser, type Conversion, type InsertConversion } from "@shared/schema";
import session from "express-session";
import createMemoryStore from "memorystore";

const MemoryStore = createMemoryStore(session);

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  saveConversion(conversion: InsertConversion & { userId: number }): Promise<Conversion>;
  getConversions(userId: number, page: number, pageSize: number): Promise<{
    conversions: Conversion[];
    totalCount: number;
  }>;
  sessionStore: session.SessionStore;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private conversions: Map<number, Conversion>;
  public sessionStore: session.SessionStore;
  private currentUserId: number;
  private currentConversionId: number;

  constructor() {
    this.users = new Map();
    this.conversions = new Map();
    this.sessionStore = new MemoryStore({
      checkPeriod: 86400000, // prune expired entries every 24h
    });
    this.currentUserId = 1;
    this.currentConversionId = 1;
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async saveConversion(conversionData: InsertConversion & { userId: number }): Promise<Conversion> {
    const id = this.currentConversionId++;
    const now = new Date();
    
    const conversion: Conversion = {
      ...conversionData,
      id,
      createdAt: now.toISOString(),
    };
    
    this.conversions.set(id, conversion);
    return conversion;
  }

  async getConversions(userId: number, page: number, pageSize: number): Promise<{
    conversions: Conversion[];
    totalCount: number;
  }> {
    const userConversions = Array.from(this.conversions.values())
      .filter(conversion => conversion.userId === userId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    
    const start = (page - 1) * pageSize;
    const paginatedConversions = userConversions.slice(start, start + pageSize);
    
    return {
      conversions: paginatedConversions,
      totalCount: userConversions.length,
    };
  }
}

export const storage = new MemStorage();
