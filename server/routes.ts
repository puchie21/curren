import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth } from "./auth";
import { storage } from "./storage";
import { insertConversionSchema } from "@shared/schema";
import axios from "axios";

// Currency exchange API
const API_KEY = process.env.EXCHANGE_RATE_API_KEY || "demo";
const API_URL = "https://v6.exchangerate-api.com/v6";

// Sample fallback rates if API is unavailable
const FALLBACK_RATES = {
  USDEUR: 0.92,
  USDGBP: 0.79,
  USDJPY: 134.08,
  USDCAD: 1.35,
  USDAUD: 1.49,
  USDCHF: 0.89,
  USDCNY: 7.11,
  USDINR: 82.08,
  USDBRL: 4.91,
  EURUSD: 1.09,
  EURGBP: 0.86,
  EURJPY: 145.74,
  GBPUSD: 1.27,
  GBPEUR: 1.16,
  GBPJPY: 169.72,
  timestamp: new Date().toISOString()
};

// Cache exchange rates for 30 minutes
let ratesCache: any = null;
let ratesCacheTime: number = 0;

async function fetchExchangeRates() {
  // If we have a recent cache, use it
  if (ratesCache && Date.now() - ratesCacheTime < 30 * 60 * 1000) {
    return ratesCache;
  }
  
  try {
    const response = await axios.get(`${API_URL}/${API_KEY}/latest/USD`);
    if (response.data && response.data.result === "success") {
      // Format the data for easier consumption
      const rates: Record<string, number> = {};
      const baseRates = response.data.conversion_rates;
      
      // Create currency pair combinations
      Object.keys(baseRates).forEach(from => {
        Object.keys(baseRates).forEach(to => {
          if (from !== to) {
            // Calculate cross rates
            const rate = baseRates[to] / baseRates[from];
            rates[`${from}${to}`] = rate;
          }
        });
      });
      
      // Add timestamp
      const result = {
        ...rates,
        timestamp: new Date().toISOString()
      };
      
      // Cache the result
      ratesCache = result;
      ratesCacheTime = Date.now();
      
      return result;
    }
    throw new Error("Failed to fetch exchange rates");
  } catch (error) {
    console.error("Error fetching exchange rates:", error);
    // If we have a cache, return it even if expired
    if (ratesCache) {
      return ratesCache;
    }
    
    // Return fallback data
    console.log("Using fallback exchange rates");
    return FALLBACK_RATES;
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Set up authentication routes
  setupAuth(app);
  
  // Exchange rates API endpoint
  app.get("/api/rates", async (req, res) => {
    try {
      const rates = await fetchExchangeRates();
      res.json(rates);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch exchange rates" });
    }
  });
  
  // Conversions API endpoints
  app.get("/api/conversions", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    const page = parseInt(req.query.page as string) || 1;
    const pageSize = parseInt(req.query.pageSize as string) || 5;
    const userId = req.user!.id;
    
    try {
      const result = await storage.getConversions(userId, page, pageSize);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch conversion history" });
    }
  });
  
  app.post("/api/conversions", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    try {
      const validatedData = insertConversionSchema.parse(req.body);
      const conversion = await storage.saveConversion({
        ...validatedData,
        userId: req.user!.id
      });
      
      res.status(201).json(conversion);
    } catch (error) {
      res.status(400).json({ error: "Invalid conversion data" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
