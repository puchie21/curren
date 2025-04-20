import { Handler } from '@netlify/functions';
import express, { Express, Request, Response, NextFunction } from 'express';
import serverless from 'serverless-http';
import cors from 'cors';
import bodyParser from 'body-parser';
import { scrypt, randomBytes, timingSafeEqual } from 'crypto';
import { promisify } from 'util';
import { storage } from '../../server/storage';
import { InsertConversion, InsertUser, User } from '../../shared/schema';
import axios from 'axios';

// Setup Express app
const app: Express = express();
app.use(cors());
app.use(bodyParser.json());

// Auth helpers
const scryptAsync = promisify(scrypt);

async function hashPassword(password: string) {
  const salt = randomBytes(16).toString('hex');
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString('hex')}.${salt}`;
}

async function comparePasswords(supplied: string, stored: string) {
  const [hashed, salt] = stored.split('.');
  const hashedBuf = Buffer.from(hashed, 'hex');
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

// Error handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Internal Server Error' });
});

// API Routes
app.post('/register', async (req, res) => {
  try {
    const existingUser = await storage.getUserByUsername(req.body.username);
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const user = await storage.createUser({
      ...req.body,
      password: await hashPassword(req.body.password),
    });

    // Don't send password to client
    const { password, ...userWithoutPassword } = user;
    res.status(201).json(userWithoutPassword);
  } catch (error) {
    res.status(500).json({ error: 'Failed to register user' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await storage.getUserByUsername(username);
    
    if (!user || !(await comparePasswords(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    // Don't send password to client
    const { password: _, ...userWithoutPassword } = user;
    res.status(200).json(userWithoutPassword);
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/exchange-rates', async (req, res) => {
  try {
    const baseCurrency = req.query.base as string || 'USD';
    const rates = await fetchExchangeRates(baseCurrency);
    res.json(rates);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch exchange rates' });
  }
});

app.post('/conversions', async (req, res) => {
  try {
    const userId = parseInt(req.body.userId);
    const conversionData: InsertConversion & { userId: number } = {
      ...req.body,
      userId,
    };
    const conversion = await storage.saveConversion(conversionData);
    res.status(201).json(conversion);
  } catch (error) {
    res.status(500).json({ error: 'Failed to save conversion' });
  }
});

app.get('/conversions', async (req, res) => {
  try {
    const userId = parseInt(req.query.userId as string);
    const page = parseInt(req.query.page as string) || 1;
    const pageSize = parseInt(req.query.pageSize as string) || 10;
    
    const result = await storage.getConversions(userId, page, pageSize);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch conversions' });
  }
});

// Exchange rates helper function
async function fetchExchangeRates(baseCurrency = 'USD') {
  try {
    // Use API key if available
    const apiKey = process.env.EXCHANGE_RATE_API_KEY;
    
    if (apiKey) {
      const response = await axios.get(
        `https://v6.exchangerate-api.com/v6/${apiKey}/latest/${baseCurrency}`
      );
      return response.data;
    } else {
      // Fallback to sample exchange rates
      return getFallbackRates(baseCurrency);
    }
  } catch (error) {
    console.error('Error fetching exchange rates:', error);
    return getFallbackRates(baseCurrency);
  }
}

// Fallback exchange rates
function getFallbackRates(baseCurrency: string) {
  const baseRates = {
    USD: 1,
    EUR: 0.85,
    GBP: 0.73,
    JPY: 110.45,
    CAD: 1.25,
    AUD: 1.32,
    CHF: 0.92,
    CNY: 6.45,
    INR: 74.5,
    RUB: 73.2,
  };

  const rates: Record<string, number> = {};
  const baseValue = baseRates[baseCurrency as keyof typeof baseRates] || 1;

  // Calculate cross rates
  Object.entries(baseRates).forEach(([currency, rate]) => {
    rates[currency] = rate / baseValue;
  });

  return {
    base_code: baseCurrency,
    conversion_rates: rates,
    time_last_update_utc: new Date().toUTCString(),
  };
}

// Create serverless handler
const handler = serverless(app);

export const handler: Handler = async (event, context) => {
  // Map API paths to remove the /.netlify/functions/api prefix
  if (event.path.startsWith('/.netlify/functions/api')) {
    event.path = event.path.replace('/.netlify/functions/api', '');
  }
  
  // Handle requests
  return handler(event, context);
};