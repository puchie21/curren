# CurrencyPro - Currency Converter Application

A full-stack application for currency conversion with user authentication, real-time exchange rates, and conversion history tracking.

## Features

- User authentication (register/login)
- Real-time currency conversion
- Current exchange rates display
- Conversion history tracking
- Responsive design

## Tech Stack

- **Frontend**: React, TanStack Query, Wouter, React Hook Form, Zod, Shadcn UI, Tailwind CSS
- **Backend**: Node.js, Express, Passport.js
- **Storage**: In-memory storage (for development/demo purposes)
- **Build Tools**: Vite, TypeScript

## Prerequisites

- Node.js (version 20 or later recommended)
- npm or yarn

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd currency-converter
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a .env file in the root directory with:
   ```
   SESSION_SECRET=your-secure-session-secret
   ```
   
   For real exchange rates (optional), get an API key from [ExchangeRate-API](https://www.exchangerate-api.com/) and add:
   ```
   EXCHANGE_RATE_API_KEY=your-api-key
   ```

## Running the Application

1. Start the development server:
   ```bash
   npm run dev
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

1. Register a new account or login with an existing account
2. On the homepage, use the currency converter to:
   - Select currencies to convert between
   - Input the amount to convert
   - View the conversion result
   - Save conversions to history
3. View your conversion history below the converter

## Building for Production

1. Build the application:
   ```bash
   npm run build
   ```

2. Start the production server:
   ```bash
   npm start
   ```

## Notes for Local Development

- The application uses an in-memory database, so data will be lost when the server restarts
- If you don't provide an API key, the application will use fallback sample exchange rates
- Session data is stored in memory and will be lost on server restart
