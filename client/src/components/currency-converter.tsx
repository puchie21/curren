import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { RefreshCw } from "lucide-react";
import ExchangeRates from "./exchange-rates";

interface ConversionData {
  fromAmount: number;
  fromCurrency: string;
  toCurrency: string;
  toAmount: number;
  exchangeRate: number;
}

const currencies = [
  "USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "INR", "BRL"
];

export default function CurrencyConverter() {
  const [fromAmount, setFromAmount] = useState<number>(1);
  const [fromCurrency, setFromCurrency] = useState<string>("USD");
  const [toCurrency, setToCurrency] = useState<string>("EUR");
  const [toAmount, setToAmount] = useState<number | null>(null);
  const { toast } = useToast();
  
  // Fetch exchange rates
  const { data: rates, isLoading: ratesLoading, error: ratesError, refetch } = useQuery({
    queryKey: ["/api/rates"],
    refetchInterval: 1800000, // 30 minutes
  });
  
  // Record a conversion
  const recordConversion = useMutation({
    mutationFn: async (data: ConversionData) => {
      const res = await apiRequest("POST", "/api/conversions", data);
      return await res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/conversions"] });
      toast({
        title: "Conversion recorded",
        description: "Your conversion has been saved to history",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Error recording conversion",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  useEffect(() => {
    if (rates && fromAmount) {
      convert();
    }
  }, [fromAmount, fromCurrency, toCurrency, rates]);

  const convert = () => {
    if (!rates) return;
    
    const rate = getExchangeRate(fromCurrency, toCurrency);
    if (rate) {
      const result = fromAmount * rate;
      setToAmount(result);
    } else {
      setToAmount(null);
    }
  };

  const getExchangeRate = (from: string, to: string) => {
    if (!rates) return null;
    if (from === to) return 1;
    
    // Access the exchange rate from the rates data
    const rate = rates[`${from}${to}`] || (1 / rates[`${to}${from}`]);
    return rate;
  };

  const handleSwapCurrencies = () => {
    setFromCurrency(toCurrency);
    setToCurrency(fromCurrency);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!rates || toAmount === null) return;
    
    const rate = getExchangeRate(fromCurrency, toCurrency);
    if (rate) {
      recordConversion.mutate({
        fromAmount,
        fromCurrency,
        toCurrency,
        toAmount,
        exchangeRate: rate
      });
    }
  };

  const formatRate = (from: string, to: string) => {
    const rate = getExchangeRate(from, to);
    if (!rate) return "N/A";
    return `1 ${from} = ${rate.toFixed(4)} ${to}`;
  };

  return (
    <Card className="shadow-md">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-2xl font-semibold mb-0">Currency Converter</CardTitle>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => refetch()} 
            disabled={ratesLoading}
          >
            <RefreshCw size={16} className={`mr-2 ${ratesLoading ? 'animate-spin' : ''}`} />
            Refresh Rates
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <ExchangeRates />
        
        <form onSubmit={handleSubmit} className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            {/* From Currency */}
            <div>
              <label htmlFor="from-amount" className="block text-gray-700 font-medium mb-2">From</label>
              <div className="flex">
                <Input
                  id="from-amount"
                  type="number"
                  value={fromAmount}
                  onChange={(e) => setFromAmount(parseFloat(e.target.value) || 0)}
                  min="0.01"
                  step="0.01"
                  className="rounded-r-none"
                  required
                />
                <Select
                  value={fromCurrency}
                  onValueChange={setFromCurrency}
                >
                  <SelectTrigger className="w-1/3 rounded-l-none">
                    <SelectValue placeholder="Select currency" />
                  </SelectTrigger>
                  <SelectContent>
                    {currencies.map(currency => (
                      <SelectItem key={currency} value={currency}>
                        {currency}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            
            {/* To Currency */}
            <div>
              <label htmlFor="to-amount" className="block text-gray-700 font-medium mb-2">To</label>
              <div className="flex">
                <Input
                  id="to-amount"
                  type="number"
                  value={toAmount !== null ? toAmount : ""}
                  readOnly
                  className="rounded-r-none bg-gray-50"
                />
                <Select
                  value={toCurrency}
                  onValueChange={setToCurrency}
                >
                  <SelectTrigger className="w-1/3 rounded-l-none">
                    <SelectValue placeholder="Select currency" />
                  </SelectTrigger>
                  <SelectContent>
                    {currencies.map(currency => (
                      <SelectItem key={currency} value={currency}>
                        {currency}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
          
          {/* Exchange Rate Information */}
          <div className="flex items-center justify-between mb-6">
            <div className="text-sm text-gray-600">
              {formatRate(fromCurrency, toCurrency)}
            </div>
            <Button 
              type="button" 
              variant="outline" 
              onClick={handleSwapCurrencies}
              size="sm"
              className="rounded-full w-10 h-10 p-0"
            >
              <RefreshCw size={16} className="rotate-90" />
            </Button>
          </div>
          
          {/* Convert Button */}
          <Button 
            type="submit" 
            className="w-full font-medium py-6"
            disabled={recordConversion.isPending || !rates}
          >
            {recordConversion.isPending ? "Converting..." : "Convert"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
