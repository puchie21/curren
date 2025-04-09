import { useQuery } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";

const popularPairs = [
  { from: "USD", to: "EUR" },
  { from: "USD", to: "GBP" },
  { from: "USD", to: "JPY" },
  { from: "USD", to: "CAD" }
];

export default function ExchangeRates() {
  const { data: rates, isLoading } = useQuery({
    queryKey: ["/api/rates"],
  });
  
  const lastUpdated = rates?.timestamp ? new Date(rates.timestamp) : new Date();
  
  const getRate = (from: string, to: string) => {
    if (!rates) return null;
    if (from === to) return 1;
    
    return rates[`${from}${to}`] || (1 / rates[`${to}${from}`]) || null;
  };
  
  return (
    <div className="bg-gray-50 rounded-md p-4 mb-6">
      <h3 className="text-md font-medium text-gray-700 mb-3">
        Current Exchange Rates 
        <span className="text-xs text-gray-500 ml-2">
          (Updated: {isLoading ? "Loading..." : format(lastUpdated, "MMM dd, yyyy, h:mm a")})
        </span>
      </h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {isLoading ? (
          Array(4).fill(0).map((_, i) => (
            <Card key={i} className="p-3">
              <div className="flex items-center">
                <Skeleton className="h-4 w-16" />
                <Skeleton className="h-4 w-12 ml-auto" />
              </div>
            </Card>
          ))
        ) : (
          popularPairs.map(({ from, to }) => {
            const rate = getRate(from, to);
            return (
              <Card key={`${from}${to}`} className="p-3 shadow-sm">
                <div className="flex items-center">
                  <span className="text-xs font-medium text-gray-500">{from}/{to}</span>
                  <span className="ml-auto text-sm font-semibold">
                    {rate ? rate.toFixed(2) : "N/A"}
                  </span>
                </div>
              </Card>
            );
          })
        )}
      </div>
    </div>
  );
}
