import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { format } from "date-fns";
import { Download } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";

interface Conversion {
  id: number;
  userId: number;
  fromAmount: number;
  fromCurrency: string;
  toAmount: number;
  toCurrency: string;
  exchangeRate: number;
  createdAt: string;
}

export default function ConversionHistory() {
  const [page, setPage] = useState(1);
  const pageSize = 5;
  
  const { data, isLoading, error } = useQuery<{
    conversions: Conversion[];
    totalCount: number;
  }>({
    queryKey: ["/api/conversions", page, pageSize],
  });
  
  const conversions = data?.conversions || [];
  const totalCount = data?.totalCount || 0;
  const totalPages = Math.ceil(totalCount / pageSize);
  
  const handleExport = () => {
    // In a real implementation, this would generate a CSV file
    // of the user's conversion history
    alert("This would export your conversion history as a CSV file");
  };
  
  if (error) {
    return (
      <Card className="shadow-md">
        <CardHeader>
          <CardTitle className="text-2xl font-semibold">Conversion History</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center p-4 text-red-500">
            Error loading conversion history
          </div>
        </CardContent>
      </Card>
    );
  }
  
  return (
    <Card className="shadow-md">
      <CardHeader>
        <div className="flex justify-between items-center">
          <CardTitle className="text-2xl font-semibold">Conversion History</CardTitle>
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download size={16} className="mr-2" />
            Export
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">From</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">To</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Rate</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array(5).fill(0).map((_, index) => (
                  <tr key={index} className="border-b border-gray-200">
                    <td className="px-4 py-3"><Skeleton className="h-4 w-24" /></td>
                    <td className="px-4 py-3"><Skeleton className="h-4 w-28" /></td>
                    <td className="px-4 py-3"><Skeleton className="h-4 w-28" /></td>
                    <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                  </tr>
                ))
              ) : conversions.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-gray-500">
                    No conversion history yet. Try converting some currencies!
                  </td>
                </tr>
              ) : (
                conversions.map((conversion) => (
                  <tr key={conversion.id} className="border-b border-gray-200 hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {format(new Date(conversion.createdAt), "MMM dd, yyyy")}
                    </td>
                    <td className="px-4 py-3 text-sm font-medium">
                      {conversion.fromAmount.toFixed(2)} {conversion.fromCurrency}
                    </td>
                    <td className="px-4 py-3 text-sm font-medium">
                      {conversion.toAmount.toFixed(2)} {conversion.toCurrency}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {conversion.exchangeRate.toFixed(4)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        
        {!isLoading && totalPages > 1 && (
          <div className="flex items-center justify-between mt-6">
            <div className="text-sm text-gray-600">
              Showing {(page - 1) * pageSize + 1}-{Math.min(page * pageSize, totalCount)} of {totalCount} entries
            </div>
            <Pagination>
              <PaginationContent>
                <PaginationItem>
                  <PaginationPrevious 
                    onClick={() => setPage(p => Math.max(p - 1, 1))}
                    className={page === 1 ? "pointer-events-none opacity-50" : ""}
                  />
                </PaginationItem>
                
                {Array.from({ length: Math.min(totalPages, 3) }, (_, i) => {
                  const pageNumber = page <= 2 ? i + 1 : page === totalPages ? totalPages - 2 + i : page - 1 + i;
                  if (pageNumber <= totalPages) {
                    return (
                      <PaginationItem key={pageNumber}>
                        <PaginationLink
                          onClick={() => setPage(pageNumber)}
                          isActive={page === pageNumber}
                        >
                          {pageNumber}
                        </PaginationLink>
                      </PaginationItem>
                    );
                  }
                  return null;
                })}
                
                <PaginationItem>
                  <PaginationNext 
                    onClick={() => setPage(p => Math.min(p + 1, totalPages))}
                    className={page === totalPages ? "pointer-events-none opacity-50" : ""}
                  />
                </PaginationItem>
              </PaginationContent>
            </Pagination>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
