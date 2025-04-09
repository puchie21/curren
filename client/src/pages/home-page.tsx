import { useAuth } from "@/hooks/use-auth";
import Navbar from "@/components/navbar";
import Footer from "@/components/footer";
import CurrencyConverter from "@/components/currency-converter";
import ConversionHistory from "@/components/conversion-history";

export default function HomePage() {
  const { user } = useAuth();

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-grow py-8 px-4">
        <div className="container mx-auto max-w-4xl">
          <div className="mb-6">
            <CurrencyConverter />
          </div>

          <ConversionHistory />
        </div>
      </main>
      <Footer />
    </div>
  );
}
