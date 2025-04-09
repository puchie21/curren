import { Facebook, Twitter, Instagram, Linkedin } from "lucide-react";

export default function Footer() {
  return (
    <footer className="bg-white border-t border-gray-200 py-6">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div>
            <h3 className="font-semibold text-gray-800 mb-4">CurrencyPro</h3>
            <p className="text-gray-600 text-sm">A reliable currency converter with real-time exchange rates for all major global currencies.</p>
          </div>
          <div>
            <h3 className="font-semibold text-gray-800 mb-4">Links</h3>
            <ul className="text-sm space-y-2">
              <li><a href="#" className="text-gray-600 hover:text-primary">About Us</a></li>
              <li><a href="#" className="text-gray-600 hover:text-primary">Terms of Service</a></li>
              <li><a href="#" className="text-gray-600 hover:text-primary">Privacy Policy</a></li>
              <li><a href="#" className="text-gray-600 hover:text-primary">Contact</a></li>
            </ul>
          </div>
          <div>
            <h3 className="font-semibold text-gray-800 mb-4">Connect</h3>
            <div className="flex space-x-4">
              <a href="#" className="text-gray-600 hover:text-primary">
                <Twitter size={20} />
              </a>
              <a href="#" className="text-gray-600 hover:text-primary">
                <Facebook size={20} />
              </a>
              <a href="#" className="text-gray-600 hover:text-primary">
                <Instagram size={20} />
              </a>
              <a href="#" className="text-gray-600 hover:text-primary">
                <Linkedin size={20} />
              </a>
            </div>
            <p className="text-gray-600 text-sm mt-4">© {new Date().getFullYear()} CurrencyPro. All rights reserved.</p>
          </div>
        </div>
      </div>
    </footer>
  );
}
