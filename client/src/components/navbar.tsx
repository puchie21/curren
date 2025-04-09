import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Ticket } from "lucide-react";
import { useLocation } from "wouter";

export default function Navbar() {
  const { user, logoutMutation } = useAuth();
  const [location, setLocation] = useLocation();
  
  const handleLogout = () => {
    logoutMutation.mutate();
  };
  
  const getInitials = (username: string) => {
    return username.substring(0, 2).toUpperCase();
  };
  
  return (
    <nav className="bg-white shadow-sm sticky top-0 z-10">
      <div className="container mx-auto px-4 py-3 flex justify-between items-center">
        <div className="flex items-center">
          <Button 
            variant="link" 
            className="text-primary text-xl font-bold p-0"
            onClick={() => setLocation('/')}
          >
            <Ticket className="mr-2" />
            CurrencyPro
          </Button>
        </div>
        
        {user ? (
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <Avatar className="h-8 w-8 bg-primary text-white mr-2">
                <AvatarFallback>{getInitials(user.username)}</AvatarFallback>
              </Avatar>
              <span className="font-medium">{user.username}</span>
            </div>
            <Button 
              variant="ghost" 
              onClick={handleLogout}
              disabled={logoutMutation.isPending}
              className="text-gray-600 hover:text-red-500"
            >
              {logoutMutation.isPending ? "Logging out..." : "Logout"}
            </Button>
          </div>
        ) : (
          <div className="flex items-center space-x-4">
            <Button 
              variant="ghost" 
              className="text-primary hover:text-primary/90 font-medium"
              onClick={() => setLocation('/auth')}
            >
              Log In
            </Button>
            <Button 
              className="bg-primary hover:bg-primary/90 text-white"
              onClick={() => {
                setLocation('/auth');
                // In a real implementation, we would set an active tab state here
              }}
            >
              Sign Up
            </Button>
          </div>
        )}
      </div>
    </nav>
  );
}
