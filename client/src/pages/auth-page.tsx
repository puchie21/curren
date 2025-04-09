import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { insertUserSchema } from "@shared/schema";
import { useAuth } from "@/hooks/use-auth";
import Navbar from "@/components/navbar";
import Footer from "@/components/footer";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ArrowRight, Ticket } from "lucide-react";

const loginSchema = insertUserSchema.pick({
  username: true,
  password: true,
});

const registerSchema = insertUserSchema.extend({
  confirmPassword: z.string(),
  terms: z.boolean().refine(val => val === true, {
    message: "You must accept the terms and conditions",
  }),
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"],
});

export default function AuthPage() {
  const [activeTab, setActiveTab] = useState<string>("login");
  const { user, loginMutation, registerMutation } = useAuth();
  const [_, setLocation] = useLocation();

  const loginForm = useForm<z.infer<typeof loginSchema>>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: "",
      password: "",
    },
  });

  const registerForm = useForm<z.infer<typeof registerSchema>>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      username: "",
      password: "",
      confirmPassword: "",
      terms: false,
    },
  });

  // Redirect if user is already logged in
  useEffect(() => {
    if (user) {
      setLocation("/");
    }
  }, [user, setLocation]);

  function onLoginSubmit(values: z.infer<typeof loginSchema>) {
    loginMutation.mutate(values);
  }

  function onRegisterSubmit(values: z.infer<typeof registerSchema>) {
    const { confirmPassword, terms, ...userData } = values;
    registerMutation.mutate(userData);
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-grow py-8 px-4">
        <div className="container mx-auto max-w-5xl">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
            {/* Form Side */}
            <div>
              <Tabs 
                defaultValue="login" 
                value={activeTab} 
                onValueChange={setActiveTab}
                className="w-full"
              >
                <TabsList className="grid w-full grid-cols-2 mb-6">
                  <TabsTrigger value="login">Login</TabsTrigger>
                  <TabsTrigger value="register">Register</TabsTrigger>
                </TabsList>
                
                <TabsContent value="login">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-2xl">Login to your account</CardTitle>
                      <CardDescription>
                        Enter your credentials to access the currency converter
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Form {...loginForm}>
                        <form onSubmit={loginForm.handleSubmit(onLoginSubmit)} className="space-y-4">
                          <FormField
                            control={loginForm.control}
                            name="username"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Username</FormLabel>
                                <FormControl>
                                  <Input placeholder="yourname@example.com" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={loginForm.control}
                            name="password"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Password</FormLabel>
                                <FormControl>
                                  <Input type="password" placeholder="••••••••" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <Checkbox id="remember" />
                              <Label htmlFor="remember" className="text-sm text-gray-700">Remember me</Label>
                            </div>
                            <Button variant="link" className="text-sm p-0 h-auto">
                              Forgot password?
                            </Button>
                          </div>
                          
                          <Button 
                            type="submit" 
                            className="w-full"
                            disabled={loginMutation.isPending}
                          >
                            {loginMutation.isPending ? "Logging in..." : "Log In"}
                          </Button>
                          
                          <div className="text-center text-sm text-gray-600">
                            Don't have an account?{" "}
                            <Button 
                              variant="link" 
                              className="p-0" 
                              onClick={() => setActiveTab("register")}
                            >
                              Sign up
                            </Button>
                          </div>
                        </form>
                      </Form>
                    </CardContent>
                  </Card>
                </TabsContent>
                
                <TabsContent value="register">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-2xl">Create a new account</CardTitle>
                      <CardDescription>
                        Enter your details to register and start using CurrencyPro
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Form {...registerForm}>
                        <form onSubmit={registerForm.handleSubmit(onRegisterSubmit)} className="space-y-4">
                          <FormField
                            control={registerForm.control}
                            name="username"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Username</FormLabel>
                                <FormControl>
                                  <Input placeholder="yourname@example.com" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={registerForm.control}
                            name="password"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Password</FormLabel>
                                <FormControl>
                                  <Input type="password" placeholder="••••••••" {...field} />
                                </FormControl>
                                <FormMessage />
                                <p className="text-xs text-gray-500 mt-1">Must be at least 8 characters long</p>
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={registerForm.control}
                            name="confirmPassword"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Confirm Password</FormLabel>
                                <FormControl>
                                  <Input type="password" placeholder="••••••••" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={registerForm.control}
                            name="terms"
                            render={({ field }) => (
                              <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                                <FormControl>
                                  <Checkbox 
                                    checked={field.value} 
                                    onCheckedChange={field.onChange} 
                                  />
                                </FormControl>
                                <div className="space-y-1 leading-none">
                                  <FormLabel className="text-sm text-gray-700">
                                    I agree to the <Button variant="link" className="p-0 h-auto">Terms of Service</Button> and <Button variant="link" className="p-0 h-auto">Privacy Policy</Button>
                                  </FormLabel>
                                  <FormMessage />
                                </div>
                              </FormItem>
                            )}
                          />
                          
                          <Button 
                            type="submit" 
                            className="w-full"
                            disabled={registerMutation.isPending}
                          >
                            {registerMutation.isPending ? "Creating Account..." : "Create Account"}
                          </Button>
                          
                          <div className="text-center text-sm text-gray-600">
                            Already have an account?{" "}
                            <Button 
                              variant="link" 
                              className="p-0" 
                              onClick={() => setActiveTab("login")}
                            >
                              Log in
                            </Button>
                          </div>
                        </form>
                      </Form>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            </div>
            
            {/* Hero Side */}
            <div className="bg-gradient-to-r from-primary/80 to-primary p-8 rounded-lg text-white shadow-lg hidden md:block">
              <div className="space-y-6">
                <h2 className="text-3xl font-bold">CurrencyPro</h2>
                <p className="text-xl">Your reliable currency converter with real-time exchange rates</p>
                <ul className="space-y-4">
                  <li className="flex items-center gap-2">
                    <ArrowRight size={20} className="shrink-0" />
                    <span>Access to 100+ global currencies</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <ArrowRight size={20} className="shrink-0" />
                    <span>Real-time exchange rates</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <ArrowRight size={20} className="shrink-0" />
                    <span>Track your conversion history</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <ArrowRight size={20} className="shrink-0" />
                    <span>Simple and intuitive interface</span>
                  </li>
                </ul>
                <div className="pt-4">
                  <div className="bg-white/10 p-4 rounded-lg backdrop-blur-sm">
                    <div className="flex items-center justify-center gap-4">
                      <div className="text-2xl font-semibold">$100 USD</div>
                      <Ticket size={24} />
                      <div className="text-2xl font-semibold">€92 EUR</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}
