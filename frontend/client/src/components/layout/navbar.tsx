import React from "react";
import { Link, useLocation } from "wouter";
import { Shield, Home, Server, Settings } from "lucide-react";
import { cn } from "@/lib/utils";

export default function Navbar() {
  const [location] = useLocation();

  const formatTime = () => {
    return new Date().toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    });
  };

  const [currentTime, setCurrentTime] = React.useState(formatTime());

  React.useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(formatTime());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const navItems = [
    { path: "/", label: "Home", icon: Home },
    { path: "/devices", label: "Devices", icon: Server },
    { path: "/settings", label: "Settings", icon: Settings },
  ];

  return (
    <nav className="bg-card border-b border-border px-6 py-4">
  <div className="flex items-center justify-between">
    {/* Logo (left side) */}
    <div className="flex items-center space-x-2">
      <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
        <Shield className="text-primary-foreground text-lg" />
      </div>
      <span className="text-xl font-bold text-foreground">Laurel</span>
    </div>

    {/* Navigation Links (right side) */}
    <div className="flex space-x-6">
      {navItems.map(({ path, label, icon: Icon }) => (
        <Link key={path} href={path}>
          <button
            data-testid={`nav-${label.toLowerCase()}`}
            className={cn(
              "flex items-center space-x-2 px-4 py-2 rounded-lg nav-transition",
              location === path
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground hover:bg-secondary"
            )}
          >
            <Icon className="w-4 h-4" />
            <span>{label}</span>
          </button>
        </Link>
      ))}
    </div>
  </div>
</nav>

  );
}
