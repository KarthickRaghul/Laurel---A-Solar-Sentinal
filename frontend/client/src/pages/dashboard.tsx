import { useQuery } from "@tanstack/react-query";
import { Monitor, DoorOpen, AlertTriangle, TrendingUp } from "lucide-react";
import Header from "@/components/layout/header";
import SecurityOverview from "@/components/security/security-overview";
import ManualScan from "@/components/security/manual-scan";
import OpenPortsTable from "@/components/security/open-ports-table";
import CVEsTable from "@/components/security/cves-table";

export default function Dashboard() {
  const { data: dashboardData, isLoading } = useQuery({
    queryKey: ["/api/dashboard"],
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <div className="max-w-7xl mx-auto p-6">
          <div className="animate-pulse">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="bg-card rounded-xl p-6 border border-border">
                  <div className="h-4 bg-muted rounded w-1/2 mb-4"></div>
                  <div className="h-8 bg-muted rounded w-1/4 mb-2"></div>
                  <div className="h-3 bg-muted rounded w-3/4"></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const {
    deviceCount = 0,
    openPortsCount = 0,
    criticalCVECount = 0,
    securityItemsCount = 0,
  } = dashboardData || {};

  return (
    <div className="min-h-screen bg-background page-transition">
      <Header />
      
      <div className="max-w-7xl mx-auto p-6">
        {/* Dashboard Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {/* Devices Card */}
          <div className="bg-card rounded-xl p-6 border border-border card-transition">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-foreground">Devices</h3>
              <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center">
                <Monitor className="text-primary-foreground text-xl" />
              </div>
            </div>
            <div className="text-3xl font-bold text-primary mb-2" data-testid="text-device-count">
              {deviceCount}
            </div>
            <div className="text-sm text-muted-foreground mb-3">Active network devices</div>
            <div className="flex items-center text-sm">
              <TrendingUp className="text-primary mr-2 h-4 w-4" />
              <span className="text-primary">12%</span>
              <span className="text-muted-foreground ml-1">vs last week</span>
            </div>
          </div>

          {/* Open Ports Card */}
          <div className="bg-card rounded-xl p-6 border border-border card-transition">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-foreground">Open Ports</h3>
              <div className="w-12 h-12 bg-yellow-500 rounded-lg flex items-center justify-center">
                <DoorOpen className="text-white text-xl" />
              </div>
            </div>
            <div className="text-3xl font-bold text-yellow-500 mb-2" data-testid="text-open-ports-count">
              {openPortsCount}
            </div>
            <div className="text-sm text-muted-foreground mb-3">Detected open ports</div>
            <div className="flex items-center text-sm">
              <AlertTriangle className="text-yellow-500 mr-2 h-4 w-4" />
              <span className="text-yellow-500">High</span>
              <span className="text-muted-foreground ml-1">attention required</span>
            </div>
          </div>

          {/* Critical CVEs Card */}
          <div className="bg-card rounded-xl p-6 border border-border card-transition">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-foreground">Critical CVEs</h3>
              <div className="w-12 h-12 bg-destructive rounded-lg flex items-center justify-center">
                <AlertTriangle className="text-destructive-foreground text-xl" />
              </div>
            </div>
            <div className="text-3xl font-bold text-destructive mb-2" data-testid="text-critical-cve-count">
              {criticalCVECount}
            </div>
            <div className="text-sm text-muted-foreground mb-3">Critical vulnerabilities</div>
            <div className="flex items-center text-sm">
              <TrendingUp className="text-destructive mr-2 h-4 w-4" />
              <span className="text-destructive">5</span>
              <span className="text-muted-foreground ml-1">new this week</span>
            </div>
          </div>
        </div>

        {/* Manual Scan and Security Overview */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <ManualScan />
          <SecurityOverview
            deviceCount={deviceCount}
            openPortsCount={openPortsCount}
            criticalCVECount={criticalCVECount}
            securityItemsCount={securityItemsCount}
          />
        </div>

        {/* Open Ports Table */}
        <OpenPortsTable />

        {/* Latest CVEs */}
        <CVEsTable />
      </div>
    </div>
  );
}
