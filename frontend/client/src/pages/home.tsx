import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Server, DoorOpen, AlertCircle, Search, TrendingUp, Wifi } from "lucide-react";
import SecurityOverviewChart from "@/components/charts/security-overview-chart";
import { mockDevices, mockOpenPorts, mockCves } from "@/lib/mock-data";
import { useScrollReveal } from "@/hooks/use-scroll-reveal";

export default function Home() {
  useScrollReveal();
  
  const metrics = {
    devices: 4,
    openPorts: 4,
    criticalCves: 1,
  };

  const getSeverityBadge = (severity: string) => {
    const variants = {
      critical: "bg-red-100 text-red-800",
      high: "bg-red-100 text-red-800", 
      medium: "bg-yellow-100 text-yellow-800",
      low: "bg-green-100 text-green-800",
    };
    return variants[severity as keyof typeof variants] || variants.low;
  };

  const getSuspiciousBadge = (suspicious: boolean) => {
    return suspicious 
      ? "bg-red-100 text-red-800"
      : "bg-green-100 text-green-800";
  };

  return (
    <div className="reveal-header">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* Devices Card */}
        <Card className="card-hover reveal-card">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-foreground mb-1">Devices</h3>
                <div className="text-3xl font-bold text-primary mb-2" data-testid="devices-count">
                  {metrics.devices}
                </div>
                <p className="text-sm text-muted-foreground">Active network devices</p>
                <div className="flex items-center mt-2 text-sm text-primary">
                  <TrendingUp className="w-4 h-4 mr-1" />
                  <span>12% vs last week</span>
                </div>
              </div>
              <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center">
                <Server className="text-primary text-xl" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Open Ports Card */}
        <Card className="card-hover reveal-card">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-foreground mb-1">Open Ports</h3>
                <div className="text-3xl font-bold text-yellow-500 mb-2" data-testid="open-ports-count">
                  {metrics.openPorts}
                </div>
                <p className="text-sm text-muted-foreground">Detected open ports</p>
                <div className="flex items-center mt-2 text-sm text-yellow-500">
                  <AlertCircle className="w-4 h-4 mr-1" />
                  <span>High attention required</span>
                </div>
              </div>
              <div className="w-12 h-12 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                <DoorOpen className="text-yellow-500 text-xl" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Critical CVEs Card */}
        <Card className="card-hover reveal-card">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-foreground mb-1">Critical CVEs</h3>
                <div className="text-3xl font-bold text-red-500 mb-2" data-testid="critical-cves-count">
                  {metrics.criticalCves}
                </div>
                <p className="text-sm text-muted-foreground">Critical vulnerabilities</p>
                <div className="flex items-center mt-2 text-sm text-red-500">
                  <TrendingUp className="w-4 h-4 mr-1" />
                  <span>5 new this week</span>
                </div>
              </div>
              <div className="w-12 h-12 bg-red-500/20 rounded-lg flex items-center justify-center">
                <AlertCircle className="text-red-500 text-xl" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Security Overview and Manual Scan */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Security Overview */}
        <Card className="lg:col-span-2 card-hover reveal-chart bg-[#313E47]">
          <CardHeader>
            <CardTitle>Security Overview</CardTitle>
          </CardHeader>
          <CardContent>
            <SecurityOverviewChart data={metrics} />
          </CardContent>
        </Card>

        {/* Manual Scan */}
        <Card className="card-hover reveal-card">
          <CardHeader>
            <CardTitle>Manual Scan</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground mb-6">
              Initiate a comprehensive network security scan to identify vulnerabilities and threats
            </p>
            <Button 
              className="w-full btn-transition" 
              data-testid="start-scan-button"
            >
              <Search className="w-4 h-4 mr-2" />
              Start Security Scan
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Open Ports Table */}
      <Card className="mb-8 card-hover reveal-table">
        <CardHeader>
          <CardTitle>Open Ports</CardTitle>
          <p className="text-muted-foreground">Network ports currently accessible</p>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device ID</TableHead>
                <TableHead>IP Address</TableHead>
                <TableHead>Open Ports</TableHead>
                <TableHead>Suspicious</TableHead>
                <TableHead>Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockOpenPorts.map((port, index) => (
                <TableRow key={index} data-testid={`open-port-row-${index}`} className="table-row-transition">
                  <TableCell className="font-medium">{port.deviceId}</TableCell>
                  <TableCell>{port.ipAddress}</TableCell>
                  <TableCell>{port.ports}</TableCell>
                  <TableCell>
                    <Badge className={getSuspiciousBadge(port.suspicious)}>
                      {port.suspicious ? "Yes" : "No"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge className={getSeverityBadge(port.severity)}>
                      {port.severity.charAt(0).toUpperCase() + port.severity.slice(1)}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Latest CVEs Table */}
      <Card className="card-hover reveal-table">
        <CardHeader>
          <CardTitle>Latest CVEs</CardTitle>
          <p className="text-muted-foreground">Recent vulnerabilities discovered</p>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>CVE ID</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>CVSS</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockCves.map((cve, index) => (
                <TableRow key={index} data-testid={`cve-row-${index}`} className="table-row-transition">
                  <TableCell className="font-medium text-primary">{cve.id}</TableCell>
                  <TableCell>{cve.description}</TableCell>
                  <TableCell>
                    <Badge className={getSeverityBadge(cve.severity)}>
                      {cve.severity.charAt(0).toUpperCase() + cve.severity.slice(1)}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-medium">{cve.cvssScore}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
