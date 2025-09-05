import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Search, Wifi, AlertTriangle } from "lucide-react";
import RiskBar from "@/components/ui/risk-bar";
import { mockDevices } from "@/lib/mock-data";
import { useScrollReveal } from "@/hooks/use-scroll-reveal";

export default function Devices() {
  useScrollReveal();
  
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");

  const getStatusBadge = (status: string) => {
    const badges = {
      online: { icon: Wifi, className: "bg-green-100 text-green-800" },
      offline: { icon: Wifi, className: "bg-gray-100 text-gray-800" },
      warning: { icon: AlertTriangle, className: "bg-yellow-100 text-yellow-800" },
    };
    
    const badge = badges[status as keyof typeof badges] || badges.online;
    const Icon = badge.icon;
    
    return (
      <Badge className={badge.className}>
        <Icon className="w-3 h-3 mr-1" />
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </Badge>
    );
  };

  return (
    <div className="reveal-header">
      <div className="mb-8 reveal-header">
        <h1 className="text-3xl font-bold text-foreground mb-2">Device Management</h1>
        <p className="text-muted-foreground">Monitor and manage all network devices</p>
      </div>

      {/* Filters Section */}
      <Card className="mb-8 card-hover reveal-card">
        <CardContent className="p-6">
          <div className="flex flex-col md:flex-row gap-4">
            {/* Search Bar */}
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
                <Input
                  type="text"
                  placeholder="Search devices..."
                  className="pl-10"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  data-testid="device-search-input"
                />
              </div>
            </div>
            
            {/* Status Filter */}
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40" data-testid="status-filter">
                <SelectValue placeholder="All Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="online">Online</SelectItem>
                <SelectItem value="offline">Offline</SelectItem>
                <SelectItem value="warning">Warning</SelectItem>
              </SelectContent>
            </Select>
            
            {/* Risk Level Filter */}
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="w-48" data-testid="risk-filter">
                <SelectValue placeholder="All Risk Levels" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk Levels</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Device Inventory Table */}
      <Card className="card-hover reveal-table">
        <CardHeader>
          <CardTitle>Device Inventory</CardTitle>
          <p className="text-muted-foreground">Complete list of network devices and their security status</p>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device ID</TableHead>
                <TableHead>Network Info</TableHead>
                <TableHead>Manufacturer</TableHead>
                <TableHead>Firmware</TableHead>
                <TableHead>Risk Score</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Scan</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockDevices.map((device, index) => (
                <TableRow key={device.id} data-testid={`device-row-${index}`} className="table-row-transition">
                  <TableCell className="font-medium">{device.id}</TableCell>
                  <TableCell>
                    <div className="text-foreground">{device.ipAddress}</div>
                    <div className="text-sm text-muted-foreground">{device.deviceType}</div>
                  </TableCell>
                  <TableCell>{device.manufacturer}</TableCell>
                  <TableCell>{device.firmware}</TableCell>
                  <TableCell>
                    <RiskBar score={device.riskScore} />
                  </TableCell>
                  <TableCell>
                    {getStatusBadge(device.status)}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{device.lastScan}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
