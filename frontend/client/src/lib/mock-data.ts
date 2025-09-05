export const mockDevices = [
  {
    id: "RTR-001",
    ipAddress: "192.168.1.1",
    deviceType: "Router - Gateway",
    manufacturer: "Cisco",
    firmware: "IOS 15.9.3",
    riskScore: 87,
    status: "online",
    lastScan: "13 min ago",
  },
  {
    id: "SRV-002", 
    ipAddress: "192.168.1.50",
    deviceType: "Web Server",
    manufacturer: "Dell",
    firmware: "Ubuntu 22.04",
    riskScore: 53,
    status: "warning",
    lastScan: "26 min ago",
  },
  {
    id: "IOT-003",
    ipAddress: "192.168.1.250", 
    deviceType: "IoT Sensor",
    manufacturer: "Raspberry Pi",
    firmware: "Raspbian 11",
    riskScore: 21,
    status: "online",
    lastScan: "1 hour ago",
  },
];

export const mockOpenPorts = [
  {
    deviceId: "DEV-001",
    ipAddress: "192.168.1.100",
    ports: "22, 80, 443, 3389",
    suspicious: true,
    severity: "high",
  },
  {
    deviceId: "DEV-002",
    ipAddress: "192.168.1.150", 
    ports: "80, 443",
    suspicious: false,
    severity: "low",
  },
];

export const mockCves = [
  {
    id: "CVE-2024-0001",
    description: "Remote code execution in Apache server",
    severity: "critical",
    cvssScore: "9.8",
  },
  {
    id: "CVE-2024-0002",
    description: "SQL injection vulnerability in MySQL",
    severity: "high", 
    cvssScore: "8.5",
  },
];

export const mockUsers = [
  {
    id: "1",
    email: "admin@cyberguard.com",
    role: "Admin",
    status: "active",
  },
  {
    id: "2", 
    email: "analyst@cyberguard.com",
    role: "Analyst",
    status: "active",
  },
  {
    id: "3",
    email: "viewer@cyberguard.com", 
    role: "Viewer",
    status: "inactive",
  },
];
