import { type User, type InsertUser, type Device, type InsertDevice, type OpenPort, type InsertOpenPort, type Cve, type InsertCve } from "@shared/schema";
import { randomUUID } from "crypto";

// modify the interface with any CRUD methods
// you might need

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  getAllUsers(): Promise<User[]>;
  deleteUser(id: string): Promise<void>;
  getDashboardMetrics(): Promise<{ devices: number; openPorts: number; criticalCves: number }>;
  getAllDevices(): Promise<Device[]>;
  getAllOpenPorts(): Promise<OpenPort[]>;
  getAllCves(): Promise<Cve[]>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private devices: Map<string, Device>;
  private openPorts: Map<string, OpenPort>;
  private cves: Map<string, Cve>;

  constructor() {
    this.users = new Map();
    this.devices = new Map();
    this.openPorts = new Map();
    this.cves = new Map();
    this.initializeMockData();
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.email === email,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = { 
      ...insertUser, 
      id, 
      role: insertUser.role || "viewer",
      status: "active",
      createdAt: new Date()
    };
    this.users.set(id, user);
    return user;
  }

  async getAllUsers(): Promise<User[]> {
    return Array.from(this.users.values());
  }

  async deleteUser(id: string): Promise<void> {
    this.users.delete(id);
  }

  async getDashboardMetrics(): Promise<{ devices: number; openPorts: number; criticalCves: number }> {
    return {
      devices: this.devices.size,
      openPorts: this.openPorts.size,
      criticalCves: Array.from(this.cves.values()).filter(cve => cve.severity === "critical").length
    };
  }

  async getAllDevices(): Promise<Device[]> {
    return Array.from(this.devices.values());
  }

  async getAllOpenPorts(): Promise<OpenPort[]> {
    return Array.from(this.openPorts.values());
  }

  async getAllCves(): Promise<Cve[]> {
    return Array.from(this.cves.values());
  }

  private initializeMockData() {
    // Initialize mock users
    const mockUsers = [
      { id: "1", email: "admin@cyberguard.com", role: "admin", status: "active", createdAt: new Date() },
      { id: "2", email: "analyst@cyberguard.com", role: "analyst", status: "active", createdAt: new Date() },
      { id: "3", email: "viewer@cyberguard.com", role: "viewer", status: "inactive", createdAt: new Date() }
    ];
    mockUsers.forEach(user => this.users.set(user.id, user));

    // Initialize mock devices
    const mockDevices = [
      { id: "RTR-001", ipAddress: "192.168.1.1", deviceType: "Router - Gateway", manufacturer: "Cisco", firmware: "IOS 15.9.3", riskScore: 87, status: "online", lastScan: new Date() },
      { id: "SRV-002", ipAddress: "192.168.1.50", deviceType: "Web Server", manufacturer: "Dell", firmware: "Ubuntu 22.04", riskScore: 53, status: "warning", lastScan: new Date() },
      { id: "IOT-003", ipAddress: "192.168.1.250", deviceType: "IoT Sensor", manufacturer: "Raspberry Pi", firmware: "Raspbian 11", riskScore: 21, status: "online", lastScan: new Date() }
    ];
    mockDevices.forEach(device => this.devices.set(device.id, device));

    // Initialize mock open ports
    const mockOpenPorts = [
      { id: "1", deviceId: "DEV-001", ipAddress: "192.168.1.100", ports: "22, 80, 443, 3389", suspicious: true, severity: "high" },
      { id: "2", deviceId: "DEV-002", ipAddress: "192.168.1.150", ports: "80, 443", suspicious: false, severity: "low" }
    ];
    mockOpenPorts.forEach(port => this.openPorts.set(port.id, port));

    // Initialize mock CVEs
    const mockCves = [
      { id: "CVE-2024-0001", description: "Remote code execution in Apache server", severity: "critical", cvssScore: "9.8", discoveredAt: new Date() },
      { id: "CVE-2024-0002", description: "SQL injection vulnerability in MySQL", severity: "high", cvssScore: "8.5", discoveredAt: new Date() }
    ];
    mockCves.forEach(cve => this.cves.set(cve.id, cve));
  }
}

export const storage = new MemStorage();
