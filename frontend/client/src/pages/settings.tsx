import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { User, Plus, Trash2 } from "lucide-react";
import { mockUsers } from "@/lib/mock-data";
import { useScrollReveal } from "@/hooks/use-scroll-reveal";

export default function Settings() {
  useScrollReveal();
  
  const [users, setUsers] = useState(mockUsers);
  const [isAddUserOpen, setIsAddUserOpen] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserRole, setNewUserRole] = useState("viewer");

  const getUserAvatar = (email: string) => {
    const colors = {
      "admin@cyberguard.com": "bg-primary",
      "analyst@cyberguard.com": "bg-blue-500", 
      "viewer@cyberguard.com": "bg-purple-500",
    };
    return colors[email as keyof typeof colors] || "bg-gray-500";
  };

  const getStatusBadge = (status: string) => {
    return status === "active" 
      ? "bg-green-100 text-green-800"
      : "bg-gray-100 text-gray-800";
  };

  const handleAddUser = () => {
    if (newUserEmail && newUserRole) {
      const newUser = {
        id: String(users.length + 1),
        email: newUserEmail,
        role: newUserRole.charAt(0).toUpperCase() + newUserRole.slice(1),
        status: "active",
      };
      setUsers([...users, newUser]);
      setNewUserEmail("");
      setNewUserRole("viewer");
      setIsAddUserOpen(false);
    }
  };

  const handleDeleteUser = (userId: string) => {
    setUsers(users.filter(user => user.id !== userId));
  };

  return (
    <div className="reveal-header">
      <div className="mb-8 reveal-header">
        <h1 className="text-3xl font-bold text-foreground mb-2">Settings</h1>
        <p className="text-muted-foreground">Manage your account and application preferences</p>
      </div>

      {/* User Management Section */}
      <Card className="mb-8 card-hover reveal-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>User Management</CardTitle>
            <Dialog open={isAddUserOpen} onOpenChange={setIsAddUserOpen}>
              <DialogTrigger asChild>
                <Button data-testid="add-user-button" className="btn-transition">
                  <Plus className="w-4 h-4 mr-2" />
                  Add User
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add New User</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="email">Email Address</Label>
                    <Input
                      id="email"
                      type="email"
                      placeholder="user@example.com"
                      value={newUserEmail}
                      onChange={(e) => setNewUserEmail(e.target.value)}
                      data-testid="new-user-email"
                    />
                  </div>
                  <div>
                    <Label htmlFor="role">Role</Label>
                    <Select value={newUserRole} onValueChange={setNewUserRole}>
                      <SelectTrigger data-testid="new-user-role">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="viewer">Viewer</SelectItem>
                        <SelectItem value="analyst">Analyst</SelectItem>
                        <SelectItem value="admin">Admin</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex space-x-3 pt-4">
                    <Button
                      variant="outline"
                      className="flex-1 btn-transition"
                      onClick={() => setIsAddUserOpen(false)}
                      data-testid="cancel-add-user"
                    >
                      Cancel
                    </Button>
                    <Button
                      className="flex-1 btn-transition"
                      onClick={handleAddUser}
                      data-testid="submit-add-user"
                    >
                      Add User
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          <h4 className="text-lg font-medium text-foreground mb-4">Current Users</h4>
          <div className="space-y-4">
            {users.map((user, index) => (
              <div 
                key={user.id} 
                className="flex items-center justify-between p-4 bg-secondary/30 rounded-lg"
                data-testid={`user-row-${index}`}
              >
                <div className="flex items-center space-x-3">
                  <div className={`w-10 h-10 ${getUserAvatar(user.email)} rounded-full flex items-center justify-center`}>
                    <User className="text-white w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-foreground font-medium">{user.email}</div>
                    <div className="text-sm text-muted-foreground">{user.role}</div>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <Badge className={getStatusBadge(user.status)}>
                    {user.status.charAt(0).toUpperCase() + user.status.slice(1)}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDeleteUser(user.id)}
                    className="text-muted-foreground hover:text-red-500 btn-transition"
                    data-testid={`delete-user-${index}`}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Security Settings Section */}
      <Card className="card-hover reveal-card">
        <CardHeader>
          <CardTitle>Security Settings</CardTitle>
        </CardHeader>
        <CardContent>
          {/* Two-Factor Authentication */}
          <div className="flex items-center justify-between py-4 border-b border-border">
            <div>
              <h4 className="text-lg font-medium text-foreground">Two-Factor Authentication</h4>
              <p className="text-sm text-muted-foreground">Add an extra layer of security to your account</p>
            </div>
            <Switch defaultChecked data-testid="2fa-toggle" />
          </div>

          {/* Session Timeout */}
          <div className="py-4 border-b border-border">
            <h4 className="text-lg font-medium text-foreground mb-2">Session Timeout</h4>
            <Select defaultValue="30min">
              <SelectTrigger className="w-full max-w-xs" data-testid="session-timeout">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="30min">30 minutes</SelectItem>
                <SelectItem value="1hour">1 hour</SelectItem>
                <SelectItem value="2hours">2 hours</SelectItem>
                <SelectItem value="4hours">4 hours</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Email Notifications */}
          <div className="pt-4">
            <h4 className="text-lg font-medium text-foreground mb-4">Email Notifications</h4>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-foreground">Critical vulnerabilities detected</span>
                <Switch defaultChecked data-testid="critical-alerts-toggle" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-foreground">Weekly security reports</span>
                <Switch defaultChecked data-testid="weekly-reports-toggle" />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
