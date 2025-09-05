import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

interface SecurityOverviewChartProps {
  data: {
    devices: number;
    openPorts: number;
    criticalCves: number;
  };
}

export default function SecurityOverviewChart({ data }: SecurityOverviewChartProps) {
  const chartData = [
    { name: "Devices", value: data.devices, color: "#39ff14" },
    { name: "Open Ports", value: data.openPorts, color:"#028A0F"  },
    { name: "Critical CVEs", value: data.criticalCves, color: "#A3F359" },
  ];

  const total = data.devices + data.openPorts + data.criticalCves;

  return (
    <div className="p-6 rounded-xl bg-[#313E47]">
      <div className="flex items-center justify-between">
        {/* Circular Chart */}
        <div className="relative w-48 h-48">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={70}
                outerRadius={96}
                paddingAngle={0}
                dataKey="value"
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <div className="text-3xl font-bold text-white">{total}</div>
            <div className="text-sm text-gray-200">Security Items</div>
          </div>
        </div>
        
        {/* Details */}
        <div className="space-y-4">
          {chartData.map((item) => (
            <div key={item.name} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div 
                  className="w-3 h-3 rounded-full" 
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-white">{item.name}</span>
              </div>
              <span className="text-white font-medium">{item.value}</span>
            </div>
          ))}
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-3 h-3 bg-gray-500 rounded-full" />
              <span className="text-white">Other</span>
            </div>
            <span className="text-white font-medium">—</span>
          </div>
        </div>
      </div>
    </div>
  );
}
