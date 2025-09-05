import { cn } from "@/lib/utils";

interface RiskBarProps {
  score: number;
  className?: string;
}

export default function RiskBar({ score, className }: RiskBarProps) {
  const getRiskColor = (score: number) => {
    if (score >= 80) return "bg-red-500";
    if (score >= 60) return "bg-yellow-500";
    if (score >= 40) return "bg-orange-500";
    return "bg-green-500";
  };

  const getRiskTextColor = (score: number) => {
    if (score >= 80) return "text-red-500";
    if (score >= 60) return "text-yellow-500";
    if (score >= 40) return "text-orange-500";
    return "text-green-500";
  };

  return (
    <div className={cn("flex items-center space-x-2", className)}>
      <span className={cn("font-bold", getRiskTextColor(score))}>{score}</span>
      <div className="risk-bar w-20">
        <div 
          className={cn("risk-bar-fill", getRiskColor(score))}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}
