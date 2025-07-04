import { useQuery } from '@tanstack/react-query';
import { gatewayApi } from '@/lib/api-client';

export const useDashboard = () => {
  return useQuery({
    queryKey: ['dashboard'],
    queryFn: () => gatewayApi.getDashboardData(),
    refetchInterval: 30000, // 30 seconds
    staleTime: 5000,
  });
};

// Hook for real-time system health
export const useSystemHealth = () => {
  return useQuery({
    queryKey: ['system', 'health'],
    queryFn: () => gatewayApi.healthCheck(),
    refetchInterval: 30000, // Check every 30 seconds
    staleTime: 15000,
    retry: 3,
  });
};

// Hook for performance metrics with custom time ranges
export const useMetrics = (hours: number = 24) => {
  return useQuery({
    queryKey: ['metrics', hours],
    queryFn: () => gatewayApi.getMetrics(hours),
    refetchInterval: hours <= 1 ? 60000 : 300000, // More frequent for shorter periods
    staleTime: hours <= 1 ? 30000 : 60000,
  });
};

export default useDashboard; 