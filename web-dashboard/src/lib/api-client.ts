import axios, { AxiosInstance } from 'axios';

// Type definitions
export interface GatewayStats {
  activePolicies: {
    count: number;
    changePercent: number;
    trend: 'up' | 'down' | 'stable';
  };
  apiRequests: {
    count: number;
    changePercent: number;
    trend: 'up' | 'down' | 'stable';
    period: string;
  };
  rateLimitViolations: {
    count: number;
    changePercent: number;
    trend: 'up' | 'down' | 'stable';
  };
  systemHealth: {
    percentage: number;
    status: 'healthy' | 'degraded' | 'critical';
    uptime: string;
  };
}

export interface SystemOverview {
  policyEngine: {
    performance: number;
    status: 'optimal' | 'good' | 'warning' | 'critical';
    responseTime: number;
  };
  cacheHitRate: {
    percentage: number;
    trend: 'up' | 'down' | 'stable';
  };
  rateLimitUtilization: {
    percentage: number;
    trend: 'up' | 'down' | 'stable';
  };
  providerHealth: {
    percentage: number;
    providers: {
      name: string;
      status: 'healthy' | 'degraded' | 'down';
      responseTime: number;
    }[];
  };
}

export interface RecentActivity {
  id: string;
  type: 'violation' | 'alert' | 'optimization' | 'config';
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  user?: string;
  resolved?: boolean;
}

export interface MetricsData {
  timestamp: string;
  requests: number;
  violations: number;
  responseTime: number;
  cacheHits: number;
}

export interface DashboardData {
  stats: GatewayStats;
  overview: SystemOverview;
  recentActivity: RecentActivity[];
  metrics: MetricsData[];
  lastUpdated: string;
}

export interface SystemMetrics {
  cpu: number;
  memory: number;
  disk: number;
  network: {
    bytesIn: number;
    bytesOut: number;
    connections: number;
  };
  uptime: number;
}

export interface Alert {
  id: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  title: string;
  message: string;
  timestamp: string;
  acknowledged: boolean;
  source: string;
}

export interface PerformanceMetrics {
  requestsPerSecond: number;
  averageResponseTime: number;
  errorRate: number;
  activeConnections: number;
  cacheHitRate: number;
}

export interface ProviderHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'down';
  responseTime: number;
  errorRate: number;
  lastCheck: string;
}

export interface AnalyticsData {
  period: string;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  totalTokens: number;
  cost: number;
  cacheHitRate: number;
  policyViolations: number;
  uniqueUsers: number;
}

export interface ProviderAnalytics {
  name: string;
  requests: number;
  errors: number;
  averageResponseTime: number;
  cost: number;
  tokens: number;
  successRate: number;
}

export interface PolicyAnalytics {
  name: string;
  evaluations: number;
  violations: number;
  averageEvaluationTime: number;
  impact: 'high' | 'medium' | 'low';
}

export interface UserAnalytics {
  userId: string;
  requests: number;
  violations: number;
  totalCost: number;
  lastActivity: string;
  status: 'active' | 'suspended' | 'inactive';
}

export interface TimeSeriesData {
  timestamp: string;
  requests: number;
  responseTime: number;
  errors: number;
  cost: number;
}

export class GatewayApiClient {
  private client: AxiosInstance;
  private baseURL: string;

  constructor(baseURL: string = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080') {
    this.baseURL = baseURL;
    this.client = axios.create({
      baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add auth token if available
        const token = typeof window !== 'undefined' ? localStorage?.getItem('auth-token') : null;
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        console.error('API Error:', error);
        return Promise.reject(error);
      }
    );
  }

  // Dashboard APIs
  async getDashboardStats(): Promise<GatewayStats> {
    try {
      const response = await this.client.get('/api/v1/dashboard/stats');
      return response.data;
    } catch {
      return this.getMockStats();
    }
  }

  async getSystemOverview(): Promise<SystemOverview> {
    try {
      const response = await this.client.get('/api/v1/dashboard/overview');
      return response.data;
    } catch {
      return this.getMockOverview();
    }
  }

  async getRecentActivity(limit: number = 10): Promise<RecentActivity[]> {
    try {
      const response = await this.client.get(`/api/v1/dashboard/activity?limit=${limit}`);
      return response.data;
    } catch {
      return this.getMockActivity();
    }
  }

  async getMetrics(hours: number = 24): Promise<MetricsData[]> {
    try {
      const response = await this.client.get(`/api/v1/dashboard/metrics?hours=${hours}`);
      return response.data;
    } catch {
      return this.getMockMetrics();
    }
  }

  async getDashboardData(): Promise<DashboardData> {
    try {
      const [stats, overview, activity, metrics] = await Promise.all([
        this.getDashboardStats(),
        this.getSystemOverview(),
        this.getRecentActivity(),
        this.getMetrics(),
      ]);

      return {
        stats,
        overview,
        recentActivity: activity,
        metrics,
        lastUpdated: new Date().toISOString(),
      };
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      throw error;
    }
  }

  // Health Check
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      const response = await this.client.get('/api/v1/health');
      return response.data;
    } catch {
      return { status: 'unavailable', timestamp: new Date().toISOString() };
    }
  }

  // Policy Management
  async getPolicies() {
    try {
      const response = await this.client.get('/api/v1/policies');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch policies:', error);
      throw error;
    }
  }

  async createPolicy(policy: Record<string, unknown>) {
    try {
      const response = await this.client.post('/api/v1/policies', policy);
      return response.data;
    } catch (error) {
      console.error('Failed to create policy:', error);
      throw error;
    }
  }

  async updatePolicy(id: string, policy: Record<string, unknown>) {
    try {
      const response = await this.client.put(`/api/v1/policies/${id}`, policy);
      return response.data;
    } catch (error) {
      console.error('Failed to update policy:', error);
      throw error;
    }
  }

  async deletePolicy(id: string) {
    try {
      const response = await this.client.delete(`/api/v1/policies/${id}`);
      return response.data;
    } catch (error) {
      console.error('Failed to delete policy:', error);
      throw error;
    }
  }

  // Monitoring APIs
  async getSystemMetrics(): Promise<SystemMetrics> {
    try {
      const response = await fetch(`${this.baseURL}/api/v1/monitoring/system`);
      if (!response.ok) {
        throw new Error('Failed to fetch system metrics');
      }
      return response.json();
    } catch {
      // Return mock data on error
      return {
        cpu: 45,
        memory: 68,
        disk: 23,
        network: {
          bytesIn: 1024000,
          bytesOut: 512000,
          connections: 150,
        },
        uptime: 86400,
      };
    }
  }

  async getAlerts(): Promise<Alert[]> {
    try {
      const response = await fetch(`${this.baseURL}/api/v1/monitoring/alerts`);
      if (!response.ok) {
        throw new Error('Failed to fetch alerts');
      }
      return response.json();
    } catch {
      // Return mock data on error
      return [
        {
          id: '1',
          severity: 'warning',
          title: 'High CPU Usage',
          message: 'CPU usage is above 80%',
          timestamp: new Date().toISOString(),
          acknowledged: false,
          source: 'system',
        },
      ];
    }
  }

  async getPerformanceMetrics(): Promise<PerformanceMetrics> {
    try {
      const response = await fetch(`${this.baseURL}/api/v1/monitoring/performance`);
      if (!response.ok) {
        throw new Error('Failed to fetch performance metrics');
      }
      return response.json();
    } catch {
      // Return mock data on error
      return {
        requestsPerSecond: 150,
        averageResponseTime: 45,
        errorRate: 0.5,
        activeConnections: 250,
        cacheHitRate: 85,
      };
    }
  }

  async getProviderHealth(): Promise<ProviderHealth[]> {
    try {
      const response = await fetch(`${this.baseURL}/api/v1/monitoring/providers`);
      if (!response.ok) {
        throw new Error('Failed to fetch provider health');
      }
      return response.json();
    } catch {
      // Return mock data on error
      return [
        {
          name: 'OpenAI',
          status: 'healthy',
          responseTime: 120,
          errorRate: 0.1,
          lastCheck: new Date().toISOString(),
        },
        {
          name: 'Anthropic',
          status: 'healthy',
          responseTime: 95,
          errorRate: 0.05,
          lastCheck: new Date().toISOString(),
        },
      ];
    }
  }

  // Analytics Methods
  async getAnalytics(timeRange: string): Promise<AnalyticsData> {
    try {
      const response = await this.client.post('/api/v1/analytics', { range: timeRange });
      return response.data;
    } catch {
      // Return mock data on error
      return {
        period: timeRange,
        totalRequests: 50000,
        successfulRequests: 48500,
        failedRequests: 1500,
        averageResponseTime: 120,
        totalTokens: 2500000,
        cost: 125.50,
        cacheHitRate: 85,
        policyViolations: 25,
        uniqueUsers: 1250,
      };
    }
  }

  async getProviderAnalytics(timeRange: string): Promise<ProviderAnalytics[]> {
    try {
      const response = await this.client.get(`/analytics/providers?range=${timeRange}`);
      return response.data;
    } catch {
      // Return mock data on error
      return [
        {
          name: 'OpenAI',
          requests: 25000,
          errors: 750,
          averageResponseTime: 125,
          cost: 75.25,
          tokens: 1500000,
          successRate: 97,
        },
        {
          name: 'Anthropic',
          requests: 20000,
          errors: 400,
          averageResponseTime: 95,
          cost: 50.25,
          tokens: 1000000,
          successRate: 98,
        },
      ];
    }
  }

  async getPolicyAnalytics(timeRange: string): Promise<PolicyAnalytics[]> {
    try {
      const response = await this.client.get(`/analytics/policies?range=${timeRange}`);
      return response.data;
    } catch {
      // Return mock data on error
      return [
        {
          name: 'PII Detection',
          evaluations: 50000,
          violations: 125,
          averageEvaluationTime: 5,
          impact: 'high',
        },
        {
          name: 'Rate Limiting',
          evaluations: 50000,
          violations: 2500,
          averageEvaluationTime: 2,
          impact: 'medium',
        },
      ];
    }
  }

  async getUserAnalytics(timeRange: string): Promise<UserAnalytics[]> {
    try {
      const response = await this.client.get(`/analytics/users?range=${timeRange}`);
      return response.data;
    } catch {
      // Return mock data on error
      return [
        {
          userId: 'user-123',
          requests: 5000,
          violations: 5,
          totalCost: 25.50,
          lastActivity: new Date().toISOString(),
          status: 'active',
        },
        {
          userId: 'user-456',
          requests: 3000,
          violations: 2,
          totalCost: 15.25,
          lastActivity: new Date().toISOString(),
          status: 'active',
        },
      ];
    }
  }

  async getTimeSeriesData(timeRange: string): Promise<TimeSeriesData[]> {
    try {
      const response = await this.client.get(`/analytics/timeseries?range=${timeRange}`);
      return response.data;
    } catch {
      // Return mock data on error
      const data: TimeSeriesData[] = [];
      const now = new Date();
      for (let i = 23; i >= 0; i--) {
        const timestamp = new Date(now.getTime() - i * 60 * 60 * 1000);
        data.push({
          timestamp: timestamp.toISOString(),
          requests: Math.floor(Math.random() * 1000) + 500,
          responseTime: Math.floor(Math.random() * 100) + 50,
          errors: Math.floor(Math.random() * 50) + 10,
          cost: Math.random() * 10 + 5,
        });
      }
      return data;
    }
  }

  async exportAnalyticsReport(format: string, filters: Record<string, unknown>): Promise<Blob> {
    try {
      const response = await this.client.post('/analytics/export', { format, filters }, {
        responseType: 'blob',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      return response.data;
    } catch (error) {
      console.error('Failed to export analytics report:', error);
      throw error;
    }
  }

  // Audit Logs
  async getAuditLogs() {
    try {
      const response = await this.client.get('/audit-logs');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch audit logs:', error);
      throw error;
    }
  }

  // Settings
  async getSystemSettings() {
    try {
      const response = await this.client.get('/api/v1/settings/system');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch system settings:', error);
      throw error;
    }
  }

  async getApiSettings() {
    try {
      const response = await this.client.get('/settings/api');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch API settings:', error);
      throw error;
    }
  }

  async getNotificationSettings() {
    try {
      const response = await this.client.get('/settings/notifications');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch notification settings:', error);
      throw error;
    }
  }

  async getSecuritySettings() {
    try {
      const response = await this.client.get('/settings/security');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch security settings:', error);
      throw error;
    }
  }

  async getCacheSettings() {
    try {
      const response = await this.client.get('/settings/cache');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch cache settings:', error);
      throw error;
    }
  }

  async updateSystemSettings(settings: Record<string, unknown>) {
    try {
      const response = await this.client.put('/api/v1/settings/system', settings);
      return response.data;
    } catch (error) {
      console.error('Failed to update system settings:', error);
      throw error;
    }
  }

  async updateApiSettings(settings: Record<string, unknown>) {
    try {
      const response = await this.client.put('/settings/api', settings);
      return response.data;
    } catch (error) {
      console.error('Failed to update API settings:', error);
      throw error;
    }
  }

  async updateNotificationSettings(settings: Record<string, unknown>) {
    try {
      const response = await this.client.put('/settings/notifications', settings);
      return response.data;
    } catch (error) {
      console.error('Failed to update notification settings:', error);
      throw error;
    }
  }

  async updateSecuritySettings(settings: Record<string, unknown>) {
    try {
      const response = await this.client.put('/settings/security', settings);
      return response.data;
    } catch (error) {
      console.error('Failed to update security settings:', error);
      throw error;
    }
  }

  async updateCacheSettings(settings: Record<string, unknown>) {
    try {
      const response = await this.client.put('/settings/cache', settings);
      return response.data;
    } catch (error) {
      console.error('Failed to update cache settings:', error);
      throw error;
    }
  }

  // Mock data methods for development
  private getMockStats(): GatewayStats {
    return {
      activePolicies: {
        count: 24,
        changePercent: 12,
        trend: 'up',
      },
      apiRequests: {
        count: 1200000,
        changePercent: 23,
        trend: 'up',
        period: '24h',
      },
      rateLimitViolations: {
        count: 15,
        changePercent: -8,
        trend: 'down',
      },
      systemHealth: {
        percentage: 99.9,
        status: 'healthy',
        uptime: '99.9%',
      },
    };
  }

  private getMockOverview(): SystemOverview {
    return {
      policyEngine: {
        performance: 92,
        status: 'optimal',
        responseTime: 45,
      },
      cacheHitRate: {
        percentage: 85,
        trend: 'up',
      },
      rateLimitUtilization: {
        percentage: 67,
        trend: 'stable',
      },
      providerHealth: {
        percentage: 98,
        providers: [
          { name: 'OpenAI', status: 'healthy', responseTime: 120 },
          { name: 'Anthropic', status: 'healthy', responseTime: 95 },
          { name: 'Azure OpenAI', status: 'degraded', responseTime: 250 },
        ],
      },
    };
  }

  private getMockActivity(): RecentActivity[] {
    const now = new Date();
    return [
      {
        id: '1',
        type: 'violation',
        title: 'PII Detection Alert',
        description: 'Sensitive data detected in API request from user@company.com',
        severity: 'high',
        timestamp: new Date(now.getTime() - 5 * 60000).toISOString(),
        user: 'user@company.com',
        resolved: false,
      },
      {
        id: '2',
        type: 'alert',
        title: 'Rate Limit Exceeded',
        description: 'User exceeded 1000 requests/hour limit',
        severity: 'medium',
        timestamp: new Date(now.getTime() - 15 * 60000).toISOString(),
        user: 'api-user-123',
        resolved: true,
      },
      {
        id: '3',
        type: 'optimization',
        title: 'Cache Performance Improved',
        description: 'Cache hit rate increased to 85% (+5%)',
        severity: 'low',
        timestamp: new Date(now.getTime() - 30 * 60000).toISOString(),
        resolved: true,
      },
      {
        id: '4',
        type: 'config',
        title: 'Policy Updated',
        description: 'Updated financial data classification policy',
        severity: 'low',
        timestamp: new Date(now.getTime() - 45 * 60000).toISOString(),
        user: 'admin@company.com',
        resolved: true,
      },
      {
        id: '5',
        type: 'violation',
        title: 'Unusual Request Pattern',
        description: 'Detected unusual request pattern from IP 192.168.1.100',
        severity: 'medium',
        timestamp: new Date(now.getTime() - 60 * 60000).toISOString(),
        resolved: false,
      },
    ];
  }

  private getMockMetrics(): MetricsData[] {
    const metrics: MetricsData[] = [];
    const now = new Date();
    
    for (let i = 23; i >= 0; i--) {
      const timestamp = new Date(now.getTime() - i * 60 * 60 * 1000);
      metrics.push({
        timestamp: timestamp.toISOString(),
        requests: Math.floor(Math.random() * 5000) + 2000,
        violations: Math.floor(Math.random() * 10) + 1,
        responseTime: Math.floor(Math.random() * 100) + 50,
        cacheHits: Math.floor(Math.random() * 1000) + 500,
      });
    }
    
    return metrics;
  }
}

// Export singleton instance
export const gatewayApi = new GatewayApiClient();
export default GatewayApiClient; 