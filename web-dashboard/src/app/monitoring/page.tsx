'use client';

import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Button,
  Stack,
  Chip,
  IconButton,
  Alert,
  Skeleton,
  Tooltip,
  Badge,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  LinearProgress,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  Info as InfoIcon,
  Speed as SpeedIcon,
  Memory as MemoryIcon,
  Storage as StorageIcon,
  NetworkCheck as NetworkIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
} from 'recharts';
import { ThemeProvider } from '@/components/ThemeProvider';
import { QueryProvider } from '@/components/QueryProvider';
import { useQuery } from '@tanstack/react-query';
import { gatewayApi } from '@/lib/api-client';

// Monitoring Types
interface SystemMetrics {
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

interface Alert {
  id: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  title: string;
  message: string;
  timestamp: string;
  acknowledged: boolean;
  source: string;
}

interface PerformanceMetrics {
  requestsPerSecond: number;
  averageResponseTime: number;
  errorRate: number;
  activeConnections: number;
  cacheHitRate: number;
}

interface ProviderHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'down';
  responseTime: number;
  errorRate: number;
  lastCheck: string;
}

// Mock data for development
const mockSystemMetrics: SystemMetrics = {
  cpu: 45.2,
  memory: 67.8,
  disk: 23.4,
  network: {
    bytesIn: 1024000,
    bytesOut: 512000,
    connections: 1250,
  },
  uptime: 86400, // 24 hours in seconds
};

const mockAlerts: Alert[] = [
  {
    id: '1',
    severity: 'warning',
    title: 'High CPU Usage',
    message: 'CPU usage has exceeded 80% for the last 5 minutes',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    acknowledged: false,
    source: 'system',
  },
  {
    id: '2',
    severity: 'error',
    title: 'Provider Timeout',
    message: 'OpenAI API requests are timing out',
    timestamp: new Date(Date.now() - 600000).toISOString(),
    acknowledged: true,
    source: 'providers',
  },
  {
    id: '3',
    severity: 'info',
    title: 'Policy Update',
    message: 'New security policy has been deployed',
    timestamp: new Date(Date.now() - 900000).toISOString(),
    acknowledged: false,
    source: 'policies',
  },
];

const mockPerformanceMetrics: PerformanceMetrics = {
  requestsPerSecond: 1250,
  averageResponseTime: 245,
  errorRate: 2.3,
  activeConnections: 850,
  cacheHitRate: 78.5,
};

const mockProviderHealth: ProviderHealth[] = [
  {
    name: 'OpenAI',
    status: 'healthy',
    responseTime: 180,
    errorRate: 0.5,
    lastCheck: new Date().toISOString(),
  },
  {
    name: 'Anthropic',
    status: 'degraded',
    responseTime: 450,
    errorRate: 3.2,
    lastCheck: new Date().toISOString(),
  },
];

// Chart data
const generateTimeSeriesData = (count: number, baseValue: number, variance: number) => {
  return Array.from({ length: count }, (_, i) => ({
    time: new Date(Date.now() - (count - i) * 60000).toLocaleTimeString(),
    value: baseValue + (Math.random() - 0.5) * variance,
  }));
};

const requestData = generateTimeSeriesData(20, 1200, 200);
const responseTimeData = generateTimeSeriesData(20, 250, 50);

const cacheData = [
  { name: 'Cache Hits', value: 78.5, color: '#4caf50' },
  { name: 'Cache Misses', value: 21.5, color: '#ff9800' },
];

const providerData = [
  { name: 'OpenAI', requests: 850, errors: 4, color: '#2196f3' },
  { name: 'Anthropic', requests: 400, errors: 13, color: '#9c27b0' },
];

// Monitoring Dashboard Component
function MonitoringDashboard() {
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Fetch monitoring data
  const {
    data: systemMetrics = mockSystemMetrics,
    isLoading: systemLoading,
    error: systemError,
    refetch: refetchSystem,
  } = useQuery({
    queryKey: ['system-metrics'],
    queryFn: async () => {
      try {
        return await gatewayApi.getSystemMetrics();
      } catch (error) {
        return mockSystemMetrics;
      }
    },
    refetchInterval: autoRefresh ? 30000 : false,
  });

  const {
    data: alerts = mockAlerts,
    isLoading: alertsLoading,
    error: alertsError,
    refetch: refetchAlerts,
  } = useQuery({
    queryKey: ['alerts'],
    queryFn: async () => {
      try {
        return await gatewayApi.getAlerts();
      } catch (error) {
        return mockAlerts;
      }
    },
    refetchInterval: autoRefresh ? 10000 : false,
  });

  const {
    data: performanceMetrics = mockPerformanceMetrics,
    isLoading: performanceLoading,
    error: performanceError,
    refetch: refetchPerformance,
  } = useQuery({
    queryKey: ['performance-metrics'],
    queryFn: async () => {
      try {
        return await gatewayApi.getPerformanceMetrics();
      } catch (error) {
        return mockPerformanceMetrics;
      }
    },
    refetchInterval: autoRefresh ? 15000 : false,
  });

  const {
    data: providerHealth = mockProviderHealth,
    isLoading: providerLoading,
    error: providerError,
    refetch: refetchProviders,
  } = useQuery({
    queryKey: ['provider-health'],
    queryFn: async () => {
      try {
        return await gatewayApi.getProviderHealth();
      } catch (error) {
        return mockProviderHealth;
      }
    },
    refetchInterval: autoRefresh ? 20000 : false,
  });

  const handleRefresh = () => {
    refetchSystem();
    refetchAlerts();
    refetchPerformance();
    refetchProviders();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'success';
      case 'degraded': return 'warning';
      case 'down': return 'error';
      default: return 'default';
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const unacknowledgedAlerts = alerts.filter(alert => !alert.acknowledged);
  const criticalAlerts = alerts.filter(alert => alert.severity === 'critical' || alert.severity === 'error');

  return (
    <Box sx={{ flexGrow: 1, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Container maxWidth="xl" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Stack direction="row" alignItems="center" spacing={2} mb={2}>
            <TimelineIcon color="primary" sx={{ fontSize: 32 }} />
            <Typography variant="h4" component="h1" fontWeight="bold">
              Real-time Monitoring
            </Typography>
            <Badge badgeContent={unacknowledgedAlerts.length} color="error">
              <Chip label="Active Alerts" variant="outlined" />
            </Badge>
            <Badge badgeContent={criticalAlerts.length} color="error">
              <Chip label="Critical" variant="outlined" />
            </Badge>
          </Stack>
          <Typography variant="body1" color="text.secondary">
            Monitor AI Gateway performance, system health, and real-time alerts
          </Typography>
        </Box>

        {/* Critical Alerts Banner */}
        {criticalAlerts.length > 0 && (
          <Alert severity="error" sx={{ mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Critical Alerts Active ({criticalAlerts.length})
            </Typography>
            <Typography variant="body2">
              {criticalAlerts.map(alert => alert.title).join(', ')}
            </Typography>
          </Alert>
        )}

        {/* System Overview Cards */}
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mb: 4 }}>
          <Box sx={{ flex: '1 1 250px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <SpeedIcon color="primary" />
                  <Typography variant="h6">CPU Usage</Typography>
                </Stack>
                <Typography variant="h4" color="primary" gutterBottom>
                  {systemMetrics.cpu.toFixed(1)}%
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={systemMetrics.cpu} 
                  color={systemMetrics.cpu > 80 ? 'error' : systemMetrics.cpu > 60 ? 'warning' : 'primary'}
                  sx={{ height: 8, borderRadius: 4 }}
                />
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 250px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <MemoryIcon color="primary" />
                  <Typography variant="h6">Memory Usage</Typography>
                </Stack>
                <Typography variant="h4" color="primary" gutterBottom>
                  {systemMetrics.memory.toFixed(1)}%
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={systemMetrics.memory} 
                  color={systemMetrics.memory > 80 ? 'error' : systemMetrics.memory > 60 ? 'warning' : 'primary'}
                  sx={{ height: 8, borderRadius: 4 }}
                />
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 250px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <StorageIcon color="primary" />
                  <Typography variant="h6">Disk Usage</Typography>
                </Stack>
                <Typography variant="h4" color="primary" gutterBottom>
                  {systemMetrics.disk.toFixed(1)}%
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={systemMetrics.disk} 
                  color={systemMetrics.disk > 80 ? 'error' : systemMetrics.disk > 60 ? 'warning' : 'primary'}
                  sx={{ height: 8, borderRadius: 4 }}
                />
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 250px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <NetworkIcon color="primary" />
                  <Typography variant="h6">Network</Typography>
                </Stack>
                <Typography variant="h6" color="primary" gutterBottom>
                  {formatBytes(systemMetrics.network.bytesIn)}/s
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {systemMetrics.network.connections} connections
                </Typography>
              </CardContent>
            </Card>
          </Box>
        </Box>

        {/* Performance Metrics */}
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mb: 4 }}>
          <Box sx={{ flex: '1 1 500px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Requests per Second
                </Typography>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={requestData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <RechartsTooltip />
                    <Line type="monotone" dataKey="value" stroke="#2196f3" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 500px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Response Time (ms)
                </Typography>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={responseTimeData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <RechartsTooltip />
                    <Area type="monotone" dataKey="value" stroke="#4caf50" fill="#4caf50" fillOpacity={0.3} />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Box>
        </Box>

        {/* Provider Health and Cache Performance */}
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mb: 4 }}>
          <Box sx={{ flex: '1 1 500px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Provider Health
                </Typography>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={providerData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="requests" fill="#2196f3" />
                    <Bar dataKey="errors" fill="#f44336" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 500px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Cache Performance
                </Typography>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={cacheData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${((percent || 0) * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {cacheData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Box>
        </Box>

        {/* Alerts and Provider Status */}
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
          <Box sx={{ flex: '2 1 600px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
                  <Typography variant="h6">
                    Recent Alerts
                  </Typography>
                  <Button
                    size="small"
                    startIcon={<RefreshIcon />}
                    onClick={handleRefresh}
                  >
                    Refresh
                  </Button>
                </Stack>
                <List>
                  {alerts.slice(0, 5).map((alert, index) => (
                    <React.Fragment key={alert.id}>
                      <ListItem>
                        <ListItemIcon>
                          {alert.severity === 'critical' && <ErrorIcon color="error" />}
                          {alert.severity === 'error' && <ErrorIcon color="error" />}
                          {alert.severity === 'warning' && <WarningIcon color="warning" />}
                          {alert.severity === 'info' && <InfoIcon color="info" />}
                        </ListItemIcon>
                        <ListItemText
                          primary={alert.title}
                          secondary={
                            <Stack direction="row" spacing={1} alignItems="center">
                              <Typography variant="body2" color="text.secondary">
                                {new Date(alert.timestamp).toLocaleString()}
                              </Typography>
                              <Chip 
                                label={alert.source} 
                                size="small" 
                                variant="outlined" 
                              />
                              {!alert.acknowledged && (
                                <Chip 
                                  label="New" 
                                  size="small" 
                                  color="error" 
                                />
                              )}
                            </Stack>
                          }
                        />
                      </ListItem>
                      {index < alerts.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 300px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Provider Status
                </Typography>
                <Stack spacing={2}>
                  {providerHealth.map((provider) => (
                    <Box key={provider.name}>
                      <Stack direction="row" alignItems="center" justifyContent="space-between">
                        <Typography variant="body1" fontWeight={500}>
                          {provider.name}
                        </Typography>
                        <Chip
                          label={provider.status}
                          size="small"
                          color={getStatusColor(provider.status) as any}
                          variant="outlined"
                        />
                      </Stack>
                      <Typography variant="body2" color="text.secondary">
                        {provider.responseTime}ms • {provider.errorRate.toFixed(1)}% errors
                      </Typography>
                    </Box>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          </Box>
        </Box>
      </Container>
    </Box>
  );
}

// Main Page Component
export default function MonitoringPage() {
  return (
    <QueryProvider>
      <ThemeProvider>
        <MonitoringDashboard />
      </ThemeProvider>
    </QueryProvider>
  );
} 