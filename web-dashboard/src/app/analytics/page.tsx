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
  Alert,
  Badge,
  Tabs,
  Tab,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Switch,
  FormControlLabel,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  Assessment as AssessmentIcon,
  BarChart as BarChartIcon,
  PieChart as PieChartIcon,
  Timeline as TimelineIcon,
  GetApp as ExportIcon,
} from '@mui/icons-material';
import {
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
  Legend,
  ResponsiveContainer,
  ComposedChart,
} from 'recharts';
import { ThemeProvider } from '@/components/ThemeProvider';
import { QueryProvider } from '@/components/QueryProvider';
import { useQuery } from '@tanstack/react-query';
import { gatewayApi } from '@/lib/api-client';

// Mock data for development
const mockAnalyticsData = {
  period: 'Last 30 Days',
  totalRequests: 2450000,
  successfulRequests: 2380000,
  failedRequests: 70000,
  averageResponseTime: 245,
  totalTokens: 1250000000,
  cost: 12500.50,
  cacheHitRate: 78.5,
  policyViolations: 1250,
  uniqueUsers: 1250,
};

const mockProviderAnalytics = [
  {
    name: 'OpenAI GPT-4',
    requests: 1200000,
    errors: 15000,
    averageResponseTime: 180,
    cost: 8500.25,
    tokens: 750000000,
    successRate: 98.75,
  },
  {
    name: 'Anthropic Claude',
    requests: 800000,
    errors: 8000,
    averageResponseTime: 220,
    cost: 3200.15,
    tokens: 400000000,
    successRate: 99.00,
  },
  {
    name: 'Azure OpenAI',
    requests: 450000,
    errors: 47000,
    averageResponseTime: 350,
    cost: 800.10,
    tokens: 100000000,
    successRate: 89.56,
  },
];

const mockPolicyAnalytics = [
  {
    name: 'PII Detection',
    evaluations: 2450000,
    violations: 1250,
    averageEvaluationTime: 12,
    impact: 'high' as const,
  },
  {
    name: 'Rate Limiting',
    evaluations: 2450000,
    violations: 850,
    averageEvaluationTime: 8,
    impact: 'medium' as const,
  },
  {
    name: 'Content Classification',
    evaluations: 1800000,
    violations: 320,
    averageEvaluationTime: 25,
    impact: 'low' as const,
  },
];

const mockUserAnalytics = [
  {
    userId: 'user-001',
    requests: 45000,
    violations: 12,
    totalCost: 450.25,
    lastActivity: '2024-01-15T10:30:00Z',
    status: 'active' as const,
  },
  {
    userId: 'user-002',
    requests: 32000,
    violations: 8,
    totalCost: 320.15,
    lastActivity: '2024-01-15T09:15:00Z',
    status: 'active' as const,
  },
  {
    userId: 'user-003',
    requests: 28000,
    violations: 25,
    totalCost: 280.75,
    lastActivity: '2024-01-14T16:45:00Z',
    status: 'suspended' as const,
  },
];

// Generate time series data
const generateTimeSeriesData = (days: number) => {
  return Array.from({ length: days }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (days - i - 1));
    return {
      timestamp: date.toISOString().split('T')[0],
      requests: Math.floor(Math.random() * 50000) + 50000,
      responseTime: Math.floor(Math.random() * 100) + 150,
      errors: Math.floor(Math.random() * 1000) + 100,
      cost: Math.floor(Math.random() * 500) + 200,
    };
  });
};

const timeSeriesData = generateTimeSeriesData(30);

// Chart data
const costBreakdownData = [
  { name: 'OpenAI GPT-4', value: 68, color: '#2196f3' },
  { name: 'Anthropic Claude', value: 25.6, color: '#9c27b0' },
  { name: 'Azure OpenAI', value: 6.4, color: '#ff9800' },
];

// Analytics Dashboard Component
function AnalyticsDashboard() {
  const [selectedTab, setSelectedTab] = useState(0);
  const [timeRange, setTimeRange] = useState('30d');
  const [selectedProvider, setSelectedProvider] = useState('all');
  const [showCosts, setShowCosts] = useState(true);
  const [exportFormat, setExportFormat] = useState('pdf');

  // Fetch analytics data
  const {
    data: analyticsData = mockAnalyticsData,
    error: analyticsError,
    refetch: refetchAnalytics,
  } = useQuery({
    queryKey: ['analytics', timeRange],
    queryFn: async () => {
      try {
        return await gatewayApi.getAnalytics(timeRange);
      } catch {
        return mockAnalyticsData;
      }
    },
    staleTime: 300000, // 5 minutes
  });

  const {
    data: providerAnalytics = mockProviderAnalytics,
    refetch: refetchProviders,
  } = useQuery({
    queryKey: ['provider-analytics', timeRange],
    queryFn: async () => {
      try {
        return await gatewayApi.getProviderAnalytics(timeRange);
      } catch {
        return mockProviderAnalytics;
      }
    },
    staleTime: 300000,
  });

  const {
    data: policyAnalytics = mockPolicyAnalytics,
    refetch: refetchPolicies,
  } = useQuery({
    queryKey: ['policy-analytics', timeRange],
    queryFn: async () => {
      try {
        return await gatewayApi.getPolicyAnalytics(timeRange);
      } catch {
        return mockPolicyAnalytics;
      }
    },
    staleTime: 300000,
  });

  const {
    data: userAnalytics = mockUserAnalytics,
    refetch: refetchUsers,
  } = useQuery({
    queryKey: ['user-analytics', timeRange],
    queryFn: async () => {
      try {
        return await gatewayApi.getUserAnalytics(timeRange);
      } catch {
        return mockUserAnalytics;
      }
    },
    staleTime: 300000,
  });

  const handleRefresh = () => {
    refetchAnalytics();
    refetchProviders();
    refetchPolicies();
    refetchUsers();
  };

  const handleExport = () => {
    // Mock export functionality
    console.log(`Exporting analytics data in ${exportFormat} format`);
    alert(`Analytics report exported in ${exportFormat.toUpperCase()} format`);
  };

  const formatNumber = (num: number) => {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'K';
    }
    return num.toLocaleString();
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(amount);
  };

  const getImpactColor = (impact: string) => {
    switch (impact) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'suspended': return 'warning';
      case 'inactive': return 'default';
      default: return 'default';
    }
  };

  if (analyticsError) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">
          Failed to load analytics data. Please try again.
        </Alert>
      </Container>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Container maxWidth="xl" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Stack direction="row" alignItems="center" spacing={2} mb={2}>
            <AssessmentIcon color="primary" sx={{ fontSize: 32 }} />
            <Typography variant="h4" component="h1" fontWeight="bold">
              Analytics & Reporting
            </Typography>
            <Badge badgeContent={analyticsData.policyViolations} color="warning">
              <Chip label="Policy Violations" variant="outlined" />
            </Badge>
            <Badge badgeContent={analyticsData.uniqueUsers} color="info">
              <Chip label="Active Users" variant="outlined" />
            </Badge>
          </Stack>
          <Typography variant="body1" color="text.secondary">
            Comprehensive analytics and reporting for AI Gateway performance and usage
          </Typography>
        </Box>

        {/* Filters and Controls */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Stack direction="row" spacing={2} alignItems="center" sx={{ flexWrap: 'wrap' }}>
              <FormControl sx={{ minWidth: 150 }}>
                <InputLabel>Time Range</InputLabel>
                <Select
                  value={timeRange}
                  onChange={(e) => setTimeRange(e.target.value)}
                  label="Time Range"
                >
                  <MenuItem value="7d">Last 7 Days</MenuItem>
                  <MenuItem value="30d">Last 30 Days</MenuItem>
                  <MenuItem value="90d">Last 90 Days</MenuItem>
                  <MenuItem value="1y">Last Year</MenuItem>
                </Select>
              </FormControl>
              <FormControl sx={{ minWidth: 150 }}>
                <InputLabel>Provider</InputLabel>
                <Select
                  value={selectedProvider}
                  onChange={(e) => setSelectedProvider(e.target.value)}
                  label="Provider"
                >
                  <MenuItem value="all">All Providers</MenuItem>
                  <MenuItem value="openai">OpenAI</MenuItem>
                  <MenuItem value="anthropic">Anthropic</MenuItem>
                  <MenuItem value="azure">Azure OpenAI</MenuItem>
                </Select>
              </FormControl>
              <FormControlLabel
                control={
                  <Switch
                    checked={showCosts}
                    onChange={(e) => setShowCosts(e.target.checked)}
                  />
                }
                label="Show Costs"
              />
              <Box sx={{ flexGrow: 1 }} />
              <Stack direction="row" spacing={1}>
                <FormControl sx={{ minWidth: 100 }}>
                  <InputLabel>Format</InputLabel>
                  <Select
                    value={exportFormat}
                    onChange={(e) => setExportFormat(e.target.value)}
                    label="Format"
                  >
                    <MenuItem value="pdf">PDF</MenuItem>
                    <MenuItem value="csv">CSV</MenuItem>
                    <MenuItem value="excel">Excel</MenuItem>
                  </Select>
                </FormControl>
                <Button
                  variant="outlined"
                  startIcon={<ExportIcon />}
                  onClick={handleExport}
                >
                  Export
                </Button>
                <Button
                  variant="contained"
                  startIcon={<RefreshIcon />}
                  onClick={handleRefresh}
                >
                  Refresh
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>

        {/* Summary Cards */}
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mb: 4 }}>
          <Box sx={{ flex: '1 1 200px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <TrendingUpIcon color="primary" />
                  <Typography variant="h6">Total Requests</Typography>
                </Stack>
                <Typography variant="h4" color="primary" gutterBottom>
                  {formatNumber(analyticsData.totalRequests)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {analyticsData.successfulRequests.toLocaleString()} successful
                </Typography>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 200px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <TimelineIcon color="primary" />
                  <Typography variant="h6">Avg Response Time</Typography>
                </Stack>
                <Typography variant="h4" color="primary" gutterBottom>
                  {analyticsData.averageResponseTime}ms
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {formatNumber(analyticsData.totalTokens)} tokens processed
                </Typography>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 200px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <BarChartIcon color="primary" />
                  <Typography variant="h6">Cache Hit Rate</Typography>
                </Stack>
                <Typography variant="h4" color="primary" gutterBottom>
                  {analyticsData.cacheHitRate.toFixed(1)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {analyticsData.policyViolations} policy violations
                </Typography>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 200px', minWidth: 0 }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={1}>
                  <PieChartIcon color="primary" />
                  <Typography variant="h6">Total Cost</Typography>
                </Stack>
                <Typography variant="h4" color="primary" gutterBottom>
                  {formatCurrency(analyticsData.cost)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {analyticsData.uniqueUsers} unique users
                </Typography>
              </CardContent>
            </Card>
          </Box>
        </Box>

        {/* Tabs */}
        <Card sx={{ mb: 4 }}>
          <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
            <Tab label="Overview" />
            <Tab label="Providers" />
            <Tab label="Policies" />
            <Tab label="Users" />
            <Tab label="Trends" />
          </Tabs>
        </Card>

        {/* Tab Content */}
        {selectedTab === 0 && (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            <Box sx={{ flex: '2 1 600px', minWidth: 0 }}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Request Trends
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <ComposedChart data={timeSeriesData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" />
                      <YAxis yAxisId="left" />
                      <YAxis yAxisId="right" orientation="right" />
                      <RechartsTooltip />
                      <Legend />
                      <Line
                        yAxisId="left"
                        type="monotone"
                        dataKey="requests"
                        stroke="#2196f3"
                        strokeWidth={2}
                        name="Requests"
                      />
                      <Line
                        yAxisId="right"
                        type="monotone"
                        dataKey="responseTime"
                        stroke="#4caf50"
                        strokeWidth={2}
                        name="Response Time (ms)"
                      />
                    </ComposedChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Box>
            <Box sx={{ flex: '1 1 400px', minWidth: 0 }}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Cost Breakdown
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={costBreakdownData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name} ${((percent || 0) * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {costBreakdownData.map((entry, index) => (
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
        )}

        {selectedTab === 1 && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Provider Performance
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Provider</TableCell>
                      <TableCell align="right">Requests</TableCell>
                      <TableCell align="right">Success Rate</TableCell>
                      <TableCell align="right">Avg Response Time</TableCell>
                      {showCosts && <TableCell align="right">Cost</TableCell>}
                      <TableCell align="right">Tokens</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {providerAnalytics.map((provider) => (
                      <TableRow key={provider.name}>
                        <TableCell>{provider.name}</TableCell>
                        <TableCell align="right">{formatNumber(provider.requests)}</TableCell>
                        <TableCell align="right">{provider.successRate.toFixed(2)}%</TableCell>
                        <TableCell align="right">{provider.averageResponseTime}ms</TableCell>
                        {showCosts && (
                          <TableCell align="right">{formatCurrency(provider.cost)}</TableCell>
                        )}
                        <TableCell align="right">{formatNumber(provider.tokens)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        )}

        {selectedTab === 2 && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Policy Performance
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Policy</TableCell>
                      <TableCell align="right">Evaluations</TableCell>
                      <TableCell align="right">Violations</TableCell>
                      <TableCell align="right">Violation Rate</TableCell>
                      <TableCell align="right">Avg Eval Time</TableCell>
                      <TableCell align="right">Impact</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {policyAnalytics.map((policy) => (
                      <TableRow key={policy.name}>
                        <TableCell>{policy.name}</TableCell>
                        <TableCell align="right">{formatNumber(policy.evaluations)}</TableCell>
                        <TableCell align="right">{formatNumber(policy.violations)}</TableCell>
                        <TableCell align="right">
                          {((policy.violations / policy.evaluations) * 100).toFixed(2)}%
                        </TableCell>
                        <TableCell align="right">{policy.averageEvaluationTime}ms</TableCell>
                        <TableCell align="right">
                          <Chip
                            label={policy.impact}
                            size="small"
                            color={getImpactColor(policy.impact) as 'error' | 'warning' | 'success' | 'default'}
                            variant="outlined"
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        )}

        {selectedTab === 3 && (
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                User Analytics
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>User ID</TableCell>
                      <TableCell align="right">Requests</TableCell>
                      <TableCell align="right">Violations</TableCell>
                      <TableCell align="right">Total Cost</TableCell>
                      <TableCell align="right">Last Activity</TableCell>
                      <TableCell align="right">Status</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {userAnalytics.map((user) => (
                      <TableRow key={user.userId}>
                        <TableCell>{user.userId}</TableCell>
                        <TableCell align="right">{formatNumber(user.requests)}</TableCell>
                        <TableCell align="right">{user.violations}</TableCell>
                        <TableCell align="right">{formatCurrency(user.totalCost)}</TableCell>
                        <TableCell align="right">
                          {new Date(user.lastActivity).toLocaleDateString()}
                        </TableCell>
                        <TableCell align="right">
                          <Chip
                            label={user.status}
                            size="small"
                            color={getStatusColor(user.status) as 'success' | 'warning' | 'default'}
                            variant="outlined"
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        )}

        {selectedTab === 4 && (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            <Box sx={{ flex: '1 1 500px', minWidth: 0 }}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Error Trends
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={timeSeriesData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <RechartsTooltip />
                      <Area
                        type="monotone"
                        dataKey="errors"
                        stroke="#f44336"
                        fill="#f44336"
                        fillOpacity={0.3}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Box>
            <Box sx={{ flex: '1 1 500px', minWidth: 0 }}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Cost Trends
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={timeSeriesData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <RechartsTooltip />
                      <Bar dataKey="cost" fill="#ff9800" />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Box>
          </Box>
        )}
      </Container>
    </Box>
  );
}

// Main Page Component
export default function AnalyticsPage() {
  return (
    <QueryProvider>
      <ThemeProvider>
        <AnalyticsDashboard />
      </ThemeProvider>
    </QueryProvider>
  );
} 