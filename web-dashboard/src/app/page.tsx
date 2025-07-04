'use client';

import { useState, useEffect } from 'react';
import {
  AppBar,
  Box,
  Button,
  Card,
  CardContent,
  Container,
  IconButton,
  Paper,
  Stack,
  Toolbar,
  Typography,
  useTheme,
  Chip,
  LinearProgress,
  Alert,
  Skeleton,
  CircularProgress,
  Tooltip,
  Badge,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Notifications as NotificationsIcon,
  Refresh as RefreshIcon,
  TrendingUp,
  TrendingDown,
  Remove as StableIcon,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Speed,
  CachedRounded,
  Security,
  Cloud,
  Timeline,
  Dashboard as DashboardIcon,
} from '@mui/icons-material';
import { ThemeProvider } from '@/components/ThemeProvider';
import { QueryProvider } from '@/components/QueryProvider';
import { useDashboard, useSystemHealth } from '@/hooks/useDashboard';
import { RecentActivity } from '@/lib/api-client';
import { formatDistanceToNow } from 'date-fns';

// Real-time Statistics Card Component with improved responsiveness
function StatCard({ 
  title, 
  value, 
  changePercent, 
  trend, 
  icon: Icon, 
  loading = false,
  color = 'primary'
}: {
  title: string;
  value: string | number;
  changePercent: number;
  trend: 'up' | 'down' | 'stable';
  icon: any;
  loading?: boolean;
  color?: 'primary' | 'secondary' | 'success' | 'error' | 'warning' | 'info';
}) {
  const theme = useTheme();
  
  const getTrendColor = () => {
    switch (trend) {
      case 'up': return theme.palette.success.main;
      case 'down': return theme.palette.error.main;
      default: return theme.palette.warning.main;
    }
  };

  const getTrendIcon = () => {
    switch (trend) {
      case 'up': return <TrendingUp sx={{ fontSize: 16 }} />;
      case 'down': return <TrendingDown sx={{ fontSize: 16 }} />;
      default: return <StableIcon sx={{ fontSize: 16 }} />;
    }
  };

  const formatValue = (val: string | number) => {
    if (typeof val === 'number') {
      if (val > 1000000) return `${(val / 1000000).toFixed(1)}M`;
      if (val > 1000) return `${(val / 1000).toFixed(1)}K`;
      return val.toLocaleString();
    }
    return val;
  };

  if (loading) {
    return (
      <Card elevation={2} sx={{ 
        height: '100%', 
        background: `linear-gradient(135deg, ${theme.palette[color].light}15, ${theme.palette[color].main}08)`,
        border: `1px solid ${theme.palette[color].main}20`
      }}>
        <CardContent>
          <Skeleton variant="text" width="60%" height={24} />
          <Skeleton variant="text" width="40%" height={36} />
          <Skeleton variant="text" width="50%" height={20} />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card 
      elevation={2} 
      sx={{ 
        height: '100%',
        background: `linear-gradient(135deg, ${theme.palette[color].light}15, ${theme.palette[color].main}08)`,
        border: `1px solid ${theme.palette[color].main}20`,
        transition: 'all 0.3s ease-in-out',
        '&:hover': {
          transform: 'translateY(-2px)',
          boxShadow: theme.shadows[4],
        }
      }}
    >
      <CardContent>
        <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
          <Typography variant="body2" color="text.secondary" fontWeight={500}>
            {title}
          </Typography>
          <Icon sx={{ 
            color: `${color}.main`, 
            fontSize: 24,
            opacity: 0.7,
          }} />
        </Stack>
        <Typography 
          variant="h4" 
          fontWeight="bold" 
          mb={1}
          sx={{ color: `${color}.dark` }}
        >
          {formatValue(value)}
        </Typography>
        <Stack direction="row" alignItems="center" spacing={0.5}>
          <Box sx={{ color: getTrendColor(), display: 'flex', alignItems: 'center' }}>
            {getTrendIcon()}
          </Box>
          <Typography 
            variant="body2" 
            sx={{ color: getTrendColor() }}
            fontWeight={500}
          >
            {changePercent > 0 ? '+' : ''}{changePercent}%
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            vs last period
          </Typography>
        </Stack>
      </CardContent>
    </Card>
  );
}

// Enhanced System Health Status Component
function SystemHealthIndicator({ loading = false }: { loading?: boolean }) {
  const { data: health, isLoading } = useSystemHealth();
  
  if (loading || isLoading) {
    return <Skeleton variant="circular" width={24} height={24} />;
  }

  const isHealthy = health?.status === 'healthy';
  const statusColor = isHealthy ? 'success' : 'warning';
  
  return (
    <Tooltip title={`System Status: ${health?.status || 'Unknown'} • Last checked: ${formatDistanceToNow(new Date(), { addSuffix: true })}`}>
      <Badge
        variant="dot"
        color={statusColor}
        sx={{
          '& .MuiBadge-badge': {
            animation: isHealthy ? 'none' : 'pulse 2s infinite',
          }
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          {isHealthy ? (
            <CheckCircle sx={{ color: 'success.main', fontSize: 20 }} />
          ) : (
            <Warning sx={{ color: 'warning.main', fontSize: 20 }} />
          )}
        </Box>
      </Badge>
    </Tooltip>
  );
}

// Enhanced Activity Item Component
function ActivityItem({ activity }: { activity: RecentActivity }) {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'error';
      case 'medium': return 'warning';
      default: return 'info';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'violation': return <Security sx={{ fontSize: 18 }} />;
      case 'alert': return <Warning sx={{ fontSize: 18 }} />;
      case 'optimization': return <Speed sx={{ fontSize: 18 }} />;
      default: return <CheckCircle sx={{ fontSize: 18 }} />;
    }
  };

  return (
    <Box
      sx={{
        p: 2,
        borderRadius: 1,
        border: 1,
        borderColor: 'divider',
        bgcolor: 'background.paper',
        '&:hover': {
          bgcolor: 'action.hover',
          borderColor: 'primary.main',
        },
        transition: 'all 0.2s ease-in-out',
      }}
    >
      <Stack direction="row" spacing={2} alignItems="flex-start">
        <Box sx={{ 
          mt: 0.5,
          p: 0.5,
          borderRadius: '50%',
          bgcolor: `${getSeverityColor(activity.severity)}.light`,
          color: `${getSeverityColor(activity.severity)}.dark`,
        }}>
          {getTypeIcon(activity.type)}
        </Box>
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Stack direction="row" spacing={1} alignItems="center" mb={0.5} flexWrap="wrap">
            <Typography variant="subtitle2" fontWeight={600}>
              {activity.title}
            </Typography>
            <Chip 
              label={activity.severity.toUpperCase()} 
              size="small" 
              color={getSeverityColor(activity.severity) as any}
              variant="outlined"
              sx={{ height: 20, fontSize: '0.7rem' }}
            />
            {!activity.resolved && (
              <Chip 
                label="ACTIVE" 
                size="small" 
                color="warning"
                variant="filled"
                sx={{ height: 20, fontSize: '0.7rem' }}
              />
            )}
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1, lineHeight: 1.4 }}>
            {activity.description}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
            {activity.user && (
              <>
                {' • '}
                <Typography component="span" variant="caption" fontWeight={500}>
                  {activity.user}
                </Typography>
              </>
            )}
          </Typography>
        </Box>
      </Stack>
    </Box>
  );
}

// Main Dashboard Component with enhanced real-time features
function DashboardContent() {
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [isRealtimeEnabled, setIsRealtimeEnabled] = useState(true);
  const { data, isLoading, isError, error, refetch } = useDashboard();
  
  const handleRefresh = async () => {
    await refetch();
    setLastRefresh(new Date());
  };

  const toggleRealtime = () => {
    setIsRealtimeEnabled(!isRealtimeEnabled);
  };

  // Auto-refresh timestamp
  useEffect(() => {
    if (!isRealtimeEnabled) return;
    
    const interval = setInterval(() => {
      setLastRefresh(new Date());
    }, 30000); // Update every 30 seconds

    return () => clearInterval(interval);
  }, [isRealtimeEnabled]);

  if (isError) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert 
          severity="error" 
          action={
            <Button color="inherit" size="small" onClick={handleRefresh}>
              Retry
            </Button>
          }
        >
          <Typography variant="h6" gutterBottom>
            Failed to load dashboard data
          </Typography>
          <Typography variant="body2">
            {error?.message || 'Please try again. The system may be temporarily unavailable.'}
          </Typography>
        </Alert>
      </Container>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, minHeight: '100vh', bgcolor: 'background.default' }}>
      {/* Enhanced App Bar with real-time indicators */}
      <AppBar position="static" elevation={2}>
        <Toolbar>
          <IconButton edge="start" color="inherit" sx={{ mr: 2 }}>
            <MenuIcon />
          </IconButton>
          <DashboardIcon sx={{ mr: 2 }} />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1, fontWeight: 600 }}>
            AI Gateway Dashboard
          </Typography>
          <Stack direction="row" spacing={2} alignItems="center">
            <Box sx={{ textAlign: 'right', display: { xs: 'none', sm: 'block' } }}>
              <Typography variant="body2" color="inherit" sx={{ opacity: 0.9, fontSize: '0.8rem' }}>
                Last updated
              </Typography>
              <Typography variant="caption" color="inherit" sx={{ opacity: 0.7 }}>
                {formatDistanceToNow(lastRefresh, { addSuffix: true })}
              </Typography>
            </Box>
            <SystemHealthIndicator loading={isLoading} />
            <Tooltip title={isRealtimeEnabled ? "Disable real-time updates" : "Enable real-time updates"}>
              <IconButton color="inherit" onClick={toggleRealtime}>
                <Timeline sx={{ color: isRealtimeEnabled ? 'success.light' : 'text.secondary' }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Refresh Dashboard">
              <IconButton 
                color="inherit" 
                onClick={handleRefresh}
                disabled={isLoading}
              >
                {isLoading ? (
                  <CircularProgress size={20} color="inherit" />
                ) : (
                  <RefreshIcon />
                )}
              </IconButton>
            </Tooltip>
            <Badge badgeContent={data?.recentActivity?.filter(a => !a.resolved).length || 0} color="error">
              <IconButton color="inherit">
                <NotificationsIcon />
              </IconButton>
            </Badge>
          </Stack>
        </Toolbar>
        {isLoading && <LinearProgress />}
      </AppBar>

      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Enhanced Dashboard Statistics with color coding */}
        <Box 
          sx={{ 
            display: 'grid', 
            gridTemplateColumns: { 
              xs: '1fr', 
              sm: 'repeat(2, 1fr)', 
              lg: 'repeat(4, 1fr)' 
            },
            gap: 3,
            mb: 4 
          }}
        >
          <StatCard
            title="Active Policies"
            value={data?.stats.activePolicies.count || 0}
            changePercent={data?.stats.activePolicies.changePercent || 0}
            trend={data?.stats.activePolicies.trend || 'stable'}
            icon={Security}
            loading={isLoading}
            color="primary"
          />
          
          <StatCard
            title="API Requests"
            value={data?.stats.apiRequests.count || 0}
            changePercent={data?.stats.apiRequests.changePercent || 0}
            trend={data?.stats.apiRequests.trend || 'stable'}
            icon={Cloud}
            loading={isLoading}
            color="info"
          />
          
          <StatCard
            title="Rate Limit Violations"
            value={data?.stats.rateLimitViolations.count || 0}
            changePercent={data?.stats.rateLimitViolations.changePercent || 0}
            trend={data?.stats.rateLimitViolations.trend || 'stable'}
            icon={ErrorIcon}
            loading={isLoading}
            color="error"
          />
          
          <StatCard
            title="System Health"
            value={data?.stats.systemHealth.uptime || '0%'}
            changePercent={0}
            trend="stable"
            icon={CheckCircle}
            loading={isLoading}
            color="success"
          />
        </Box>

        {/* Enhanced Content Grid with better responsiveness */}
        <Box 
          sx={{ 
            display: 'grid', 
            gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' },
            gap: 3,
            mb: 4
          }}
        >
          {/* Enhanced System Overview */}
          <Card elevation={2}>
            <CardContent>
              <Stack direction="row" alignItems="center" spacing={1} mb={3}>
                <Speed color="primary" />
                <Typography variant="h6" fontWeight={600}>
                  System Overview
                </Typography>
                {isLoading && <CircularProgress size={16} />}
              </Stack>
              
              {isLoading ? (
                <Stack spacing={3}>
                  {[...Array(4)].map((_, i) => (
                    <Box key={i}>
                      <Skeleton variant="text" width="40%" height={20} />
                      <Skeleton variant="rectangular" height={8} sx={{ mt: 1, mb: 1, borderRadius: 1 }} />
                      <Skeleton variant="text" width="20%" height={16} />
                    </Box>
                  ))}
                </Stack>
              ) : (
                <Stack spacing={3}>
                  {/* Policy Engine Performance */}
                  <Box>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                      <Typography variant="body2" fontWeight={500}>Policy Engine Performance</Typography>
                      <Typography variant="body2" fontWeight="bold" color="primary.main">
                        {data?.overview.policyEngine.performance || 0}%
                      </Typography>
                    </Stack>
                    <LinearProgress 
                      variant="determinate" 
                      value={data?.overview.policyEngine.performance || 0}
                      sx={{ height: 8, borderRadius: 4 }}
                      color="primary"
                    />
                    <Typography variant="caption" color="text.secondary" mt={0.5} display="block">
                      Avg response time: {data?.overview.policyEngine.responseTime || 0}ms
                    </Typography>
                  </Box>

                  {/* Cache Hit Rate */}
                  <Box>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                      <Typography variant="body2" fontWeight={500}>Cache Hit Rate</Typography>
                      <Typography variant="body2" fontWeight="bold" color="success.main">
                        {data?.overview.cacheHitRate.percentage || 0}%
                      </Typography>
                    </Stack>
                    <LinearProgress 
                      variant="determinate" 
                      value={data?.overview.cacheHitRate.percentage || 0}
                      color="success"
                      sx={{ height: 8, borderRadius: 4 }}
                    />
                  </Box>

                  {/* Rate Limit Utilization */}
                  <Box>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                      <Typography variant="body2" fontWeight={500}>Rate Limit Utilization</Typography>
                      <Typography variant="body2" fontWeight="bold" color="warning.main">
                        {data?.overview.rateLimitUtilization.percentage || 0}%
                      </Typography>
                    </Stack>
                    <LinearProgress 
                      variant="determinate" 
                      value={data?.overview.rateLimitUtilization.percentage || 0}
                      color="warning"
                      sx={{ height: 8, borderRadius: 4 }}
                    />
                  </Box>

                  {/* Provider Health */}
                  <Box>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                      <Typography variant="body2" fontWeight={500}>Provider Health</Typography>
                      <Typography variant="body2" fontWeight="bold" color="info.main">
                        {data?.overview.providerHealth.percentage || 0}%
                      </Typography>
                    </Stack>
                    <LinearProgress 
                      variant="determinate" 
                      value={data?.overview.providerHealth.percentage || 0}
                      color="info"
                      sx={{ height: 8, borderRadius: 4 }}
                    />
                    <Stack direction="row" spacing={1} mt={2} flexWrap="wrap" useFlexGap>
                      {data?.overview.providerHealth.providers.map((provider) => (
                        <Chip
                          key={provider.name}
                          label={`${provider.name} (${provider.responseTime}ms)`}
                          size="small"
                          color={provider.status === 'healthy' ? 'success' : 'warning'}
                          variant="outlined"
                          icon={provider.status === 'healthy' ? <CheckCircle sx={{ fontSize: 14 }} /> : <Warning sx={{ fontSize: 14 }} />}
                        />
                      ))}
                    </Stack>
                  </Box>
                </Stack>
              )}
            </CardContent>
          </Card>

          {/* Enhanced Recent Activity */}
          <Card elevation={2}>
            <CardContent>
              <Stack direction="row" alignItems="center" justifyContent="space-between" mb={3}>
                <Stack direction="row" alignItems="center" spacing={1}>
                  <NotificationsIcon color="primary" />
                  <Typography variant="h6" fontWeight={600}>
                    Recent Activity
                  </Typography>
                </Stack>
                <Chip 
                  label={`${data?.recentActivity?.length || 0} events`}
                  size="small"
                  color="primary"
                  variant="outlined"
                />
              </Stack>
              
              {isLoading ? (
                <Stack spacing={2}>
                  {[...Array(5)].map((_, i) => (
                    <Stack key={i} direction="row" spacing={2}>
                      <Skeleton variant="circular" width={32} height={32} />
                      <Box sx={{ flex: 1 }}>
                        <Skeleton variant="text" width="80%" height={20} />
                        <Skeleton variant="text" width="60%" height={16} />
                        <Skeleton variant="text" width="40%" height={14} />
                      </Box>
                    </Stack>
                  ))}
                </Stack>
              ) : (
                <Stack spacing={2} sx={{ maxHeight: 450, overflow: 'auto' }}>
                  {data?.recentActivity?.map((activity) => (
                    <ActivityItem key={activity.id} activity={activity} />
                  ))}
                  {(!data?.recentActivity || data.recentActivity.length === 0) && (
                    <Box 
                      sx={{ 
                        textAlign: 'center', 
                        py: 4,
                        color: 'text.secondary',
                        bgcolor: 'grey.50',
                        borderRadius: 1,
                      }}
                    >
                      <Timeline sx={{ fontSize: 48, opacity: 0.3, mb: 1 }} />
                      <Typography variant="body2">
                        No recent activity
                      </Typography>
                    </Box>
                  )}
                </Stack>
              )}
            </CardContent>
          </Card>
        </Box>

        {/* Enhanced Quick Actions */}
        <Paper elevation={2} sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom fontWeight={600}>
            Quick Actions
          </Typography>
          <Stack 
            direction={{ xs: 'column', sm: 'row' }} 
            spacing={2}
            flexWrap="wrap"
            useFlexGap
          >
            <Button 
              variant="outlined" 
              startIcon={<Security />}
              sx={{ minWidth: { xs: '100%', sm: 'auto' } }}
            >
              Manage Policies
            </Button>
            <Button 
              variant="outlined" 
              startIcon={<Speed />}
              sx={{ minWidth: { xs: '100%', sm: 'auto' } }}
            >
              View Analytics
            </Button>
            <Button 
              variant="outlined" 
              startIcon={<CachedRounded />}
              sx={{ minWidth: { xs: '100%', sm: 'auto' } }}
            >
              System Settings
            </Button>
            <Button 
              variant="outlined" 
              startIcon={<Cloud />}
              sx={{ minWidth: { xs: '100%', sm: 'auto' } }}
            >
              Performance Reports
            </Button>
          </Stack>
        </Paper>
      </Container>
    </Box>
  );
}

// Main Page Component with Providers and metadata
export default function Dashboard() {
  return (
    <QueryProvider>
      <ThemeProvider>
        <DashboardContent />
      </ThemeProvider>
    </QueryProvider>
  );
}
