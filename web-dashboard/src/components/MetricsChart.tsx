'use client';

import { useState, useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  ToggleButton,
  ToggleButtonGroup,
  useTheme,
  Stack,
} from '@mui/material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
  AreaChart,
  Area,
} from 'recharts';
import { format, parseISO } from 'date-fns';
import { MetricsData } from '@/lib/api-client';

interface MetricsChartProps {
  data: MetricsData[];
  loading?: boolean;
  title?: string;
  height?: number;
}

type ChartType = 'line' | 'area';

const MetricsChart = ({ 
  data = [], 
  loading = false, 
  title = 'Real-time Performance Metrics',
  height = 300 
}: MetricsChartProps) => {
  const theme = useTheme();
  const [chartType, setChartType] = useState<ChartType>('area');

  // Filter and format data
  const filteredData = useMemo(() => {
    if (!data.length) return [];
    
    return data
      .slice(-24) // Last 24 data points
      .map(item => ({
        ...item,
        formattedTime: format(parseISO(item.timestamp), 'HH:mm'),
      }));
  }, [data]);

  const handleChartTypeChange = (_event: React.MouseEvent<HTMLElement>, newType: ChartType) => {
    if (newType !== null) {
      setChartType(newType);
    }
  };

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <Box
          sx={{
            bgcolor: 'background.paper',
            border: 1,
            borderColor: 'divider',
            borderRadius: 1,
            p: 2,
            boxShadow: 1,
          }}
        >
          <Typography variant="body2" fontWeight="bold" mb={1}>
            {label}
          </Typography>
          {payload.map((entry: any, index: number) => (
            <Typography
              key={index}
              variant="body2"
              sx={{ color: entry.color }}
            >
              {entry.name}: {entry.value.toLocaleString()}
            </Typography>
          ))}
        </Box>
      );
    }
    return null;
  };

  if (loading) {
    return (
      <Card elevation={1}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            {title}
          </Typography>
          <Box 
            sx={{ 
              height, 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              bgcolor: 'grey.50',
              borderRadius: 1,
            }}
          >
            <Typography variant="body2" color="text.secondary">
              Loading metrics data...
            </Typography>
          </Box>
        </CardContent>
      </Card>
    );
  }

  const renderChart = () => {
    const chartProps = {
      data: filteredData,
      margin: { top: 5, right: 30, left: 20, bottom: 5 },
    };

    if (chartType === 'area') {
      return (
        <AreaChart {...chartProps}>
          <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
          <XAxis dataKey="formattedTime" stroke={theme.palette.text.secondary} fontSize={12} />
          <YAxis stroke={theme.palette.text.secondary} fontSize={12} />
          <RechartsTooltip content={<CustomTooltip />} />
          <Legend />
          <Area
            type="monotone"
            dataKey="requests"
            stroke={theme.palette.primary.main}
            fill={theme.palette.primary.main}
            fillOpacity={0.3}
            name="Requests"
          />
          <Area
            type="monotone"
            dataKey="cacheHits"
            stroke={theme.palette.success.main}
            fill={theme.palette.success.main}
            fillOpacity={0.3}
            name="Cache Hits"
          />
        </AreaChart>
      );
    }

    return (
      <LineChart {...chartProps}>
        <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
        <XAxis dataKey="formattedTime" stroke={theme.palette.text.secondary} fontSize={12} />
        <YAxis stroke={theme.palette.text.secondary} fontSize={12} />
        <RechartsTooltip content={<CustomTooltip />} />
        <Legend />
        <Line 
          type="monotone" 
          dataKey="requests" 
          stroke={theme.palette.primary.main}
          strokeWidth={2}
          dot={false}
          name="Requests"
        />
        <Line 
          type="monotone" 
          dataKey="responseTime" 
          stroke={theme.palette.secondary.main}
          strokeWidth={2}
          dot={false}
          name="Response Time (ms)"
        />
      </LineChart>
    );
  };

  return (
    <Card elevation={1}>
      <CardContent>
        <Stack 
          direction={{ xs: 'column', sm: 'row' }} 
          justifyContent="space-between" 
          alignItems={{ xs: 'stretch', sm: 'center' }}
          spacing={2}
          mb={3}
        >
          <Typography variant="h6">
            {title}
          </Typography>
          
          <ToggleButtonGroup
            value={chartType}
            exclusive
            onChange={handleChartTypeChange}
            size="small"
          >
            <ToggleButton value="line">Line</ToggleButton>
            <ToggleButton value="area">Area</ToggleButton>
          </ToggleButtonGroup>
        </Stack>

        <Box sx={{ height, width: '100%' }}>
          {filteredData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              {renderChart()}
            </ResponsiveContainer>
          ) : (
            <Box 
              sx={{ 
                height: '100%', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center',
                bgcolor: 'grey.50',
                borderRadius: 1,
              }}
            >
              <Typography variant="body2" color="text.secondary">
                No metrics data available
              </Typography>
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default MetricsChart; 