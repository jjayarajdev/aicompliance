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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  Grid,
  Snackbar,
} from '@mui/material';
import {
  History as HistoryIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Visibility as ViewIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { ThemeProvider } from '@/components/ThemeProvider';
import { QueryProvider } from '@/components/QueryProvider';
import { useQuery } from '@tanstack/react-query';
import { gatewayApi } from '@/lib/api-client';

// Audit Log Types
interface AuditLogEntry {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  resource: string;
  status: 'success' | 'failure' | 'warning';
  details: string;
  ip: string;
}

// Mock data
const mockAuditLogs: AuditLogEntry[] = [
  {
    id: '1',
    timestamp: '2024-07-01T10:00:00Z',
    user: 'admin',
    action: 'LOGIN',
    resource: 'Dashboard',
    status: 'success',
    details: 'User admin logged in successfully.',
    ip: '192.168.1.10',
  },
  {
    id: '2',
    timestamp: '2024-07-01T10:05:00Z',
    user: 'john.doe',
    action: 'CREATE_POLICY',
    resource: 'Policy:PII Detection',
    status: 'success',
    details: 'Created new policy for PII detection.',
    ip: '192.168.1.20',
  },
  {
    id: '3',
    timestamp: '2024-07-01T10:10:00Z',
    user: 'jane.smith',
    action: 'DELETE_USER',
    resource: 'User:bob.wilson',
    status: 'failure',
    details: 'Attempted to delete user bob.wilson. Permission denied.',
    ip: '192.168.1.30',
  },
];

// Audit Logs Component
function AuditLogs() {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>({ open: false, message: '', severity: 'info' });

  // Fetch audit logs
  const {
    data: auditLogs = mockAuditLogs,
    error: logsError,
    refetch: refetchLogs,
  } = useQuery({
    queryKey: ['audit-logs'],
    queryFn: async () => {
      try {
        return await gatewayApi.getAuditLogs();
      } catch {
        return mockAuditLogs;
      }
    },
    staleTime: 300000,
  });

  // Filter logs
  const filteredLogs = auditLogs.filter((log: AuditLogEntry) => {
    const matchesSearch =
      log.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.resource.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.details.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || log.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleRefresh = () => {
    refetchLogs();
  };

  const handleExport = () => {
    setSnackbar({ open: true, message: 'Export functionality coming soon', severity: 'info' });
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  if (logsError) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">Failed to load audit logs. Please try again.</Alert>
      </Container>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Container maxWidth="xl" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Stack direction="row" alignItems="center" spacing={2} mb={2}>
            <HistoryIcon color="primary" sx={{ fontSize: 32 }} />
            <Typography variant="h4" component="h1" fontWeight="bold">
              Audit Logs & Activity History
            </Typography>
            <Chip label="Audit Trail" color="info" variant="outlined" />
          </Stack>
          <Typography variant="body1" color="text.secondary">
            View, search, and filter all actions and events for transparency and traceability
          </Typography>
        </Box>

        {/* Filters and Controls */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Stack direction="row" spacing={2} alignItems="center" sx={{ flexWrap: 'wrap' }}>
              <TextField
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                size="small"
                sx={{ minWidth: 200 }}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                }}
              />
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <InputLabel>Status</InputLabel>
                <Select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  label="Status"
                >
                  <MenuItem value="all">All Status</MenuItem>
                  <MenuItem value="success">Success</MenuItem>
                  <MenuItem value="failure">Failure</MenuItem>
                  <MenuItem value="warning">Warning</MenuItem>
                </Select>
              </FormControl>
              <Box sx={{ flexGrow: 1 }} />
              <Stack direction="row" spacing={1}>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={handleExport}
                >
                  Export
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={handleRefresh}
                >
                  Refresh
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>

        {/* Audit Logs Table */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Audit Log Entries ({filteredLogs.length})
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>User</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>Resource</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="right">Details</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredLogs.map((log: AuditLogEntry) => (
                    <TableRow key={log.id}>
                      <TableCell>{new Date(log.timestamp).toLocaleString()}</TableCell>
                      <TableCell>{log.user}</TableCell>
                      <TableCell>{log.action}</TableCell>
                      <TableCell>{log.resource}</TableCell>
                      <TableCell>
                        <Chip
                          label={log.status}
                          size="small"
                          color={
                            log.status === 'success'
                              ? 'success'
                              : log.status === 'failure'
                              ? 'error'
                              : 'warning'
                          }
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="View Details">
                          <IconButton size="small" onClick={() => setSelectedLog(log)}>
                            <ViewIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>

        {/* Log Details Dialog */}
        <Dialog
          open={!!selectedLog}
          onClose={() => setSelectedLog(null)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>
            Audit Log Details
            <IconButton
              aria-label="close"
              onClick={() => setSelectedLog(null)}
              sx={{ position: 'absolute', right: 8, top: 8 }}
            >
              <CloseIcon />
            </IconButton>
          </DialogTitle>
          <DialogContent dividers>
            {selectedLog && (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box>
                  <Typography variant="subtitle2">Timestamp</Typography>
                  <Typography variant="body2" gutterBottom>{new Date(selectedLog.timestamp).toLocaleString()}</Typography>
                </Box>
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <Box sx={{ flex: 1, minWidth: 150 }}>
                    <Typography variant="subtitle2">User</Typography>
                    <Typography variant="body2" gutterBottom>{selectedLog.user}</Typography>
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 150 }}>
                    <Typography variant="subtitle2">IP Address</Typography>
                    <Typography variant="body2" gutterBottom>{selectedLog.ip}</Typography>
                  </Box>
                </Box>
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <Box sx={{ flex: 1, minWidth: 150 }}>
                    <Typography variant="subtitle2">Action</Typography>
                    <Typography variant="body2" gutterBottom>{selectedLog.action}</Typography>
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 150 }}>
                    <Typography variant="subtitle2">Resource</Typography>
                    <Typography variant="body2" gutterBottom>{selectedLog.resource}</Typography>
                  </Box>
                </Box>
                <Box>
                  <Typography variant="subtitle2">Status</Typography>
                  <Chip
                    label={selectedLog.status}
                    size="small"
                    color={
                      selectedLog.status === 'success'
                        ? 'success'
                        : selectedLog.status === 'failure'
                        ? 'error'
                        : 'warning'
                    }
                    variant="outlined"
                    sx={{ mb: 2 }}
                  />
                </Box>
                <Box>
                  <Typography variant="subtitle2">Details</Typography>
                  <Typography variant="body2">{selectedLog.details}</Typography>
                </Box>
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSelectedLog(null)}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* Snackbar */}
        <Snackbar
          open={snackbar.open}
          autoHideDuration={4000}
          onClose={handleCloseSnackbar}
          message={snackbar.message}
        />
      </Container>
    </Box>
  );
}

// Main Page Component
export default function AuditLogsPage() {
  return (
    <QueryProvider>
      <ThemeProvider>
        <AuditLogs />
      </ThemeProvider>
    </QueryProvider>
  );
} 