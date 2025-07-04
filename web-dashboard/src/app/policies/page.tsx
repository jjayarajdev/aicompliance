'use client';

import React, { useState, useEffect } from 'react';
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
  Alert,
  Skeleton,
  Tooltip,
  Badge,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Security as SecurityIcon,
  Policy as PolicyIcon,
  ExpandMore as ExpandMoreIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Save as SaveIcon,
  CheckCircle as CheckIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { ThemeProvider } from '@/components/ThemeProvider';
import { QueryProvider } from '@/components/QueryProvider';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { gatewayApi } from '@/lib/api-client';

// Policy Types
interface Policy {
  id: string;
  name: string;
  description: string;
  type: 'security' | 'compliance' | 'performance' | 'custom';
  status: 'active' | 'inactive' | 'draft';
  priority: 'low' | 'medium' | 'high' | 'critical';
  conditions: PolicyCondition[];
  actions: PolicyAction[];
  createdAt: string;
  updatedAt: string;
  version: string;
  tags: string[];
  enabled: boolean;
}

interface PolicyCondition {
  id: string;
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'greater_than' | 'less_than' | 'exists';
  value: string;
  logicalOperator?: 'AND' | 'OR';
}

interface PolicyAction {
  id: string;
  type: 'allow' | 'deny' | 'log' | 'alert' | 'transform';
  parameters: Record<string, any>;
}

interface PolicyFormData extends Record<string, unknown> {
  name: string;
  description: string;
  type: 'security' | 'compliance' | 'performance' | 'custom';
  priority: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  conditions: PolicyCondition[];
  actions: PolicyAction[];
  tags: string[];
}

// Mock data for development
const mockPolicies: Policy[] = [
  {
    id: '1',
    name: 'PII Detection Policy',
    description: 'Detect and block requests containing personally identifiable information',
    type: 'security',
    status: 'active',
    priority: 'high',
    conditions: [
      { id: '1', field: 'content', operator: 'contains', value: 'ssn|credit_card|email' }
    ],
    actions: [
      { id: '1', type: 'deny', parameters: { reason: 'PII detected' } }
    ],
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T00:00:00Z',
    version: '1.0.0',
    tags: ['security', 'pii', 'compliance'],
    enabled: true,
  },
  {
    id: '2',
    name: 'Rate Limiting Policy',
    description: 'Enforce rate limits for API requests per user',
    type: 'performance',
    status: 'active',
    priority: 'medium',
    conditions: [
      { id: '2', field: 'user_id', operator: 'exists', value: '' }
    ],
    actions: [
      { id: '2', type: 'log', parameters: { level: 'info' } }
    ],
    createdAt: '2024-01-02T00:00:00Z',
    updatedAt: '2024-01-10T00:00:00Z',
    version: '1.0.0',
    tags: ['performance', 'rate-limiting'],
    enabled: true,
  },
];

// Policy Management Component
function PolicyManagement() {
  const [selectedTab, setSelectedTab] = useState(0);
  const [openDialog, setOpenDialog] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const queryClient = useQueryClient();

  // Fetch policies (using mock data for now)
  const {
    data: policies = mockPolicies,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['policies'],
    queryFn: async () => {
      try {
        return await gatewayApi.getPolicies();
      } catch (error) {
        // Return mock data if API is not available
        return mockPolicies;
      }
    },
    staleTime: 30000,
  });

  // Create/Update policy mutation
  const mutation = useMutation({
    mutationFn: (policy: PolicyFormData) => {
      if (editingPolicy) {
        return gatewayApi.updatePolicy(editingPolicy.id, policy as Record<string, unknown>);
      }
      return gatewayApi.createPolicy(policy as Record<string, unknown>);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      setOpenDialog(false);
      setEditingPolicy(null);
    },
    onError: (error) => {
      console.error('Policy operation failed:', error);
    },
  });

  // Delete policy mutation
  const deleteMutation = useMutation({
    mutationFn: (policyId: string) => gatewayApi.deletePolicy(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
  });

  // Filter policies
  const filteredPolicies = policies.filter((policy: Policy) => {
    const matchesSearch = policy.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         policy.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === 'all' || policy.type === filterType;
    const matchesStatus = filterStatus === 'all' || policy.status === filterStatus;
    return matchesSearch && matchesType && matchesStatus;
  });

  const handleOpenDialog = (policy?: Policy) => {
    if (policy) {
      setEditingPolicy(policy);
    } else {
      setEditingPolicy(null);
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingPolicy(null);
  };

  const handleDeletePolicy = (policyId: string) => {
    if (confirm('Are you sure you want to delete this policy?')) {
      deleteMutation.mutate(policyId);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'inactive': return 'default';
      case 'draft': return 'warning';
      default: return 'default';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'default';
      default: return 'default';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'security': return <SecurityIcon />;
      case 'compliance': return <CheckIcon />;
      case 'performance': return <InfoIcon />;
      default: return <PolicyIcon />;
    }
  };

  if (error) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">
          Failed to load policies. Please try again.
        </Alert>
      </Container>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Stack direction="row" alignItems="center" spacing={2} mb={2}>
            <PolicyIcon color="primary" sx={{ fontSize: 32 }} />
            <Typography variant="h4" component="h1" fontWeight="bold">
              Policy Management
            </Typography>
            <Badge badgeContent={policies.length} color="primary">
              <Chip label="Total Policies" variant="outlined" />
            </Badge>
          </Stack>
          <Typography variant="body1" color="text.secondary">
            Manage AI Gateway policies for security, compliance, and performance monitoring
          </Typography>
        </Box>

        {/* Tabs */}
        <Card sx={{ mb: 3 }}>
          <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
            <Tab label="All Policies" />
            <Tab label="Security" />
            <Tab label="Compliance" />
            <Tab label="Performance" />
            <Tab label="Custom" />
          </Tabs>
        </Card>

        {/* Filters and Actions */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Stack spacing={2}>
              <TextField
                fullWidth
                placeholder="Search policies..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                }}
              />
              <Stack direction="row" spacing={2} sx={{ flexWrap: 'wrap' }}>
                <FormControl sx={{ minWidth: 200 }}>
                  <InputLabel>Type</InputLabel>
                  <Select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                    label="Type"
                  >
                    <MenuItem value="all">All Types</MenuItem>
                    <MenuItem value="security">Security</MenuItem>
                    <MenuItem value="compliance">Compliance</MenuItem>
                    <MenuItem value="performance">Performance</MenuItem>
                    <MenuItem value="custom">Custom</MenuItem>
                  </Select>
                </FormControl>
                <FormControl sx={{ minWidth: 200 }}>
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    label="Status"
                  >
                    <MenuItem value="all">All Status</MenuItem>
                    <MenuItem value="active">Active</MenuItem>
                    <MenuItem value="inactive">Inactive</MenuItem>
                    <MenuItem value="draft">Draft</MenuItem>
                  </Select>
                </FormControl>
                <Stack direction="row" spacing={1}>
                  <Tooltip title="Refresh">
                    <IconButton onClick={() => refetch()} disabled={isLoading}>
                      <RefreshIcon />
                    </IconButton>
                  </Tooltip>
                  <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => handleOpenDialog()}
                  >
                    New Policy
                  </Button>
                </Stack>
              </Stack>
            </Stack>
          </CardContent>
        </Card>

        {/* Policies List */}
        {isLoading ? (
          <Stack spacing={2}>
            {[...Array(5)].map((_, i) => (
              <Card key={i}>
                <CardContent>
                  <Skeleton variant="text" width="60%" height={24} />
                  <Skeleton variant="text" width="40%" height={20} />
                  <Stack direction="row" spacing={1} mt={1}>
                    <Skeleton variant="rectangular" width={80} height={24} />
                    <Skeleton variant="rectangular" width={80} height={24} />
                  </Stack>
                </CardContent>
              </Card>
            ))}
          </Stack>
        ) : (
          <Stack spacing={2}>
            {filteredPolicies.length === 0 ? (
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 4 }}>
                  <PolicyIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No policies found
                  </Typography>
                  <Typography variant="body2" color="text.secondary" mb={2}>
                    {searchTerm || filterType !== 'all' || filterStatus !== 'all'
                      ? 'Try adjusting your search or filters'
                      : 'Create your first policy to get started'
                    }
                  </Typography>
                  <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => handleOpenDialog()}
                  >
                    Create Policy
                  </Button>
                </CardContent>
              </Card>
            ) : (
              filteredPolicies.map((policy: Policy) => (
                <Card key={policy.id} elevation={1}>
                  <CardContent>
                    <Stack spacing={2}>
                      <Stack direction="row" alignItems="center" spacing={1}>
                        {getTypeIcon(policy.type)}
                        <Typography variant="h6" fontWeight={600}>
                          {policy.name}
                        </Typography>
                        <Chip
                          label={policy.status}
                          size="small"
                          color={getStatusColor(policy.status) as any}
                          variant="outlined"
                        />
                      </Stack>
                      <Typography variant="body2" color="text.secondary">
                        {policy.description}
                      </Typography>
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        <Chip
                          label={policy.priority}
                          size="small"
                          color={getPriorityColor(policy.priority) as any}
                          variant="outlined"
                        />
                        {policy.tags.map((tag) => (
                          <Chip key={tag} label={tag} size="small" variant="outlined" />
                        ))}
                      </Stack>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Stack spacing={0.5}>
                          <Typography variant="caption" color="text.secondary">
                            Version {policy.version}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            Updated {new Date(policy.updatedAt).toLocaleDateString()}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {policy.conditions.length} conditions, {policy.actions.length} actions
                          </Typography>
                        </Stack>
                        <Stack direction="row" spacing={1}>
                          <Tooltip title="View Policy">
                            <IconButton size="small">
                              <ViewIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Edit Policy">
                            <IconButton 
                              size="small" 
                              onClick={() => handleOpenDialog(policy)}
                            >
                              <EditIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete Policy">
                            <IconButton 
                              size="small" 
                              color="error"
                              onClick={() => handleDeletePolicy(policy.id)}
                              disabled={deleteMutation.isPending}
                            >
                              <DeleteIcon />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </Stack>
                    </Stack>
                  </CardContent>
                </Card>
              ))
            )}
          </Stack>
        )}

        {/* Policy Dialog */}
        <PolicyDialog
          open={openDialog}
          onClose={handleCloseDialog}
          policy={editingPolicy}
          onSubmit={mutation.mutate}
          loading={mutation.isPending}
        />
      </Container>
    </Box>
  );
}

// Policy Dialog Component
function PolicyDialog({
  open,
  onClose,
  policy,
  onSubmit,
  loading,
}: {
  open: boolean;
  onClose: () => void;
  policy: Policy | null;
  onSubmit: (data: PolicyFormData) => void;
  loading: boolean;
}) {
  const [formData, setFormData] = useState<PolicyFormData>({
    name: '',
    description: '',
    type: 'security',
    priority: 'medium',
    conditions: [],
    actions: [],
    tags: [],
    enabled: true,
  });

  // Reset form when dialog opens/closes
  useEffect(() => {
    if (policy) {
      setFormData({
        name: policy.name,
        description: policy.description,
        type: policy.type,
        priority: policy.priority,
        conditions: policy.conditions,
        actions: policy.actions,
        tags: policy.tags,
        enabled: policy.enabled,
      });
    } else {
      setFormData({
        name: '',
        description: '',
        type: 'security',
        priority: 'medium',
        conditions: [],
        actions: [],
        tags: [],
        enabled: true,
      });
    }
  }, [policy, open]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  const addCondition = () => {
    setFormData(prev => ({
      ...prev,
      conditions: [...prev.conditions, {
        id: Date.now().toString(),
        field: '',
        operator: 'equals',
        value: '',
      }],
    }));
  };

  const removeCondition = (id: string) => {
    setFormData(prev => ({
      ...prev,
      conditions: prev.conditions.filter(c => c.id !== id),
    }));
  };

  const updateCondition = (id: string, field: keyof PolicyCondition, value: any) => {
    setFormData(prev => ({
      ...prev,
      conditions: prev.conditions.map(c => 
        c.id === id ? { ...c, [field]: value } : c
      ),
    }));
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        {policy ? 'Edit Policy' : 'Create New Policy'}
      </DialogTitle>
      <form onSubmit={handleSubmit}>
        <DialogContent>
          <Stack spacing={3}>
            {/* Basic Information */}
            <Stack spacing={2}>
              <TextField
                fullWidth
                label="Policy Name"
                value={formData.name}
                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                required
              />
              <FormControl fullWidth>
                <InputLabel>Type</InputLabel>
                <Select
                  value={formData.type}
                  onChange={(e) => setFormData(prev => ({ ...prev, type: e.target.value }))}
                  label="Type"
                >
                  <MenuItem value="security">Security</MenuItem>
                  <MenuItem value="compliance">Compliance</MenuItem>
                  <MenuItem value="performance">Performance</MenuItem>
                  <MenuItem value="custom">Custom</MenuItem>
                </Select>
              </FormControl>
            </Stack>

            <TextField
              fullWidth
              label="Description"
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              multiline
              rows={3}
              required
            />

            <Stack direction="row" spacing={2}>
              <FormControl fullWidth>
                <InputLabel>Priority</InputLabel>
                <Select
                  value={formData.priority}
                  onChange={(e) => setFormData(prev => ({ ...prev, priority: e.target.value }))}
                  label="Priority"
                >
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                </Select>
              </FormControl>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.enabled}
                    onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                  />
                }
                label="Enabled"
              />
            </Stack>

            {/* Conditions */}
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="h6">Conditions ({formData.conditions.length})</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Stack spacing={2}>
                  {formData.conditions.map((condition) => (
                    <Card key={condition.id} variant="outlined">
                      <CardContent>
                        <Stack spacing={2}>
                          <TextField
                            fullWidth
                            label="Field"
                            value={condition.field}
                            onChange={(e) => updateCondition(condition.id, 'field', e.target.value)}
                            size="small"
                          />
                          <FormControl fullWidth size="small">
                            <InputLabel>Operator</InputLabel>
                            <Select
                              value={condition.operator}
                              onChange={(e) => updateCondition(condition.id, 'operator', e.target.value)}
                              label="Operator"
                            >
                              <MenuItem value="equals">Equals</MenuItem>
                              <MenuItem value="contains">Contains</MenuItem>
                              <MenuItem value="regex">Regex</MenuItem>
                              <MenuItem value="greater_than">Greater Than</MenuItem>
                              <MenuItem value="less_than">Less Than</MenuItem>
                              <MenuItem value="exists">Exists</MenuItem>
                            </Select>
                          </FormControl>
                          <TextField
                            fullWidth
                            label="Value"
                            value={condition.value}
                            onChange={(e) => updateCondition(condition.id, 'value', e.target.value)}
                            size="small"
                          />
                          <Button
                            color="error"
                            onClick={() => removeCondition(condition.id)}
                            size="small"
                            startIcon={<DeleteIcon />}
                          >
                            Remove Condition
                          </Button>
                        </Stack>
                      </CardContent>
                    </Card>
                  ))}
                  <Button
                    startIcon={<AddIcon />}
                    onClick={addCondition}
                    variant="outlined"
                  >
                    Add Condition
                  </Button>
                </Stack>
              </AccordionDetails>
            </Accordion>

            {/* Actions */}
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="h6">Actions ({formData.actions.length})</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary">
                  Actions will be configured in the next iteration
                </Typography>
              </AccordionDetails>
            </Accordion>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="contained"
            startIcon={<SaveIcon />}
            disabled={loading || !formData.name.trim()}
          >
            {loading ? 'Saving...' : (policy ? 'Update Policy' : 'Create Policy')}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
}

// Main Page Component
export default function PoliciesPage() {
  return (
    <QueryProvider>
      <ThemeProvider>
        <PolicyManagement />
      </ThemeProvider>
    </QueryProvider>
  );
} 