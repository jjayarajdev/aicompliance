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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Avatar,
  IconButton,
  Tooltip,
  Grid,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Block as BlockIcon,
  CheckCircle as CheckIcon,
  Group as GroupIcon,
  Refresh as RefreshIcon,
  Search as SearchIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { ThemeProvider } from '@/components/ThemeProvider';
import { QueryProvider } from '@/components/QueryProvider';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { gatewayApi } from '@/lib/api-client';

// User Types
interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: 'admin' | 'user' | 'manager' | 'viewer';
  status: 'active' | 'suspended' | 'inactive';
  lastLogin: string;
  createdAt: string;
  permissions: string[];
  quota: {
    daily: number;
    monthly: number;
    used: number;
  };
  apiKeys: {
    id: string;
    name: string;
    lastUsed: string;
    status: 'active' | 'expired' | 'revoked';
  }[];
}

// Mock data
const mockUsers: User[] = [
  {
    id: '1',
    username: 'admin',
    email: 'admin@example.com',
    firstName: 'Admin',
    lastName: 'User',
    role: 'admin',
    status: 'active',
    lastLogin: '2024-01-15T10:30:00Z',
    createdAt: '2024-01-01T00:00:00Z',
    permissions: ['read', 'write', 'delete', 'admin'],
    quota: {
      daily: 10000,
      monthly: 100000,
      used: 2500,
    },
    apiKeys: [
      {
        id: 'key1',
        name: 'Primary API Key',
        lastUsed: '2024-01-15T09:15:00Z',
        status: 'active',
      },
    ],
  },
  {
    id: '2',
    username: 'john.doe',
    email: 'john.doe@example.com',
    firstName: 'John',
    lastName: 'Doe',
    role: 'user',
    status: 'active',
    lastLogin: '2024-01-15T08:45:00Z',
    createdAt: '2024-01-05T00:00:00Z',
    permissions: ['read', 'write'],
    quota: {
      daily: 5000,
      monthly: 50000,
      used: 1200,
    },
    apiKeys: [
      {
        id: 'key2',
        name: 'Development Key',
        lastUsed: '2024-01-14T16:30:00Z',
        status: 'active',
      },
    ],
  },
];

// User Management Component
function UserManagement() {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [roleFilter, setRoleFilter] = useState('all');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [isUserDialogOpen, setIsUserDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<Partial<User> | null>(null);

  const queryClient = useQueryClient();

  // Fetch users
  const {
    data: users = mockUsers,
    error: usersError,
    refetch: refetchUsers,
  } = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      try {
        return await gatewayApi.getUsers();
      } catch {
        return mockUsers;
      }
    },
    staleTime: 300000,
  });

  // Mutations
  const createUserMutation = useMutation({
    mutationFn: async (userData: Partial<User>) => {
      return await gatewayApi.createUser(userData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setIsUserDialogOpen(false);
      setEditingUser(null);
    },
  });

  const updateUserMutation = useMutation({
    mutationFn: async ({ id, userData }: { id: string; userData: Partial<User> }) => {
      return await gatewayApi.updateUser(id, userData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setIsUserDialogOpen(false);
      setEditingUser(null);
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      return await gatewayApi.deleteUser(userId);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });

  // Filter users
  const filteredUsers = users.filter((user) => {
    const matchesSearch = 
      user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      `${user.firstName} ${user.lastName}`.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesStatus = statusFilter === 'all' || user.status === statusFilter;
    const matchesRole = roleFilter === 'all' || user.role === roleFilter;
    
    return matchesSearch && matchesStatus && matchesRole;
  });

  // Handlers
  const handleCreateUser = () => {
    setEditingUser({});
    setIsUserDialogOpen(true);
  };

  const handleEditUser = (user: User) => {
    setEditingUser(user);
    setIsUserDialogOpen(true);
  };

  const handleViewUser = (user: User) => {
    setSelectedUser(user);
  };

  const handleDeleteUser = (userId: string) => {
    if (confirm('Are you sure you want to delete this user?')) {
      deleteUserMutation.mutate(userId);
    }
  };

  const handleSaveUser = () => {
    if (editingUser) {
      if (editingUser.id) {
        updateUserMutation.mutate({ id: editingUser.id, userData: editingUser });
      } else {
        createUserMutation.mutate(editingUser);
      }
    }
  };

  const handleRefresh = () => {
    refetchUsers();
  };

  // Utility functions
  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return 'error';
      case 'manager': return 'warning';
      case 'user': return 'primary';
      case 'viewer': return 'default';
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

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString();
  };

  if (usersError) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">
          Failed to load user data. Please try again.
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
            <GroupIcon color="primary" sx={{ fontSize: 32 }} />
            <Typography variant="h4" component="h1" fontWeight="bold">
              User Management
            </Typography>
            <Badge badgeContent={users.filter(u => u.status === 'active').length} color="success">
              <Chip label="Active Users" variant="outlined" />
            </Badge>
            <Badge badgeContent={users.filter(u => u.status === 'suspended').length} color="warning">
              <Chip label="Suspended" variant="outlined" />
            </Badge>
          </Stack>
          <Typography variant="body1" color="text.secondary">
            Manage users, roles, and access permissions for the AI Gateway
          </Typography>
        </Box>

        {/* Filters and Controls */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Stack direction="row" spacing={2} alignItems="center" sx={{ flexWrap: 'wrap' }}>
              <TextField
                placeholder="Search users..."
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
                  <MenuItem value="active">Active</MenuItem>
                  <MenuItem value="suspended">Suspended</MenuItem>
                  <MenuItem value="inactive">Inactive</MenuItem>
                </Select>
              </FormControl>
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <InputLabel>Role</InputLabel>
                <Select
                  value={roleFilter}
                  onChange={(e) => setRoleFilter(e.target.value)}
                  label="Role"
                >
                  <MenuItem value="all">All Roles</MenuItem>
                  <MenuItem value="admin">Admin</MenuItem>
                  <MenuItem value="manager">Manager</MenuItem>
                  <MenuItem value="user">User</MenuItem>
                  <MenuItem value="viewer">Viewer</MenuItem>
                </Select>
              </FormControl>
              <Box sx={{ flexGrow: 1 }} />
              <Stack direction="row" spacing={1}>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={() => alert('Export functionality coming soon')}
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
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={handleCreateUser}
                >
                  Add User
                </Button>
              </Stack>
            </Stack>
          </CardContent>
        </Card>

        {/* Users Table */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Users ({filteredUsers.length})
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>User</TableCell>
                    <TableCell>Role</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Last Login</TableCell>
                    <TableCell>Quota Usage</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredUsers.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell>
                        <Stack direction="row" alignItems="center" spacing={2}>
                          <Avatar>
                            {user.firstName.charAt(0)}{user.lastName.charAt(0)}
                          </Avatar>
                          <Box>
                            <Typography variant="body2" fontWeight="medium">
                              {user.firstName} {user.lastName}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {user.email}
                            </Typography>
                          </Box>
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={user.role}
                          size="small"
                          color={getRoleColor(user.role) as any}
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={user.status}
                          size="small"
                          color={getStatusColor(user.status) as any}
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {formatDate(user.lastLogin)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {user.quota.used.toLocaleString()} / {user.quota.monthly.toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Stack direction="row" spacing={1}>
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                              onClick={() => handleViewUser(user)}
                            >
                              <ViewIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Edit User">
                            <IconButton
                              size="small"
                              onClick={() => handleEditUser(user)}
                            >
                              <EditIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete User">
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => handleDeleteUser(user.id)}
                            >
                              <DeleteIcon />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>

        {/* User Dialog */}
        <Dialog
          open={isUserDialogOpen}
          onClose={() => setIsUserDialogOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            {editingUser?.id ? 'Edit User' : 'Create User'}
          </DialogTitle>
          <DialogContent>
            <Grid container spacing={2} sx={{ mt: 1 }}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="First Name"
                  value={editingUser?.firstName || ''}
                  onChange={(e) => setEditingUser({ ...editingUser, firstName: e.target.value })}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Last Name"
                  value={editingUser?.lastName || ''}
                  onChange={(e) => setEditingUser({ ...editingUser, lastName: e.target.value })}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Username"
                  value={editingUser?.username || ''}
                  onChange={(e) => setEditingUser({ ...editingUser, username: e.target.value })}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Email"
                  type="email"
                  value={editingUser?.email || ''}
                  onChange={(e) => setEditingUser({ ...editingUser, email: e.target.value })}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Role</InputLabel>
                  <Select
                    value={editingUser?.role || ''}
                    onChange={(e) => setEditingUser({ ...editingUser, role: e.target.value as any })}
                    label="Role"
                  >
                    <MenuItem value="admin">Admin</MenuItem>
                    <MenuItem value="manager">Manager</MenuItem>
                    <MenuItem value="user">User</MenuItem>
                    <MenuItem value="viewer">Viewer</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={editingUser?.status || 'active'}
                    onChange={(e) => setEditingUser({ ...editingUser, status: e.target.value as any })}
                    label="Status"
                  >
                    <MenuItem value="active">Active</MenuItem>
                    <MenuItem value="suspended">Suspended</MenuItem>
                    <MenuItem value="inactive">Inactive</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setIsUserDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleSaveUser} variant="contained">
              Save
            </Button>
          </DialogActions>
        </Dialog>
      </Container>
    </Box>
  );
}

// Main Page Component
export default function UsersPage() {
  return (
    <QueryProvider>
      <ThemeProvider>
        <UserManagement />
      </ThemeProvider>
    </QueryProvider>
  );
} 