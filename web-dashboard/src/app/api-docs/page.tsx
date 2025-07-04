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
  TextField,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListItemIcon,
  Paper,
  Tabs,
  Tab,
  Snackbar,
} from '@mui/material';
import {
  Api as ApiIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  ContentCopy as CopyIcon,
  ExpandMore as ExpandMoreIcon,
  Key as KeyIcon,
  Lock as LockIcon,
} from '@mui/icons-material';
import { ThemeProvider } from '@/components/ThemeProvider';
import { QueryProvider } from '@/components/QueryProvider';

// API Documentation Types
interface ApiEndpoint {
  id: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  title: string;
  description: string;
  category: string;
  requiresAuth: boolean;
  parameters: ApiParameter[];
  requestBody?: ApiRequestBody;
  responses: ApiResponse[];
  examples: ApiExample[];
}

interface ApiParameter {
  name: string;
  type: string;
  required: boolean;
  description: string;
  defaultValue?: string;
}

interface ApiRequestBody {
  type: string;
  schema: Record<string, unknown>;
  required: boolean;
  description: string;
}

interface ApiResponse {
  code: number;
  description: string;
  schema: Record<string, unknown>;
  example: Record<string, unknown>;
}

interface ApiExample {
  name: string;
  description: string;
  request: Record<string, unknown>;
  response: Record<string, unknown>;
}

// Mock API Documentation
const mockApiEndpoints: ApiEndpoint[] = [
  {
    id: '1',
    method: 'GET',
    path: '/api/v1/health',
    title: 'Health Check',
    description: 'Check the health status of the AI Gateway',
    category: 'System',
    requiresAuth: false,
    parameters: [],
    responses: [
      {
        code: 200,
        description: 'Service is healthy',
        schema: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            timestamp: { type: 'string' },
            uptime: { type: 'number' },
          },
        },
        example: {
          status: 'healthy',
          timestamp: '2024-01-15T10:30:00Z',
          uptime: 86400,
        },
      },
    ],
    examples: [
      {
        name: 'Basic Health Check',
        description: 'Simple health check request',
        request: {},
        response: {
          status: 'healthy',
          timestamp: '2024-01-15T10:30:00Z',
          uptime: 86400,
        },
      },
    ],
  },
  {
    id: '2',
    method: 'POST',
    path: '/api/v1/chat/completions',
    title: 'Chat Completions',
    description: 'Generate chat completions using AI models',
    category: 'AI Models',
    requiresAuth: true,
    parameters: [],
    requestBody: {
      type: 'application/json',
      required: true,
      description: 'Chat completion request parameters',
      schema: {
        type: 'object',
        properties: {
          model: { type: 'string' },
          messages: { type: 'array' },
          max_tokens: { type: 'number' },
          temperature: { type: 'number' },
        },
        required: ['model', 'messages'],
      },
    },
    responses: [
      {
        code: 200,
        description: 'Successful completion',
        schema: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            object: { type: 'string' },
            created: { type: 'number' },
            model: { type: 'string' },
            choices: { type: 'array' },
            usage: { type: 'object' },
          },
        },
        example: {
          id: 'chatcmpl-123',
          object: 'chat.completion',
          created: 1677652288,
          model: 'gpt-3.5-turbo',
          choices: [
            {
              index: 0,
              message: {
                role: 'assistant',
                content: 'Hello! How can I help you today?',
              },
              finish_reason: 'stop',
            },
          ],
          usage: {
            prompt_tokens: 9,
            completion_tokens: 12,
            total_tokens: 21,
          },
        },
      },
    ],
    examples: [
      {
        name: 'Simple Chat',
        description: 'Basic chat completion request',
        request: {
          model: 'gpt-3.5-turbo',
          messages: [
            { role: 'user', content: 'Hello, how are you?' },
          ],
          max_tokens: 100,
          temperature: 0.7,
        },
        response: {
          id: 'chatcmpl-123',
          object: 'chat.completion',
          created: 1677652288,
          model: 'gpt-3.5-turbo',
          choices: [
            {
              index: 0,
              message: {
                role: 'assistant',
                content: 'Hello! I\'m doing well, thank you for asking. How can I assist you today?',
              },
              finish_reason: 'stop',
            },
          ],
          usage: {
            prompt_tokens: 9,
            completion_tokens: 12,
            total_tokens: 21,
          },
        },
      },
    ],
  },
  {
    id: '3',
    method: 'GET',
    path: '/api/v1/policies',
    title: 'List Policies',
    description: 'Retrieve all policies configured in the system',
    category: 'Policies',
    requiresAuth: true,
    parameters: [
      {
        name: 'limit',
        type: 'number',
        required: false,
        description: 'Maximum number of policies to return',
        defaultValue: '10',
      },
      {
        name: 'offset',
        type: 'number',
        required: false,
        description: 'Number of policies to skip',
        defaultValue: '0',
      },
    ],
    responses: [
      {
        code: 200,
        description: 'List of policies',
        schema: {
          type: 'object',
          properties: {
            policies: { type: 'array' },
            total: { type: 'number' },
            limit: { type: 'number' },
            offset: { type: 'number' },
          },
        },
        example: {
          policies: [
            {
              id: '1',
              name: 'PII Detection',
              description: 'Detect and flag personally identifiable information',
              enabled: true,
              created_at: '2024-01-15T10:30:00Z',
            },
          ],
          total: 1,
          limit: 10,
          offset: 0,
        },
      },
    ],
    examples: [
      {
        name: 'List All Policies',
        description: 'Retrieve all policies with default pagination',
        request: {},
        response: {
          policies: [
            {
              id: '1',
              name: 'PII Detection',
              description: 'Detect and flag personally identifiable information',
              enabled: true,
              created_at: '2024-01-15T10:30:00Z',
            },
          ],
          total: 1,
          limit: 10,
          offset: 0,
        },
      },
    ],
  },
];

// API Documentation Component
function ApiDocumentation() {
  const [selectedTab, setSelectedTab] = useState(0);
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpoint | null>(null);
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('http://localhost:8080');
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(null);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info';
  }>({ open: false, message: '', severity: 'info' });

  // Group endpoints by category
  const endpointsByCategory = mockApiEndpoints.reduce((acc, endpoint) => {
    if (!acc[endpoint.category]) {
      acc[endpoint.category] = [];
    }
    acc[endpoint.category].push(endpoint);
    return acc;
  }, {} as Record<string, ApiEndpoint[]>);

  const handleTestEndpoint = async (endpoint: ApiEndpoint) => {
    setIsTesting(true);
    setSelectedEndpoint(endpoint);
    
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Mock response based on endpoint
      const mockResponse = endpoint.examples[0]?.response || {
        status: 'success',
        message: 'Request completed successfully',
      };
      
      setTestResult({
        status: 200,
        data: mockResponse,
        headers: {
          'content-type': 'application/json',
          'x-request-id': 'req-123',
        },
      });
      
      showSnackbar('API test completed successfully', 'success');
    } catch {
      setTestResult({
        status: 500,
        error: 'Internal server error',
        message: 'Failed to complete API request',
      });
      showSnackbar('API test failed', 'error');
    } finally {
      setIsTesting(false);
    }
  };

  const handleCopyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    showSnackbar('Copied to clipboard', 'success');
  };

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info') => {
    setSnackbar({ open: true, message, severity });
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const getMethodColor = (method: string) => {
    switch (method) {
      case 'GET': return 'success';
      case 'POST': return 'primary';
      case 'PUT': return 'warning';
      case 'DELETE': return 'error';
      case 'PATCH': return 'info';
      default: return 'default';
    }
  };

  const formatJson = (obj: Record<string, unknown>) => {
    return JSON.stringify(obj, null, 2);
  };

  return (
    <Box sx={{ flexGrow: 1, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Container maxWidth="xl" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Stack direction="row" alignItems="center" spacing={2} mb={2}>
            <ApiIcon color="primary" sx={{ fontSize: 32 }} />
            <Typography variant="h4" component="h1" fontWeight="bold">
              API Documentation
            </Typography>
            <Chip label="Interactive" color="info" variant="outlined" />
            <Chip label="v1.0" color="secondary" variant="outlined" />
          </Stack>
          <Typography variant="body1" color="text.secondary">
            Explore and test the AI Gateway API endpoints with interactive documentation
          </Typography>
        </Box>

        {/* Configuration */}
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              API Configuration
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Box sx={{ flex: 1, minWidth: 300 }}>
                <TextField
                  fullWidth
                  label="Base URL"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  helperText="The base URL for API requests"
                />
              </Box>
              <Box sx={{ flex: 1, minWidth: 300 }}>
                <TextField
                  fullWidth
                  label="API Key"
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  helperText="Your API key for authentication"
                  InputProps={{
                    startAdornment: <KeyIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                  }}
                />
              </Box>
            </Box>
          </CardContent>
        </Card>

        {/* API Endpoints */}
        <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
          {/* Endpoints List */}
          <Box sx={{ flex: '0 0 300px', minWidth: 300 }}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Endpoints
                </Typography>
                <List>
                  {Object.entries(endpointsByCategory).map(([category, endpoints]) => (
                    <Accordion key={category} sx={{ boxShadow: 'none' }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1" fontWeight="medium">
                          {category}
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <List dense>
                          {endpoints.map((endpoint) => (
                            <ListItemButton
                              key={endpoint.id}
                              onClick={() => setSelectedEndpoint(endpoint)}
                              selected={selectedEndpoint?.id === endpoint.id}
                            >
                              <ListItemIcon>
                                <Chip
                                  label={endpoint.method}
                                  size="small"
                                  color={getMethodColor(endpoint.method) as any}
                                  variant="outlined"
                                />
                              </ListItemIcon>
                              <ListItemText
                                primary={endpoint.title}
                                secondary={endpoint.path}
                              />
                            </ListItemButton>
                          ))}
                        </List>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Box>

          {/* Endpoint Details */}
          <Box sx={{ flex: 1, minWidth: 400 }}>
            {selectedEndpoint ? (
              <Card>
                <CardContent>
                  <Stack direction="row" alignItems="center" spacing={2} mb={3}>
                    <Chip
                      label={selectedEndpoint.method}
                      color={getMethodColor(selectedEndpoint.method) as any}
                      variant="filled"
                    />
                    <Typography variant="h6">{selectedEndpoint.title}</Typography>
                    {selectedEndpoint.requiresAuth && (
                      <Chip
                        label="Auth Required"
                        size="small"
                        color="warning"
                        variant="outlined"
                        icon={<LockIcon />}
                      />
                    )}
                  </Stack>

                  <Typography variant="body1" color="text.secondary" mb={3}>
                    {selectedEndpoint.description}
                  </Typography>

                  <Typography variant="subtitle1" gutterBottom>
                    Endpoint: <code>{baseUrl}{selectedEndpoint.path}</code>
                    <IconButton
                      size="small"
                      onClick={() => handleCopyToClipboard(`${baseUrl}${selectedEndpoint.path}`)}
                    >
                      <CopyIcon />
                    </IconButton>
                  </Typography>

                  <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)} sx={{ mb: 3 }}>
                    <Tab label="Test" />
                    <Tab label="Parameters" />
                    <Tab label="Examples" />
                    <Tab label="Responses" />
                  </Tabs>

                  {selectedTab === 0 && (
                    <Box>
                      <Stack direction="row" spacing={2} mb={3}>
                        <Button
                          variant="contained"
                          startIcon={isTesting ? <StopIcon /> : <PlayIcon />}
                          onClick={() => handleTestEndpoint(selectedEndpoint)}
                          disabled={isTesting}
                        >
                          {isTesting ? 'Testing...' : 'Test Endpoint'}
                        </Button>
                        <Button
                          variant="outlined"
                          startIcon={<CopyIcon />}
                          onClick={() => handleCopyToClipboard(formatJson(selectedEndpoint.examples[0]?.request || {}))}
                        >
                          Copy Request
                        </Button>
                      </Stack>

                      {testResult && (
                        <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                          <Typography variant="subtitle2" gutterBottom>
                            Response (Status: {testResult.status as number})
                          </Typography>
                          <Box sx={{ position: 'relative' }}>
                            <IconButton
                              size="small"
                              sx={{ position: 'absolute', top: 8, right: 8 }}
                              onClick={() => handleCopyToClipboard(formatJson(testResult.data as Record<string, unknown>))}
                            >
                              <CopyIcon />
                            </IconButton>
                            <pre style={{ 
                              fontSize: '12px', 
                              overflow: 'auto', 
                              maxHeight: '300px',
                              padding: '16px',
                              backgroundColor: 'white',
                              border: '1px solid #e0e0e0',
                              borderRadius: '4px',
                            }}>
                              {formatJson(testResult.data as Record<string, unknown>)}
                            </pre>
                          </Box>
                        </Paper>
                      )}
                    </Box>
                  )}

                  {selectedTab === 1 && (
                    <Box>
                      {selectedEndpoint.parameters.length > 0 ? (
                        <List>
                          {selectedEndpoint.parameters.map((param) => (
                            <ListItem key={param.name}>
                              <ListItemIcon>
                                {param.required ? (
                                  <Chip label="Required" size="small" color="error" />
                                ) : (
                                  <Chip label="Optional" size="small" color="default" />
                                )}
                              </ListItemIcon>
                              <ListItemText
                                primary={param.name}
                                secondary={`${param.type} - ${param.description}`}
                              />
                              {param.defaultValue && (
                                <Typography variant="caption" color="text.secondary">
                                  Default: {param.defaultValue}
                                </Typography>
                              )}
                            </ListItem>
                          ))}
                        </List>
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          No parameters required for this endpoint.
                        </Typography>
                      )}

                      {selectedEndpoint.requestBody && (
                        <Box sx={{ mt: 3 }}>
                          <Typography variant="subtitle1" gutterBottom>
                            Request Body
                          </Typography>
                          <Typography variant="body2" color="text.secondary" mb={2}>
                            {selectedEndpoint.requestBody.description}
                          </Typography>
                          <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                            <pre style={{ fontSize: '12px', margin: 0 }}>
                              {formatJson(selectedEndpoint.requestBody.schema)}
                            </pre>
                          </Paper>
                        </Box>
                      )}
                    </Box>
                  )}

                  {selectedTab === 2 && (
                    <Box>
                      {selectedEndpoint.examples.map((example, index) => (
                        <Accordion key={index} sx={{ mb: 2 }}>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle1">{example.name}</Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            <Typography variant="body2" color="text.secondary" mb={2}>
                              {example.description}
                            </Typography>
                            
                            <Typography variant="subtitle2" gutterBottom>
                              Request
                            </Typography>
                            <Paper sx={{ p: 2, bgcolor: 'grey.50', mb: 2 }}>
                              <Box sx={{ position: 'relative' }}>
                                <IconButton
                                  size="small"
                                  sx={{ position: 'absolute', top: 8, right: 8 }}
                                  onClick={() => handleCopyToClipboard(formatJson(example.request))}
                                >
                                  <CopyIcon />
                                </IconButton>
                                <pre style={{ fontSize: '12px', margin: 0 }}>
                                  {formatJson(example.request)}
                                </pre>
                              </Box>
                            </Paper>

                            <Typography variant="subtitle2" gutterBottom>
                              Response
                            </Typography>
                            <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                              <Box sx={{ position: 'relative' }}>
                                <IconButton
                                  size="small"
                                  sx={{ position: 'absolute', top: 8, right: 8 }}
                                  onClick={() => handleCopyToClipboard(formatJson(example.response))}
                                >
                                  <CopyIcon />
                                </IconButton>
                                <pre style={{ fontSize: '12px', margin: 0 }}>
                                  {formatJson(example.response)}
                                </pre>
                              </Box>
                            </Paper>
                          </AccordionDetails>
                        </Accordion>
                      ))}
                    </Box>
                  )}

                  {selectedTab === 3 && (
                    <Box>
                      {selectedEndpoint.responses.map((response) => (
                        <Accordion key={response.code} sx={{ mb: 2 }}>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Stack direction="row" alignItems="center" spacing={2}>
                              <Chip
                                label={response.code}
                                size="small"
                                color={response.code >= 400 ? 'error' : 'success'}
                                variant="outlined"
                              />
                              <Typography variant="subtitle1">{response.description}</Typography>
                            </Stack>
                          </AccordionSummary>
                          <AccordionDetails>
                            <Typography variant="subtitle2" gutterBottom>
                              Schema
                            </Typography>
                            <Paper sx={{ p: 2, bgcolor: 'grey.50', mb: 2 }}>
                              <pre style={{ fontSize: '12px', margin: 0 }}>
                                {formatJson(response.schema)}
                              </pre>
                            </Paper>

                            <Typography variant="subtitle2" gutterBottom>
                              Example
                            </Typography>
                            <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
                              <Box sx={{ position: 'relative' }}>
                                <IconButton
                                  size="small"
                                  sx={{ position: 'absolute', top: 8, right: 8 }}
                                  onClick={() => handleCopyToClipboard(formatJson(response.example))}
                                >
                                  <CopyIcon />
                                </IconButton>
                                <pre style={{ fontSize: '12px', margin: 0 }}>
                                  {formatJson(response.example)}
                                </pre>
                              </Box>
                            </Paper>
                          </AccordionDetails>
                        </Accordion>
                      ))}
                    </Box>
                  )}
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent>
                  <Box sx={{ textAlign: 'center', py: 4 }}>
                    <ApiIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                    <Typography variant="h6" color="text.secondary" gutterBottom>
                      Select an Endpoint
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Choose an endpoint from the list to view its documentation and test it.
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            )}
          </Box>
        </Box>

        {/* Snackbar */}
        <Snackbar
          open={snackbar.open}
          autoHideDuration={4000}
          onClose={handleCloseSnackbar}
        >
          <Alert
            onClose={handleCloseSnackbar}
            severity={snackbar.severity}
            sx={{ width: '100%' }}
          >
            {snackbar.message}
          </Alert>
        </Snackbar>
      </Container>
    </Box>
  );
}

// Main Page Component
export default function ApiDocsPage() {
  return (
    <QueryProvider>
      <ThemeProvider>
        <ApiDocumentation />
      </ThemeProvider>
    </QueryProvider>
  );
} 