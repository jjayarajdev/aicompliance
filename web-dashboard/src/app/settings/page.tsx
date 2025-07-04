'use client';

import React from 'react';
import { Box, Container, Typography, Card, CardContent } from '@mui/material';
import { Settings as SettingsIcon } from '@mui/icons-material';

export default function SettingsPage() {
  return (
    <Box sx={{ flexGrow: 1, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Box sx={{ mb: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <SettingsIcon color="primary" sx={{ fontSize: 32 }} />
            <Typography variant="h4" component="h1" fontWeight="bold">
              Settings & Configuration
            </Typography>
          </Box>
          <Typography variant="body1" color="text.secondary">
            Settings interface coming soon
          </Typography>
        </Box>

        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Settings Placeholder
            </Typography>
            <Typography variant="body2" color="text.secondary">
              The settings interface is currently being implemented. This page will include:
            </Typography>
            <Box component="ul" sx={{ mt: 2 }}>
              <Typography component="li">System Configuration</Typography>
              <Typography component="li">API Provider Settings</Typography>
              <Typography component="li">Notification Preferences</Typography>
              <Typography component="li">Security Configuration</Typography>
              <Typography component="li">Cache Settings</Typography>
            </Box>
          </CardContent>
        </Card>
      </Container>
    </Box>
  );
} 