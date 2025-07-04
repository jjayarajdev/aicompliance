# AI Gateway - Deployment Guide

This guide provides step-by-step instructions to run the AI Gateway application with both backend and frontend components.

## 📋 Prerequisites

Before running the application, ensure you have the following installed:

- **Go** (version 1.21 or higher)
- **Node.js** (version 18 or higher)
- **npm** (comes with Node.js)
- **Git** (for cloning the repository)

### Verify Prerequisites

```bash
# Check Go version
go version

# Check Node.js version
node --version

# Check npm version
npm --version
```

## 🚀 Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd genAIlandscape

# Install Go dependencies
go mod download

# Install frontend dependencies
cd web-dashboard
npm install
cd ..
```

### 2. Build the Backend

```bash
# Build the simple gateway binary
go build -o bin/simple-gateway cmd/simple-gateway/main.go
```

### 3. Start the Backend

```bash
# Run the AI Gateway backend
./bin/simple-gateway
```

**Expected Output:**
```
🚀 AI Gateway server starting on http://localhost:8080
📊 Dashboard available at http://localhost:3000
🔍 Health check: http://localhost:8080/health
📈 API endpoints:
  GET /api/v1/dashboard/stats
  GET /api/v1/dashboard/overview
  GET /api/v1/dashboard/activity
  GET /api/v1/dashboard/metrics
  GET /api/v1/monitoring/system
  GET /api/v1/policies
```

### 4. Start the Frontend (New Terminal)

```bash
# Navigate to frontend directory
cd web-dashboard

# Start the development server
PORT=3000 npm run dev
```

**Expected Output:**
```
> web-dashboard@0.1.0 dev
> next dev --turbopack
   ▲ Next.js 15.3.4 (Turbopack)
   - Local:        http://localhost:3000
   - Network:      http://192.168.1.33:3000
 ✓ Starting...
 ✓ Ready in 605ms
```

## 🔗 Access the Application

Once both services are running:

- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8080
- **Health Check**: http://localhost:8080/api/v1/health

## 📊 Available Features

### Dashboard Features
- **Home**: Real-time system overview and statistics
- **Policies**: Policy management interface
- **Monitoring**: System metrics and performance monitoring
- **Analytics**: Advanced analytics and reporting
- **Users**: User management interface
- **Settings**: System configuration
- **Audit Logs**: Activity history and audit trails
- **API Docs**: Interactive API documentation

### API Endpoints

#### Dashboard APIs
- `GET /api/v1/dashboard/stats` - Gateway statistics
- `GET /api/v1/dashboard/overview` - System overview
- `GET /api/v1/dashboard/activity` - Recent activity
- `GET /api/v1/dashboard/metrics` - Performance metrics

#### Policy Management
- `GET /api/v1/policies` - List all policies
- `POST /api/v1/policies` - Create new policy
- `PUT /api/v1/policies/{id}` - Update policy
- `DELETE /api/v1/policies/{id}` - Delete policy

#### Monitoring
- `GET /api/v1/monitoring/system` - System metrics
- `GET /api/v1/monitoring/alerts` - System alerts
- `GET /api/v1/monitoring/performance` - Performance metrics
- `GET /api/v1/monitoring/providers` - Provider health

#### Settings
- `GET /api/v1/settings/system` - System settings
- `PUT /api/v1/settings/system` - Update system settings

## 🧪 Testing the Setup

### 1. Backend Health Check

```bash
curl http://localhost:8080/api/v1/health
```

**Expected Response:**
```json
{
  "service": "ai-gateway-poc",
  "status": "healthy",
  "timestamp": "2025-07-03T23:04:44+05:30"
}
```

### 2. Test Dashboard API

```bash
curl http://localhost:8080/api/v1/dashboard/stats
```

**Expected Response:**
```json
{
  "activePolicies": {
    "count": 24,
    "changePercent": 12,
    "trend": "up"
  },
  "apiRequests": {
    "count": 1289551,
    "changePercent": 20,
    "period": "24h",
    "trend": "up"
  },
  "rateLimitViolations": {
    "count": 17,
    "changePercent": -6,
    "trend": "down"
  },
  "systemHealth": {
    "percentage": 99.9,
    "status": "healthy",
    "uptime": "99.9%"
  }
}
```

### 3. Test Frontend Access

```bash
curl -I http://localhost:3000
```

**Expected Response:**
```
HTTP/1.1 200 OK
X-Powered-By: Next.js
Content-Type: text/html; charset=utf-8
```

## 🛠️ Configuration

### Environment Variables

Create a `.env.local` file in the `web-dashboard` directory for frontend configuration:

```bash
# Frontend environment variables
NEXT_PUBLIC_API_URL=http://localhost:8080
```

### Backend Configuration

The backend uses configuration files in the `configs/` directory:

- `config.yaml` - Main configuration
- `config.development.yaml` - Development settings
- `config.production.yaml` - Production settings

## 🐛 Troubleshooting

### Common Issues

#### 1. Port Already in Use

If port 3000 is occupied:
```bash
# Find and kill the process using port 3000
lsof -ti:3000 | xargs kill

# Or use a different port
PORT=3001 npm run dev
```

#### 2. Backend Build Issues

If you encounter build errors with the main gateway:
```bash
# Use the simple gateway instead
go build -o bin/simple-gateway cmd/simple-gateway/main.go
./bin/simple-gateway
```

#### 3. Frontend Dependencies Issues

```bash
# Clear npm cache and reinstall
cd web-dashboard
rm -rf node_modules package-lock.json
npm install
```

#### 4. Go Dependencies Issues

```bash
# Clean and rebuild Go modules
go clean -modcache
go mod download
go mod tidy
```

### Logs and Debugging

- **Backend Logs**: Console output from the backend process
- **Frontend Logs**: Browser console and terminal output
- **API Testing**: Use curl or tools like Postman to test API endpoints

## 🔧 Development Mode

### Hot Reload

Both services support hot reload:

- **Backend**: Restart the binary after code changes
- **Frontend**: Automatic hot reload with Next.js

### Making Changes

1. **Backend Changes**: 
   - Modify Go files
   - Rebuild: `go build -o bin/simple-gateway cmd/simple-gateway/main.go`
   - Restart: `./bin/simple-gateway`

2. **Frontend Changes**:
   - Modify React/TypeScript files
   - Changes auto-reload in browser

## 📈 Production Deployment

For production deployment:

1. **Build Frontend**:
   ```bash
   cd web-dashboard
   npm run build
   npm start
   ```

2. **Backend Binary**:
   ```bash
   go build -ldflags="-s -w" -o bin/gateway cmd/simple-gateway/main.go
   ```

3. **Environment Configuration**:
   - Update `config.production.yaml`
   - Set appropriate environment variables

## 🎯 Next Steps

After successful deployment:

1. **Explore the Dashboard**: Navigate through different sections
2. **Test API Integration**: Use the API documentation page
3. **Configure Policies**: Set up custom policies via the UI
4. **Monitor System**: Check real-time metrics and alerts
5. **Review Audit Logs**: Examine system activity

## 📞 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Verify all prerequisites are installed correctly
3. Ensure ports 3000 and 8080 are available
4. Check console outputs for error messages

---

**Project Status**: Backend-Frontend Integration Complete ✅
**Development Ready**: Both services operational on localhost
**Features**: Full dashboard, policy management, monitoring, and analytics 