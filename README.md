# AI Gateway Proof of Concept

A forward proxy edge AI control plane designed to intercept, monitor, and govern organizational data flowing to external Large Language Model (LLM) providers.

## Overview

The AI Gateway PoC demonstrates core enterprise security capabilities for AI request governance, including:

- **Forward Proxy**: Transparent interception of AI API requests
- **PII Detection**: Real-time detection and masking of sensitive data
- **Policy Engine**: Configurable rules for data governance
- **Audit Logging**: Comprehensive logging for compliance
- **Multi-Provider Support**: OpenAI and Anthropic Claude integration
- **Web Dashboard**: Real-time monitoring and administration

## Technology Stack

- **Backend**: Go 1.21+ with Gorilla Mux
- **Frontend**: Next.js 14+ with TypeScript and Material-UI
- **Database**: PostgreSQL for persistence, Redis for caching
- **Configuration**: YAML with Viper library
- **Logging**: Structured JSON with Logrus
- **API Documentation**: OpenAPI 3.0 with Swagger

## Quick Start

### Prerequisites

- Go 1.21 or later
- Node.js 18+ and npm
- PostgreSQL 13+
- Redis 6+
- Docker and Docker Compose (optional)

### Environment Variables

Create a `.env` file with the following variables:

```bash
# AI Provider API Keys
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Security
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Database
GATEWAY_DATABASE_USERNAME=gateway_user
GATEWAY_DATABASE_PASSWORD=gateway_password

# Redis (if password protected)
GATEWAY_REDIS_PASSWORD=your_redis_password
```

### Development Setup

1. **Clone and Initialize**
   ```bash
   git clone <repository-url>
   cd ai-gateway-poc
   go mod tidy
   ```

2. **Setup Database**
   ```bash
   # Create PostgreSQL database
   createdb ai_gateway
   
   # Run migrations (when available)
   go run cmd/migrate/main.go
   ```

3. **Start Dependencies with Docker**
   ```bash
   docker-compose up -d postgres redis
   ```

4. **Run the Application**
   ```bash
   # Start the Go backend
   go run cmd/gateway/main.go
   
   # In another terminal, start the Next.js frontend
   cd web
   npm install
   npm run dev
   ```

5. **Access the Application**
   - API Server: http://localhost:8080
   - Web Dashboard: http://localhost:3000
   - API Documentation: http://localhost:8080/swagger/
   - Health Check: http://localhost:8080/api/v1/health
   - Metrics: http://localhost:9090/metrics

### Using Docker

```bash
# Start all services
docker-compose up

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## API Endpoints

### Health & Status
- `GET /api/v1/health` - Health check
- `GET /api/v1/ready` - Readiness check
- `GET /api/v1/version` - Service version info

### AI Provider Proxy (Planned)
- `POST /api/v1/proxy/openai/*` - OpenAI API proxy
- `POST /api/v1/proxy/anthropic/*` - Anthropic API proxy

### Policy Management (Planned)
- `GET /api/v1/policies` - List policies
- `POST /api/v1/policies` - Create policy
- `PUT /api/v1/policies/{id}` - Update policy
- `DELETE /api/v1/policies/{id}` - Delete policy

### Monitoring & Audit (Planned)
- `GET /api/v1/audit/logs` - Audit logs
- `GET /api/v1/monitoring/metrics` - System metrics
- `GET /api/v1/monitoring/alerts` - Active alerts

## Configuration

The application uses YAML configuration files located in the `configs/` directory. Configuration can be overridden using environment variables with the `GATEWAY_` prefix.

Example configuration structure:
```yaml
environment: development
log_level: info
server:
  port: 8080
  host: "0.0.0.0"
database:
  host: localhost
  port: 5432
  username: gateway_user
  password: gateway_password
  database: ai_gateway
providers:
  openai:
    api_key: "${OPENAI_API_KEY}"
    base_url: "https://api.openai.com/v1"
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
    base_url: "https://api.anthropic.com"
```

## Development

### Running Tests

```bash
# Run all Go tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/config

# Run frontend tests
cd web
npm test
```

### Code Generation

```bash
# Generate Swagger documentation
swag init -g cmd/gateway/main.go

# Format Go code
go fmt ./...

# Run Go linter
golangci-lint run
```

### Project Structure

```
ai-gateway-poc/
├── cmd/gateway/          # Application entry point
├── internal/             # Internal Go packages
│   ├── config/           # Configuration management
│   ├── server/           # HTTP server and routing
│   ├── proxy/            # Forward proxy implementation
│   ├── providers/        # AI provider clients
│   ├── analysis/         # Content analysis and PII detection
│   ├── policy/           # Policy engine
│   ├── monitoring/       # Audit logging and alerts
│   ├── cache/            # Caching layer
│   ├── limits/           # Rate limiting
│   └── auth/             # Authentication and authorization
├── web/                  # Next.js frontend application
├── configs/              # Configuration files
├── docker-compose.yml    # Docker services
├── Dockerfile            # Backend container
└── go.mod               # Go module dependencies
```

## Contributing

1. Follow Go conventions and best practices
2. Write tests for new functionality
3. Update documentation for API changes
4. Use conventional commit messages
5. Ensure all tests pass before submitting PR

## License

MIT License - see LICENSE file for details

## Support

For questions and support, please refer to the project documentation or create an issue in the repository. 