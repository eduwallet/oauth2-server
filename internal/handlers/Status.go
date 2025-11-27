package handlers

import (
	"fmt"
	"net/http"
	"oauth2-server/pkg/config"
)

// StatusHandler manages the status page requests
type StatusHandler struct {
	Configuration *config.Config
}

// NewStatusHandler creates a new status handler
func NewStatusHandler(configuration *config.Config) *StatusHandler {
	return &StatusHandler{
		Configuration: configuration,
	}
}

// ServeHTTP handles status page requests
func (h *StatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyMode := h.Configuration.IsProxyMode()
	upstreamURL := ""
	if proxyMode {
		upstreamURL = h.Configuration.UpstreamProvider.ProviderURL
	}
	statusHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>OAuth2 Server Status</title>
	<style>
		:root {
			--primary: #2563eb;
			--primary-dark: #1d4ed8;
			--success: #10b981;
			--warning: #f59e0b;
			--gray-50: #f9fafb;
			--gray-100: #f3f4f6;
			--gray-200: #e5e7eb;
			--gray-300: #d1d5db;
			--gray-600: #4b5563;
			--gray-700: #374151;
			--gray-800: #1f2937;
			--gray-900: #111827;
			--shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
			--shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
		}

		* { box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			margin: 0;
			padding: 0;
			background: linear-gradient(135deg, var(--gray-50) 0%%, var(--gray-100) 100%%);
			min-height: 100vh;
			color: var(--gray-800);
		}

		.container {
			max-width: 1200px;
			margin: 0 auto;
			padding: 2rem 1rem;
		}

		.header {
			text-align: center;
			margin-bottom: 2rem;
		}

		.title {
			font-size: 2.5rem;
			font-weight: 700;
			color: var(--gray-900);
			margin: 0 0 0.5rem 0;
			display: flex;
			align-items: center;
			justify-content: center;
			gap: 0.75rem;
		}

		.subtitle {
			font-size: 1.125rem;
			color: var(--gray-600);
			margin: 0;
		}

		.grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
			gap: 1.5rem;
			margin-bottom: 2rem;
		}

		.card {
			background: white;
			border-radius: 0.75rem;
			padding: 1.5rem;
			box-shadow: var(--shadow);
			border: 1px solid var(--gray-200);
			transition: all 0.2s ease;
		}

		.card:hover {
			box-shadow: var(--shadow-lg);
			transform: translateY(-2px);
		}

		.card-header {
			display: flex;
			align-items: center;
			gap: 0.75rem;
			margin-bottom: 1rem;
			padding-bottom: 0.75rem;
			border-bottom: 1px solid var(--gray-200);
		}

		.card-icon {
			font-size: 1.5rem;
		}

		.card-title {
			font-size: 1.25rem;
			font-weight: 600;
			color: var(--gray-900);
			margin: 0;
		}

		.info-grid {
			display: grid;
			grid-template-columns: 1fr 2fr;
			gap: 0.75rem;
			align-items: center;
		}

		.info-label {
			font-weight: 500;
			color: var(--gray-700);
		}

		.info-value {
			font-family: 'Monaco', 'Menlo', monospace;
			background: var(--gray-100);
			padding: 0.25rem 0.5rem;
			border-radius: 0.25rem;
			font-size: 0.875rem;
			color: var(--gray-800);
			word-break: break-all;
		}

		.status-badge {
			display: inline-flex;
			align-items: center;
			gap: 0.375rem;
			padding: 0.25rem 0.75rem;
			border-radius: 9999px;
			font-size: 0.875rem;
			font-weight: 500;
		}

		.status-running {
			background: var(--success);
			color: white;
		}

		.status-proxy {
			background: var(--primary);
			color: white;
		}

		.btn {
			display: inline-flex;
			align-items: center;
			gap: 0.5rem;
			padding: 0.5rem 1rem;
			background: var(--primary);
			color: white;
			text-decoration: none;
			border-radius: 0.5rem;
			font-size: 0.875rem;
			font-weight: 500;
			transition: all 0.2s ease;
			border: none;
			cursor: pointer;
		}

		.btn:hover {
			background: var(--primary-dark);
			transform: translateY(-1px);
		}

		@media (max-width: 768px) {
			.container { padding: 1rem; }
			.title { font-size: 2rem; }
			.grid { grid-template-columns: 1fr; }
		}
	</style>
</head>
<body>
	<div class="container">
		<header class="header">
			<h1 class="title">
				🚀 OAuth2 Server
			</h1>
			<p class="subtitle">Authorization Server Status Dashboard</p>
		</header>

		<div class="grid">
			<div class="card">
				<div class="card-header">
					<span class="card-icon">📊</span>
					<h2 class="card-title">Server Status</h2>
				</div>
				<div class="info-grid">
					<span class="info-label">Status:</span>
					<span class="status-badge status-running">✅ Running</span>

					<span class="info-label">Mode:</span>
					<span class="status-badge status-proxy">%s</span>
					%s
				</div>
			</div>

		</div>
	</div>

</body>
</html>`,
		func() string {
			if proxyMode {
				return "🔄 Proxy Mode"
			}
			return "🏠 Standalone Mode"
		}(),
		func() string {
			if proxyMode && upstreamURL != "" {
				return fmt.Sprintf(`
					<span class="info-label">Upstream:</span>
					<span class="info-value">%s</span>`, upstreamURL)
			}
			return ""
		}())

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(statusHTML))
}
