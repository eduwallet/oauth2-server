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
	statusHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>OAuth2 Server</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
		.container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		h1 { color: #333; text-align: center; margin-bottom: 30px; }
		.section { margin-bottom: 30px; padding: 20px; background-color: #f8f9fa; border-radius: 6px; }
		.btn { display: inline-block; padding: 10px 20px; margin: 5px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; }
		.btn:hover { background-color: #0056b3; }
		.endpoint { font-family: monospace; background-color: #e9ecef; padding: 8px; border-radius: 3px; }
		ul { margin: 10px 0; }
		li { margin: 8px 0; }
		code { background-color: #f1f3f4; padding: 2px 4px; border-radius: 2px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>🚀 OAuth2 Authorization Server</h1>
		
		<div class="section">
			<h2>📋 Server Information</h2>
			<p><strong>Base URL:</strong> %s</p>
			<p><strong>Version:</strong> Development</p>
			<p><strong>Status:</strong> ✅ Running</p>
		</div>

		<div class="section">
			<h3>🔍 Discovery Endpoints</h3>
			<ul>
				<li><a href="/.well-known/oauth-authorization-server" class="btn">OAuth2 Discovery</a></li>
				<li><a href="/.well-known/openid-configuration" class="btn">OpenID Connect Discovery</a></li>
				<li><a href="/.well-known/jwks.json" class="btn">JWKS</a></li>
			</ul>
		</div>

		<!-- Fancy Server Stats Section -->
		<div class="stats-section" style="margin-top:30px;">
		  <h2 style="text-align:center;">🚦 Server Stats</h2>
		  <div id="stats-cards" style="display:flex; gap:24px; justify-content:center; flex-wrap:wrap; margin-top:20px;">
		    <div class="stat-card" id="stat-tokens">
		      <div class="stat-icon">🔑</div>
		      <div class="stat-label">Tokens</div>
		      <div class="stat-value" id="stats-tokens-value">...</div>
		    </div>
		    <div class="stat-card" id="stat-clients">
		      <div class="stat-icon">🧩</div>
		      <div class="stat-label">Clients</div>
		      <div class="stat-value" id="stats-clients-value">...</div>
		    </div>
		    <div class="stat-card" id="stat-users">
		      <div class="stat-icon">👤</div>
		      <div class="stat-label">Users</div>
		      <div class="stat-value" id="stats-users-value">...</div>
		    </div>
		  </div>
		</div>
		<style>
		  .stat-card {
		    background: #fff;
		    border-radius: 12px;
		    box-shadow: 0 2px 8px rgba(0,0,0,0.07);
		    padding: 24px 32px;
		    min-width: 140px;
		    text-align: center;
		    transition: box-shadow 0.2s;
		  }
		  .stat-card:hover {
		    box-shadow: 0 4px 16px rgba(0,0,0,0.13);
		  }
		  .stat-icon {
		    font-size: 2.2em;
		    margin-bottom: 8px;
		  }
		  .stat-label {
		    font-size: 1.1em;
		    color: #555;
		    margin-bottom: 6px;
		    font-weight: 500;
		  }
		  .stat-value {
		    font-size: 2em;
		    font-weight: bold;
		    color: #007bff;
		  }
		</style>
		<script>
		function loadStats() {
			fetch('/stats')
				.then(r => r.json())
				.then(stats => {
					// Properly access properties from the stats object
					document.getElementById('stats-tokens-value').innerText = 
						stats.tokens ?? "—";
					document.getElementById('stats-clients-value').innerText = 
						stats.clients ?? "—";
					document.getElementById('stats-users-value').innerText = 
						stats.users ?? "—";
				})
				.catch(() => {
					document.getElementById('stats-tokens-value').innerText = '—';
					document.getElementById('stats-clients-value').innerText = '—';
					document.getElementById('stats-users-value').innerText = '—';
				});
		}
		document.addEventListener('DOMContentLoaded', loadStats);
		</script>
	</div>
</body>
</html>`, h.Configuration.Server.BaseURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(statusHTML))
}
