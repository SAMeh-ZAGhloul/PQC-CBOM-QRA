# 13 -- Frontend React + Vite SPA

> Read `00_MASTER_SPEC.md`, `05_API_BACKEND.md` first.

---

## Directory Structure

```
frontend/
├── Dockerfile
├── nginx.conf
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.ts
├── index.html
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── router.tsx               # React Router v6 routes + guards
    ├── api/
    │   ├── client.ts            # axios instance + interceptors
    │   ├── auth.ts
    │   ├── scans.ts
    │   ├── cbom.ts
    │   ├── findings.ts
    │   ├── certs.ts
    │   ├── qars.ts
    │   ├── qsri.ts
    │   ├── reports.ts
    │   ├── admin.ts
    │   └── traffic.ts
    ├── store/
    │   ├── auth.store.ts        # Zustand auth store
    │   └── ui.store.ts          # UI state (sidebar, modals)
    ├── hooks/
    │   ├── useAuth.ts
    │   ├── useScanWebSocket.ts  # Real-time scan progress
    │   └── usePermission.ts     # RBAC hook
    ├── components/
    │   ├── layout/
    │   │   ├── AppLayout.tsx
    │   │   ├── Sidebar.tsx
    │   │   └── TopBar.tsx
    │   ├── ui/
    │   │   ├── Badge.tsx
    │   │   ├── DataTable.tsx
    │   │   ├── StatusDot.tsx
    │   │   ├── SeverityBadge.tsx
    │   │   ├── QarsGauge.tsx
    │   │   ├── QsriRadar.tsx
    │   │   └── ProgressBar.tsx
    │   └── shared/
    │       ├── ConfirmDialog.tsx
    │       ├── ExportButton.tsx
    │       └── ErrorBoundary.tsx
    └── pages/
        ├── Login.tsx
        ├── Dashboard.tsx        # /dashboard
        ├── Scans.tsx            # /scans
        ├── ScanDetail.tsx       # /scans/:id
        ├── CbomExplorer.tsx     # /cbom
        ├── Findings.tsx         # /findings
        ├── Certificates.tsx     # /certs
        ├── QarsView.tsx         # /qars
        ├── QsriView.tsx         # /qsri
        ├── Reports.tsx          # /reports
        ├── Roadmap.tsx          # /roadmap
        ├── ExecutiveDashboard.tsx # /executive (ceo role)
        └── admin/
            ├── AdminLayout.tsx
            ├── Users.tsx        # /admin/users
            ├── Groups.tsx       # /admin/groups
            ├── AuditLog.tsx     # /admin/audit
            └── Sessions.tsx     # /admin/sessions
```

---

## package.json

```json
{
  "name": "cbom-frontend",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint src --ext ts,tsx --report-unused-disable-directives",
    "type-check": "tsc --noEmit"
  },
  "dependencies": {
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "react-router-dom": "^6.24.0",
    "@tanstack/react-query": "^5.50.0",
    "axios": "^1.7.0",
    "zustand": "^4.5.0",
    "recharts": "^2.12.0",
    "lucide-react": "^0.400.0",
    "clsx": "^2.1.0",
    "date-fns": "^3.6.0",
    "react-hot-toast": "^2.4.0",
    "@radix-ui/react-dialog": "^1.1.0",
    "@radix-ui/react-dropdown-menu": "^2.1.0",
    "@radix-ui/react-select": "^2.1.0",
    "@radix-ui/react-tabs": "^1.1.0",
    "@radix-ui/react-tooltip": "^1.1.0"
  },
  "devDependencies": {
    "@types/react": "^18.3.0",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.0",
    "typescript": "^5.5.0",
    "vite": "^5.3.0",
    "tailwindcss": "^3.4.0",
    "autoprefixer": "^10.4.0",
    "postcss": "^8.4.0",
    "eslint": "^9.0.0",
    "@typescript-eslint/eslint-plugin": "^7.0.0"
  }
}
```

---

## vite.config.ts

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': { target: 'http://api:8000', changeOrigin: true },
      '/auth': { target: 'http://api:8000', changeOrigin: true },
      '/health': { target: 'http://api:8000', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
          query: ['@tanstack/react-query'],
        },
      },
    },
  },
})
```

---

## src/api/client.ts

```typescript
import axios, { AxiosInstance, AxiosResponse } from 'axios'
import { useAuthStore } from '../store/auth.store'

const apiClient: AxiosInstance = axios.create({
  baseURL: '',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
})

// Request interceptor: attach JWT access token
apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor: handle 401 -> refresh token
apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error) => {
    const original = error.config
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true
      try {
        const { refreshToken, setTokens, logout } = useAuthStore.getState()
        if (!refreshToken) { logout(); return Promise.reject(error) }
        const res = await axios.post('/auth/refresh', { refresh_token: refreshToken })
        setTokens(res.data.access_token, res.data.refresh_token)
        original.headers.Authorization = `Bearer ${res.data.access_token}`
        return apiClient(original)
      } catch {
        useAuthStore.getState().logout()
      }
    }
    return Promise.reject(error)
  }
)

export default apiClient
```

---

## src/store/auth.store.ts

```typescript
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface User {
  id: string
  email: string
  displayName: string | null
  roles: string[]
}

interface AuthState {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  setTokens: (access: string, refresh: string) => void
  setUser: (user: User) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      setTokens: (access, refresh) =>
        set({ accessToken: access, refreshToken: refresh, isAuthenticated: true }),
      setUser: (user) => set({ user }),
      logout: () =>
        set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false }),
    }),
    { name: 'cbom-auth', partialize: (s) => ({ refreshToken: s.refreshToken }) }
  )
)
```

---

## src/hooks/usePermission.ts

```typescript
import { useAuthStore } from '../store/auth.store'

type Permission =
  | 'scan:run'
  | 'scan:read'
  | 'cbom:read'
  | 'cbom:export'
  | 'finding:manage'
  | 'finding:approve'
  | 'report:export'
  | 'compliance:export'
  | 'admin:manage'
  | 'dashboard:executive'

const ROLE_PERMISSIONS: Record<string, Set<Permission>> = {
  admin:    new Set(['scan:run','scan:read','cbom:read','cbom:export','finding:manage',
                     'finding:approve','report:export','compliance:export','admin:manage','dashboard:executive']),
  engineer: new Set(['scan:run','scan:read','cbom:read','cbom:export','finding:manage','report:export']),
  ciso:     new Set(['scan:read','cbom:read','cbom:export','finding:approve','report:export','compliance:export','dashboard:executive']),
  auditor:  new Set(['scan:read','cbom:read','report:export','compliance:export']),
  ceo:      new Set(['dashboard:executive']),
}

export function usePermission(permission: Permission): boolean {
  const roles = useAuthStore((s) => s.user?.roles ?? [])
  return roles.some((role) => ROLE_PERMISSIONS[role]?.has(permission))
}

export function useHasRole(...roles: string[]): boolean {
  const userRoles = useAuthStore((s) => s.user?.roles ?? [])
  return roles.some((r) => userRoles.includes(r))
}
```

---

## src/router.tsx

```typescript
import { createBrowserRouter, Navigate, Outlet } from 'react-router-dom'
import { useAuthStore } from './store/auth.store'
import { useHasRole } from './hooks/usePermission'
import AppLayout from './components/layout/AppLayout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import CbomExplorer from './pages/CbomExplorer'
import Findings from './pages/Findings'
import Certificates from './pages/Certificates'
import QarsView from './pages/QarsView'
import QsriView from './pages/QsriView'
import Reports from './pages/Reports'
import Roadmap from './pages/Roadmap'
import ExecutiveDashboard from './pages/ExecutiveDashboard'
import AdminLayout from './pages/admin/AdminLayout'
import Users from './pages/admin/Users'
import Groups from './pages/admin/Groups'
import AuditLog from './pages/admin/AuditLog'
import Sessions from './pages/admin/Sessions'

function RequireAuth() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  return isAuthenticated ? <Outlet /> : <Navigate to="/login" replace />
}

function RequireRole({ roles }: { roles: string[] }) {
  const hasRole = useHasRole(...roles)
  return hasRole ? <Outlet /> : <Navigate to="/dashboard" replace />
}

export const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  {
    element: <RequireAuth />,
    children: [{
      element: <AppLayout />,
      children: [
        { path: '/', element: <Navigate to="/dashboard" replace /> },
        { path: '/dashboard', element: <Dashboard /> },
        { path: '/scans', element: <Scans /> },
        { path: '/scans/:id', element: <ScanDetail /> },
        { path: '/cbom', element: <CbomExplorer /> },
        { path: '/findings', element: <Findings /> },
        { path: '/certs', element: <Certificates /> },
        { path: '/qars', element: <QarsView /> },
        { path: '/qsri', element: <QsriView /> },
        { path: '/reports', element: <Reports /> },
        { path: '/roadmap', element: <Roadmap /> },
        {
          element: <RequireRole roles={['ceo', 'ciso', 'admin']} />,
          children: [{ path: '/executive', element: <ExecutiveDashboard /> }],
        },
        {
          element: <RequireRole roles={['admin']} />,
          children: [{
            path: '/admin',
            element: <AdminLayout />,
            children: [
              { index: true, element: <Navigate to="/admin/users" replace /> },
              { path: 'users', element: <Users /> },
              { path: 'groups', element: <Groups /> },
              { path: 'audit', element: <AuditLog /> },
              { path: 'sessions', element: <Sessions /> },
            ],
          }],
        },
      ],
    }],
  },
])
```

---

## src/hooks/useScanWebSocket.ts

```typescript
import { useEffect, useRef, useState } from 'react'
import { useAuthStore } from '../store/auth.store'

interface ScanProgress {
  status: string
  assets_found: number
  files_scanned: number
  qars_avg?: number
}

export function useScanWebSocket(scanId: string | null) {
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const token = useAuthStore((s) => s.accessToken)

  useEffect(() => {
    if (!scanId || !token) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(
      `${protocol}//${window.location.host}/api/scans/${scanId}/ws?token=${token}`
    )
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setProgress(data)
      } catch {}
    }

    ws.onerror = () => {
      // Fall back to polling
      const interval = setInterval(async () => {
        try {
          const res = await fetch(`/api/scans/${scanId}`, {
            headers: { Authorization: `Bearer ${token}` },
          })
          const data = await res.json()
          setProgress({
            status: data.status,
            assets_found: data.assets_found,
            files_scanned: data.files_scanned,
          })
          if (['complete', 'failed', 'cancelled'].includes(data.status)) {
            clearInterval(interval)
          }
        } catch {}
      }, 5000)
      return () => clearInterval(interval)
    }

    return () => ws.close()
  }, [scanId, token])

  return progress
}
```

---

## src/components/ui/QarsGauge.tsx

```typescript
import { RadialBarChart, RadialBar, PolarAngleAxis } from 'recharts'

interface QarsGaugeProps {
  score: number        // 0.0 - 1.0
  size?: number
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#A32D2D',
  high:     '#BA7517',
  medium:   '#185FA5',
  low:      '#3B6D11',
}

function getSeverity(score: number): string {
  if (score >= 0.8) return 'critical'
  if (score >= 0.6) return 'high'
  if (score >= 0.4) return 'medium'
  return 'low'
}

export function QarsGauge({ score, size = 120 }: QarsGaugeProps) {
  const severity = getSeverity(score)
  const color = SEVERITY_COLORS[severity]
  const data = [{ value: score * 100, fill: color }]

  return (
    <div className="flex flex-col items-center">
      <RadialBarChart
        width={size} height={size}
        cx={size / 2} cy={size / 2}
        innerRadius={size * 0.3} outerRadius={size * 0.45}
        barSize={10} data={data}
        startAngle={90} endAngle={-270}
      >
        <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
        <RadialBar dataKey="value" cornerRadius={5} background={{ fill: '#e5e7eb' }} />
      </RadialBarChart>
      <div className="text-center -mt-2">
        <div className="text-2xl font-bold" style={{ color }}>
          {score.toFixed(3)}
        </div>
        <div className="text-xs uppercase font-semibold" style={{ color }}>
          {severity}
        </div>
      </div>
    </div>
  )
}
```

---

## src/components/ui/QsriRadar.tsx

```typescript
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
  ResponsiveContainer, Legend, Tooltip,
} from 'recharts'

interface QsriRadarProps {
  scores: Record<string, number>   // dimension -> maturity level (0-5)
}

const DIMENSION_LABELS: Record<string, string> = {
  inventory:       'Inventory',
  risk_assessment: 'Risk',
  crypto_agility:  'Agility',
  migration:       'Migration',
  tech_impl:       'Tech Impl',
  supply_chain:    'Supply Chain',
  governance:      'Governance',
  awareness:       'Awareness',
}

export function QsriRadar({ scores }: QsriRadarProps) {
  const data = Object.entries(DIMENSION_LABELS).map(([key, label]) => ({
    dimension: label,
    score: scores[key] ?? 0,
    max: 5,
  }))

  return (
    <ResponsiveContainer width="100%" height={320}>
      <RadarChart data={data}>
        <PolarGrid gridType="polygon" />
        <PolarAngleAxis dataKey="dimension" tick={{ fontSize: 11 }} />
        <Radar
          name="Current Level"
          dataKey="score"
          stroke="#0F6E56"
          fill="#0F6E56"
          fillOpacity={0.25}
          dot={{ fill: '#0F6E56', r: 3 }}
        />
        <Tooltip
          formatter={(value: number) => [`${value}/5`, 'Maturity Level']}
        />
        <Legend />
      </RadarChart>
    </ResponsiveContainer>
  )
}
```

---

## Dockerfile

```dockerfile
# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --prefer-offline
COPY . .
RUN npm run build

# Production stage: Nginx serving built SPA
FROM nginx:1.27-alpine AS production
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
```

---

## nginx.conf

```nginx
server {
    listen 3000;
    root /usr/share/nginx/html;
    index index.html;

    # React SPA routing: serve index.html for all non-file requests
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets aggressively
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Security headers (Traefik adds HSTS, this adds the rest)
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # Gzip compression
    gzip on;
    gzip_types text/plain application/javascript application/json text/css;
    gzip_min_length 1024;
}
```

---

## Page Specifications

### Dashboard.tsx (/dashboard)
Visible to: all roles (content differs by role)
- **engineer/admin view:** Total assets, vulnerable count, QARS avg gauge, recent scans list, last 5 findings
- **ciso view:** QARS score trend chart, QSRI radar, compliance status badges (DORA/NIS2/NSM10), migration progress bar
- **auditor view:** Read-only findings summary, certificate expiry alerts, export buttons
- **ceo view:** Redirect to /executive

### Scans.tsx (/scans)
Visible to: engineer, admin, ciso (read-only for ciso)
- Table of all scans: name, status, assets found, QARS avg, created at
- "New Scan" button (engineer/admin only) -> opens scan config modal
- Scan config fields: target repos, target hosts, DB connections, sector, Q-Day year, LLM fallback toggle
- Real-time status badges with polling

### ScanDetail.tsx (/scans/:id)
- Real-time progress bar via WebSocket
- Tab view: Assets | Findings | Certificates | QARS | QSRI
- Export button (CycloneDX JSON/XML/CSV/PDF)

### CbomExplorer.tsx (/cbom)
- Filterable, sortable table of all crypto assets
- Filters: quantum class, algorithm, source, severity
- Columns: algorithm, key size, quantum class, PQC replacement, location, QARS score, first seen
- Row click: asset detail drawer with full CycloneDX properties
- Batch annotate: assign owner, system name, data classification

### Findings.tsx (/findings)
- Kanban or table view of findings by status
- Status workflow: open -> in_progress -> resolved | accepted_risk
- Assign owner (user picker), set due date, add rationale
- Filter by severity, status, framework, owner

### Certificates.tsx (/certs)
- Certificate inventory table: subject, algorithm, key size, valid until, days remaining
- Color-coded expiry: red (<7 days), orange (<30 days), yellow (<90 days)
- Live TLS probe button (engineer/admin)

### QarsView.tsx (/qars)
- Per-asset QARS score table sorted by weighted_qars descending
- Mosca inequality breakdown: X + Y vs Z visualization
- Sector selector (changes displayed weights)
- Configurable Q-Day year slider

### QsriView.tsx (/qsri)
- QSRI radar chart (QsriRadar component)
- Per-dimension score cards with maturity level badges
- Improvement recommendations sorted by impact
- Manual assessment input: sliders for each dimension

### ExecutiveDashboard.tsx (/executive)
Visible to: ceo, ciso, admin only
- 4 KPI cards: PQC Readiness %, Critical Assets Count, Days to Q-Day, Compliance Status
- Single QSRI total score gauge
- Migration timeline (simple Gantt-style bar chart)
- No algorithm names or technical detail
