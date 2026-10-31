# SnareSight Frontend
### Security Operations Center (SOC) Dashboard

---

## 1. Overview
The SnareSight frontend provides an interactive, real-time Security Operations Center dashboard built with **React**, **TypeScript**, **Vite**, and **Tailwind CSS**.

---

## 2. Technical Stack
* **Runtime & Bundler:** Vite 6 with React 18 & TypeScript 5
* **UI Design System:** Tailwind CSS (Dark theme with semantic threat severity accents)
* **Iconography:** Lucide React
* **Metrics & Analytics:** Recharts (24h event velocity, protocol breakdown)
* **Attack-Chain Visualizer:** React Flow (Directed acyclic graph of correlated intrusion stages)
* **Real-Time Channel:** Server-Sent Events (SSE) via native `EventSource`

---

## 3. Directory Layout
```
frontend/
├── src/
│   ├── app/          # App initialization, routing & global providers
│   ├── assets/       # Static branding assets and icons
│   ├── components/   # Reusable UI primitives (Button, Modal, Card, Badge)
│   ├── features/     # Feature-specific modules (alerts, events, attack-chains, mitre)
│   ├── hooks/        # Custom React hooks (useSSE, useAuth)
│   ├── layouts/      # DashboardLayout, Sidebar, Navbar
│   ├── services/     # REST API client abstraction
│   ├── types/        # Shared TypeScript interfaces
│   ├── utils/        # Formatting and timestamp utilities
│   └── styles/       # Tailwind CSS entry points
├── tests/            # Vitest unit and component test suites
├── public/           # Static assets
├── package.json      # Dependencies and build scripts
└── vite.config.ts    # Bundler and dev proxy configuration
```

---

## 4. Development Notice
> [!NOTE]
> Dependency installation and component implementation will begin in **Phase 6 (SOC Dashboard)**. No dependencies have been installed during Phase 1.

