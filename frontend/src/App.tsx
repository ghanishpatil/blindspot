import { Route, Routes } from 'react-router-dom';

import { AppShell } from '@/components/AppShell';
import { CBOMPage } from '@/pages/CBOMPage';
import Dashboard from '@/pages/Dashboard';
import FindingDetail from '@/pages/FindingDetail';
import Findings from '@/pages/Findings';
import { Landing } from '@/pages/Landing';
import Login from '@/pages/Login';
import NotFound from '@/pages/NotFound';
import Signup from '@/pages/Signup';
import { ProjectsPage } from '@/pages/ProjectsPage';
import { ReportsPage } from '@/pages/ReportsPage';
import { ScanPage } from '@/pages/ScanPage';

export default function App() {
  return (
    <Routes>
      {/* Landing page renders outside shell */}
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />

      {/* Application views render inside AppShell */}
      <Route
        path="/dashboard"
        element={
          <AppShell>
            <Dashboard />
          </AppShell>
        }
      />
      <Route
        path="/scan"
        element={
          <AppShell>
            <ScanPage />
          </AppShell>
        }
      />
      <Route
        path="/findings"
        element={
          <AppShell>
            <Findings />
          </AppShell>
        }
      />
      <Route
        path="/findings/:findingId"
        element={
          <AppShell>
            <FindingDetail />
          </AppShell>
        }
      />
      <Route
        path="/cbom"
        element={
          <AppShell>
            <CBOMPage />
          </AppShell>
        }
      />
      <Route
        path="/reports"
        element={
          <AppShell>
            <ReportsPage />
          </AppShell>
        }
      />
      <Route
        path="/projects"
        element={
          <AppShell>
            <ProjectsPage />
          </AppShell>
        }
      />

      <Route
        path="*"
        element={
          <AppShell>
            <NotFound />
          </AppShell>
        }
      />
    </Routes>
  );
}
